#include "process.h"

Process::Process( DWORD process_id )
{
	this->pid = process_id;
	this->handle = nullptr;
}

Process::~Process( )
{
	Process::CloseOpenHandle( );
}

bool Process::Open( DWORD desired_access, BOOL inherit_handle )
{
	this->handle = OpenProcess( desired_access, inherit_handle, this->pid );
	if ( this->handle == INVALID_HANDLE_VALUE ) {
		return false;
	}

	return true;
}

bool Process::CloseOpenHandle( ) const
{
	if ( this->handle == INVALID_HANDLE_VALUE ) {
		return false;
	}

	if ( !CloseHandle( this->handle ) ) {
		return false;
	}

	return true;
}

std::string Process::FetchProcessImageFileName( ) const
{
	char process_name[ MAX_PATH ] = { };

	if ( !GetProcessImageFileName( this->handle, process_name, MAX_PATH ) ) {
		return { };
	}

	return std::string{ process_name };
}

bool Process::Terminate( UINT exit_code ) const
{
	if ( !TerminateProcess( this->handle, exit_code ) ) {
		return false;
	}

	return true;
}

std::vector<HANDLE> Process::FetchThreads( ) const
{
	std::vector<HANDLE> thread_handles;

	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	if ( snapshot == INVALID_HANDLE_VALUE ) {
		return { };
	}

	THREADENTRY32 thread_entry = { sizeof( THREADENTRY32 ) };
	Thread32First( snapshot, &thread_entry );
	do
	{
		if ( thread_entry.th32OwnerProcessID == pid )
		{
			HANDLE thread_handle = OpenThread( THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID );
			thread_handles.push_back( thread_handle );
		}
	} while ( Thread32Next( snapshot, &thread_entry ) );
	
	if ( !CloseHandle( snapshot ) ) {
		return { };
	}

	return thread_handles;
}

bool Process::Resume( ) const
{
	auto thread_handles = FetchThreads( );
	for ( auto &thread : thread_handles ) {
		if ( !ResumeThread( thread ) ) {
			return false;
		}
	}

	return true;
}

bool Process::NtResume( ) const
{
	static auto ResumeProcess = ( Process::NtResumeProcess ) GetProcAddress( GetModuleHandleA( "ntdll" ), "NtResumeProcess" );
	if ( NT_ERROR( ResumeProcess( Process::handle ) ) ) {
		return false;
	}

	return true;
}

bool Process::Suspend( ) const
{
	auto thread_handles = FetchThreads( );
	for ( auto &thread : thread_handles ) {
		if ( !SuspendThread( thread ) ) {
			return false;
		}
	}

	return true;
}

bool Process::NtSuspend( ) const
{
	static auto SuspendProcess = ( Process::NtSuspendProcess ) GetProcAddress( GetModuleHandleA( "ntdll" ), "NtSuspendProcess" );
	if ( NT_ERROR( SuspendProcess( this->handle ) ) ) {
		return false;
	}

	return true;
}

HANDLE Process::CreateMapView( ) const
{
	TCHAR buffer[ MAX_PATH ];
	if ( !GetModuleFileNameEx( this->handle, nullptr, buffer, MAX_PATH ) ) {
		return nullptr;
	}

	HANDLE file = CreateFile( buffer, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( file == INVALID_HANDLE_VALUE ) {
		return nullptr;
	}

	HANDLE map = CreateFileMapping( file, nullptr, PAGE_READONLY, 0, 0, nullptr );
	if ( !map ) {
		return nullptr;
	}

	HANDLE map_view = MapViewOfFile( map, FILE_MAP_READ, 0, 0, 0 );
	if ( !map_view ) {
		return nullptr;
	}

	if ( !CloseHandle( file ) && !CloseHandle( map ) && !CloseHandle( map_view ) ) {
		return nullptr;
	}

	return map_view;
}

PIMAGE_DOS_HEADER Process::FetchDOSHeader( HANDLE map_view )
{
	PIMAGE_DOS_HEADER dos_header = ( PIMAGE_DOS_HEADER ) map_view;
	if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
		return nullptr;
	}

	return dos_header;
}

PIMAGE_NT_HEADERS Process::FetchImageHeader( ) const
{
	PIMAGE_DOS_HEADER dos_header = Process::FetchDOSHeader( Process::CreateMapView( ) );
	if ( !dos_header ) {
		return nullptr;
	}

	PIMAGE_NT_HEADERS image_header = ( PIMAGE_NT_HEADERS )( ( char* ) dos_header + dos_header->e_lfanew );
	if ( image_header->Signature != IMAGE_NT_SIGNATURE ) {
		return nullptr;
	}

	return image_header;
}

bool Process::Is64Bit( ) const
{
	PIMAGE_NT_HEADERS header = Process::FetchImageHeader( );
	if ( !header ) {
		return false;
	}

	if ( header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ) {
		return true;
	}

	return false;
}

HANDLE Process::FetchAccessToken( DWORD desired_access ) const
{
	HANDLE token_handle;

	if ( !OpenProcessToken( this->handle, desired_access, &token_handle ) ) {
		return nullptr;
	}

	return token_handle;
}

bool Process::RtlAdjustPrivileges( ULONG privilege, BOOLEAN enable, BOOLEAN current_thread, PBOOLEAN enabled )
{
	static auto AdjustPrivileges = ( Process::RtlAdjustPrivilege ) GetProcAddress( GetModuleHandleA( "ntdll" ), "RtlAdjustPrivilege" );
	if ( NT_ERROR( AdjustPrivileges( privilege, enable, current_thread, enabled ) ) ) {
		return false;
	}

	return true;
}