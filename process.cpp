#include "process.h"
#include <memory>

Process::Process( DWORD process_id )
{
	this->m_pid = process_id;
	this->m_handle = nullptr;
	this->m_file = nullptr;
}

Process::~Process( )
{
	Process::CloseOpenHandle( );
}

bool Process::IsValid( ) const
{
	if ( this->m_handle == INVALID_HANDLE_VALUE ) {
		return false;
	}

	return WaitForSingleObject( this->m_handle, 0 ) == WAIT_TIMEOUT;
}

void Process::SetDesiredAccess( DWORD desired_access )
{
	this->m_desired_access = desired_access;
}

bool Process::Open( BOOL inherit_handle )
{
	this->m_handle = OpenProcess( this->m_desired_access, inherit_handle, this->m_pid );
	if ( this->m_handle == INVALID_HANDLE_VALUE ) {
		return false;
	}

	return true;
}

bool Process::CloseOpenHandle( ) const
{
	if ( this->m_handle == INVALID_HANDLE_VALUE ) {
		return false;
	}

	if ( !CloseHandle( this->m_handle ) ) {
		return false;
	}

	return true;
}

std::string Process::FetchProcessImageFileName( ) const
{
	char process_name[ MAX_PATH ] = { };

	if ( !GetProcessImageFileName( this->m_handle, process_name, MAX_PATH ) ) {
		return { };
	}

	return std::string{ process_name };
}

bool Process::Terminate( UINT exit_code ) const
{
	if ( !TerminateProcess( this->m_handle, exit_code ) ) {
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
		if ( thread_entry.th32OwnerProcessID == m_pid )
		{
			HANDLE thread_handle = OpenThread( THREAD_QUERY_INFORMATION, FALSE, thread_entry.th32ThreadID );
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
	static auto ResumeProcess = reinterpret_cast<Process::NtResumeProcess>( GetProcAddress( GetModuleHandleA( "ntdll" ), "NtResumeProcess" ) );
	if ( NT_ERROR( ResumeProcess( Process::m_handle ) ) ) {
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
	static auto SuspendProcess = reinterpret_cast<Process::NtSuspendProcess>( GetProcAddress( GetModuleHandleA( "ntdll" ), "NtSuspendProcess" ) );
	if ( NT_ERROR( SuspendProcess( this->m_handle ) ) ) {
		return false;
	}

	return true;
}

HANDLE Process::CreateMapView( )
{
	TCHAR buffer[ MAX_PATH ];
	if ( !GetModuleFileNameEx( this->m_handle, nullptr, buffer, MAX_PATH ) ) {
		return nullptr;
	}

	this->m_file = CreateFile( buffer, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( this->m_file == INVALID_HANDLE_VALUE ) {
		return nullptr;
	}

	HANDLE map = CreateFileMapping( this->m_file, nullptr, PAGE_READONLY, 0, 0, nullptr );
	if ( !map ) {
		return nullptr;
	}

	HANDLE map_view = MapViewOfFile( map, FILE_MAP_READ, 0, 0, 0 );
	if ( !map_view ) {
		return nullptr;
	}

	if ( !CloseHandle( this->m_file ) && !CloseHandle( map ) && !CloseHandle( map_view ) ) {
		return nullptr;
	}

	return map_view;
}

PIMAGE_DOS_HEADER Process::FetchDOSHeader( HANDLE map_view )
{
	PIMAGE_DOS_HEADER dos_header = static_cast<PIMAGE_DOS_HEADER>( map_view );
	if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
		return nullptr;
	}

	return dos_header;
}

PIMAGE_NT_HEADERS Process::FetchImageHeader( )
{
	PIMAGE_DOS_HEADER dos_header = Process::FetchDOSHeader( Process::CreateMapView( ) );
	if ( !dos_header ) {
		return nullptr;
	}

	PIMAGE_NT_HEADERS image_header = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<PCHAR>( dos_header ) + dos_header->e_lfanew );
	if ( image_header->Signature != IMAGE_NT_SIGNATURE ) {
		return nullptr;
	}

	return image_header;
}

bool Process::Is64Bit( )
{
	PIMAGE_NT_HEADERS nt_header = Process::FetchImageHeader( );
	if ( !nt_header ) {
		return false;
	}

	if ( nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ) {
		return true;
	}

	return false;
}

std::vector<DWORD> Process::FetchImports( )
{
	std::vector<DWORD> return_imports;

	PIMAGE_NT_HEADERS nt_header = Process::FetchImageHeader( );
	if ( !nt_header ) {
		return { };
	}
	
	DWORD virtual_address = nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress;
	if ( !virtual_address ) {
		return { };
	}

	// TODO
	
	return return_imports;
}

std::vector<Process::HANDLE_INFO> Process::FetchHandles( ) const
{
	std::vector<HANDLE_INFO> return_handles;

	static auto QuerySystemInformation = reinterpret_cast<Process::NtQuerySystemInformation>( GetProcAddress( GetModuleHandleA( "ntdll" ), "NtQuerySystemInformation" ) );

	ULONG return_length = 0;
	ULONG buffer_size = 1 << 20; // 1048576
	std::unique_ptr<BYTE[ ]> buffer( new BYTE[ buffer_size ] );

	NTSTATUS status;

	do // guess buffer size
	{
		status = QuerySystemInformation( SystemExtendedHandleInformation, buffer.get( ), buffer_size, &buffer_size );
		if ( status == STATUS_INFO_LENGTH_MISMATCH )
		{
			buffer_size = ( return_length > buffer_size ) ? return_length : ( buffer_size * 2 );
			buffer.reset( new BYTE[ buffer_size ] );
		}
	} while ( status == STATUS_INFO_LENGTH_MISMATCH && buffer_size < 1 << 24 ); // 16777216

	if ( NT_ERROR( status ) ) {
		buffer.reset( );
	}

	auto system_handle_info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>( buffer.get( ) );
	for ( size_t i = 0; i < system_handle_info->number_of_handles; i++ )
	{
		HANDLE process_copy = nullptr;

		auto system_handle = &system_handle_info->handles[ i ];

		HANDLE process_handle = OpenProcess( PROCESS_DUP_HANDLE, FALSE, system_handle->pid );
		if ( DuplicateHandle( process_handle, reinterpret_cast<HANDLE>( system_handle->handle_value ), GetCurrentProcess( ), &process_copy, PROCESS_QUERY_INFORMATION, 0, 0 ) )
		{
			HANDLE_INFO handle_info = { 0, nullptr };

			if ( GetProcessId( process_copy ) == this->m_pid )
			{
				handle_info.pid = system_handle->pid;
				handle_info.process = reinterpret_cast<HANDLE>( system_handle->handle_value );
				return_handles.push_back( handle_info );
			}
		}

		CloseHandle( process_handle );
		CloseHandle( process_copy );
	}

	return return_handles;
}

HANDLE Process::FetchAccessToken( DWORD desired_access ) const
{
	HANDLE token_handle;

	if ( !OpenProcessToken( this->m_handle, desired_access, &token_handle ) ) {
		return nullptr;
	}

	return token_handle;
}

bool Process::SetPrivilege( LPCTSTR name, BOOL enable_privilege ) const
{
	TOKEN_PRIVILEGES privilege = { 0, 0, 0, 0 };
	LUID luid = { 0, 0 };

	HANDLE token = Process::FetchAccessToken( TOKEN_ADJUST_PRIVILEGES );

	if ( !LookupPrivilegeValueA( nullptr, name, &luid ) ) 
	{
		CloseHandle( token );
		return false;
	}

	privilege.PrivilegeCount = 1;
	privilege.Privileges[ 0 ].Luid = luid;
	privilege.Privileges[ 0 ].Attributes = enable_privilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

	if ( !AdjustTokenPrivileges( token, FALSE, &privilege, 0, nullptr, nullptr ) ) 
	{
		CloseHandle( token );
		return false;
	}

	return true;
}

bool Process::RtlAdjustPrivileges( ULONG privilege, BOOLEAN enable, BOOLEAN current_thread, PBOOLEAN enabled )
{
	static auto AdjustPrivileges = reinterpret_cast<Process::RtlAdjustPrivilege>( GetProcAddress( GetModuleHandleA( "ntdll" ), "RtlAdjustPrivilege" ) );
	if ( NT_ERROR( AdjustPrivileges( privilege, enable, current_thread, enabled ) ) ) {
		return false;
	}

	return true;
}