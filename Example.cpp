/*
* 
* All credits for anti-debug samples: https://github.com/Ahora57
* 
*/

#include <iostream>
#include "syscall/Syscall.hpp"

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <intrin.h>
#include <cstdint>
#include <array>
#include <span>
#include <expected>

#define NtCurrentProcess ( (HANDLE)(LONG_PTR)-1 )
#define NtCurrentThread ( (HANDLE)(LONG_PTR)-2 )

constexpr uint32_t PROCESS_DEBUG_OBJECT_HANDLE = 30;
constexpr uint32_t PROCESS_HANDLE_TRACING = 32;
constexpr uint32_t OBJECT_HANDLE_FLAG_INFORMATION = 4;

struct process_handle_tracing_enable {
    ULONG flags;
};

struct object_handle_flag_information {
    BOOLEAN inherit;
    BOOLEAN protect_from_close;
};

namespace test_wrap {
    void MessageBox ( ) {
        UNICODE_STRING msg_body;
        UNICODE_STRING msg_caption;

        ULONG error_response;

        static constexpr std::wstring_view c_body = L"Hello from kernel";
        msg_body.Length = static_cast< USHORT >( c_body.size ( ) * sizeof ( wchar_t ) );
        msg_body.MaximumLength = msg_body.Length;
        msg_body.Buffer = const_cast< wchar_t* >( c_body.data ( ) );

        static constexpr std::wstring_view c_caption = L"Message";
        msg_caption.Length = static_cast< USHORT >( c_caption.size ( ) * sizeof ( wchar_t ) );
        msg_caption.MaximumLength = msg_caption.Length;
        msg_caption.Buffer = const_cast< wchar_t* >( c_caption.data ( ) );

        const std::array<ULONG_PTR, 3> msg_params = {
            reinterpret_cast< ULONG_PTR >( &msg_body ),
            reinterpret_cast< ULONG_PTR >( &msg_caption ),
            static_cast< ULONG_PTR >( MB_OK | MB_ICONWARNING )
        };

        c_syscall::Syscall<NTSTATUS> ( HASH ( "ZwRaiseHardError" ), 0x50000018L, 0x00000003L, msg_params.size ( ), msg_params.data ( ), nullptr, &error_response );
    }

    std::expected<bool, NTSTATUS> IsDebugObject ( ) {
        bool is_detect = false;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
        uint64_t kernel_address = 0xFFFFF80000000000;
        HANDLE debug_object = nullptr;

        nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, &debug_object, sizeof ( debug_object ), nullptr );

        if ( nt_status != STATUS_PORT_NOT_SET || debug_object != nullptr ) {
            c_syscall::Syscall<NTSTATUS> ( HASH ( "NtRemoveProcessDebug" ), NtCurrentThread, debug_object );
            is_detect = true;
        }

        // Try BSOD by don't check address buffer in ProcessInformation
        for ( uint8_t i = 0; i < 0x10; i++, kernel_address += ( 0x10000000 + __rdtsc ( ) % 0x1000000000 ) ) {
            nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, reinterpret_cast< PVOID >( kernel_address ), sizeof ( HANDLE ), nullptr );
            nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, reinterpret_cast< PVOID >( kernel_address ), nullptr, nullptr );
            nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, nullptr, nullptr, reinterpret_cast< PULONG >( kernel_address ) );
            nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, &debug_object, sizeof ( debug_object ), reinterpret_cast< PULONG >( &debug_object ) );
        }

        debug_object = nullptr;
        nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, &debug_object, sizeof ( debug_object ), nullptr );

        if ( nt_status != STATUS_PORT_NOT_SET || reinterpret_cast< ULONG >( debug_object ) != 0 ) {
            is_detect = true;
        }

        nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, &debug_object, sizeof ( debug_object ), reinterpret_cast< PULONG >( &debug_object ) );
        if ( nt_status != STATUS_PORT_NOT_SET || reinterpret_cast< uint64_t >( debug_object ) != sizeof ( debug_object ) )
            is_detect = true;

        debug_object = reinterpret_cast< HANDLE >( 1 );

        // Alignment Fault check
        nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, reinterpret_cast< PVOID >( 5 ), sizeof ( debug_object ), nullptr );
        if ( ( nt_status != STATUS_DATATYPE_MISALIGNMENT && nt_status != STATUS_INVALID_INFO_CLASS ) || debug_object != reinterpret_cast< HANDLE >( 1 ) ) {
            is_detect = true;
        }

        if ( c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, &debug_object, sizeof ( BOOLEAN ), nullptr ) != STATUS_INFO_LENGTH_MISMATCH )
            is_detect = true;

        // TitanHide return STATUS_INVALID_HANDLE, but should be STATUS_ACCESS_VIOLATION
        nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), nullptr, PROCESS_DEBUG_OBJECT_HANDLE, &debug_object, sizeof ( debug_object ), reinterpret_cast< PULONG >( kernel_address % 0x1000 | 1 ) );
        if ( ( nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT ) || debug_object != reinterpret_cast< HANDLE >( 1 ) )
            is_detect = true;

        nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, &debug_object, sizeof ( debug_object ), reinterpret_cast< PULONG >( kernel_address % 0x1000 | 1 ) );
        if ( ( nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT ) || debug_object != reinterpret_cast< HANDLE >( 1 ) )
            is_detect = true;

        // HyperHide return STATUS_INFO_LENGTH_MISMATCH, but should be STATUS_ACCESS_VIOLATION
        nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), NtCurrentProcess, PROCESS_DEBUG_OBJECT_HANDLE, &debug_object, nullptr, reinterpret_cast< PULONG >( kernel_address % 0x1000 | 1 ) );
        if ( ( nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT ) || debug_object != reinterpret_cast< HANDLE >( 1 ) )
            is_detect = true;

        return is_detect;
    }

    std::expected<bool, NTSTATUS> IsHideThread ( ) {
        bool is_thread_hide = false;

        if ( NT_SUCCESS ( c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationThread" ), NtCurrentThread, 0x11, nullptr, 0 ) ) ) {
            auto nt_status = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationThread" ), NtCurrentThread, 0x11, &is_thread_hide, sizeof ( is_thread_hide ), nullptr );
            if ( NT_SUCCESS ( nt_status ) && is_thread_hide ) {
                is_thread_hide = true;
            }
        }

        return is_thread_hide;
    }

    std::expected<bool, NTSTATUS> IsDuplicateHandleBad ( ) {
        bool is_detect = false;
        HANDLE duplicate_handle = nullptr;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
        process_handle_tracing_enable tracing_handle = { 0 };
        object_handle_flag_information object_flag_info = { false, false };

        // STATUS_ACCESS_VIOLATION should be (rip SharpOD)
        if ( STATUS_INVALID_HANDLE == c_syscall::Syscall<NTSTATUS> ( HASH ( "NtDuplicateObject" ), NtCurrentProcess, nullptr, NtCurrentProcess, reinterpret_cast< PHANDLE >( 1 ), nullptr, FALSE, DUPLICATE_CLOSE_SOURCE ) )
            is_detect = true;

        __try {
            object_flag_info.protect_from_close = TRUE;
            c_syscall::Syscall<NTSTATUS> ( HASH ( "NtDuplicateObject" ), NtCurrentProcess, NtCurrentProcess, NtCurrentProcess, &duplicate_handle, nullptr, FALSE, 0 );
            c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationObject" ), duplicate_handle, OBJECT_HANDLE_FLAG_INFORMATION, &object_flag_info, sizeof ( object_flag_info ) );
            c_syscall::Syscall<NTSTATUS> ( HASH ( "NtDuplicateObject" ), NtCurrentProcess, duplicate_handle, NtCurrentProcess, &duplicate_handle, nullptr, FALSE, DUPLICATE_CLOSE_SOURCE );
        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            is_detect = true;
        }

        object_flag_info.protect_from_close = FALSE;
        c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationObject" ), duplicate_handle, OBJECT_HANDLE_FLAG_INFORMATION, &object_flag_info, sizeof ( object_flag_info ) );
        c_syscall::Syscall<NTSTATUS> ( HASH ( "NtClose" ), duplicate_handle );

        if ( !NT_SUCCESS ( c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationObject" ), NtCurrentProcess, PROCESS_HANDLE_TRACING, &tracing_handle, sizeof ( process_handle_tracing_enable ) ) ) )
            return is_detect;

        __try {
            object_flag_info.protect_from_close = TRUE;
            c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationObject" ), NtCurrentProcess, NtCurrentProcess, NtCurrentProcess, &duplicate_handle, nullptr, FALSE, 0 );
            c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationObject" ), duplicate_handle, OBJECT_HANDLE_FLAG_INFORMATION, &object_flag_info, sizeof ( object_flag_info ) );
            c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationObject" ), NtCurrentProcess, duplicate_handle, NtCurrentProcess, &duplicate_handle, nullptr, FALSE, DUPLICATE_CLOSE_SOURCE );
            is_detect = true;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            if ( GetExceptionCode ( ) != STATUS_HANDLE_NOT_CLOSABLE )
                is_detect = true;
        }

        // Disable tracing
        c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationObject" ), NtCurrentProcess, PROCESS_HANDLE_TRACING, &tracing_handle, 0 );

        object_flag_info.protect_from_close = FALSE;
        c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationObject" ), duplicate_handle, OBJECT_HANDLE_FLAG_INFORMATION, &object_flag_info, sizeof ( object_flag_info ) );
        c_syscall::Syscall<NTSTATUS> ( HASH ( "NtClose" ), duplicate_handle );

        return is_detect;
    }

}

int main ( ) {
    SetConsoleTitleW ( L"Some test..." );

    if ( auto result = test_wrap::IsDebugObject ( ) )
        std::cout << "Is debug object -> " << *result << '\n';
    else
        std::cout << "Error checking debug object: " << result.error ( ) << '\n';

    if ( auto result = test_wrap::IsHideThread ( ) )
        std::cout << "Is bad hide thread -> " << !*result << '\n';
    else
        std::cout << "Error checking hide thread: " << result.error ( ) << '\n';

    if ( auto result = test_wrap::IsDuplicateHandleBad ( ) )
        std::cout << "Is duplicate bad -> " << *result << '\n';
    else
        std::cout << "Error checking duplicate handle: " << result.error ( ) << '\n';

    test_wrap::MessageBox ( );
    return EXIT_SUCCESS;
}