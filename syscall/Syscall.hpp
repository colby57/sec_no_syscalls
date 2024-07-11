#pragma once

#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <memory>
#include <random>
#include <iostream>

#define SEC_NO_CHANGE 0x00400000

__forceinline constexpr uint32_t fnv1a_32 ( const char* str, size_t n ) {
    uint32_t hash = 2166136261u;
    for ( size_t i = 0; i < n; ++i ) {
        hash ^= static_cast< uint8_t >( str [ i ] );
        hash *= 16777619u;
    }
    return hash;
}

#define HASH(str) fnv1a_32(str, sizeof(str) - 1)

class c_syscall {
protected:
    struct UNICODE_STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        PWCH Buffer;
    };

    struct LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        union
        {
            LIST_ENTRY InInitializationOrderLinks;
            LIST_ENTRY InProgressLinks;
        };
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
    };

    typedef enum _SECTION_INHERIT {
        ViewShare = 1,
        ViewUnmap = 2
    } SECTION_INHERIT, * PSECTION_INHERIT;

    struct s_memory_block {
        HANDLE m_section_handle;
        void* m_base_address;

        s_memory_block ( HANDLE handle, void* address )
            : m_section_handle ( handle ), m_base_address ( address ) {}
    };

private:
    typedef NTSTATUS ( NTAPI* pNtCreateSection )( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE );
    typedef NTSTATUS ( NTAPI* pNtMapViewOfSection )( HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG );
    typedef NTSTATUS ( NTAPI* pNtUnmapViewOfSection )( HANDLE, PVOID );

    __forceinline static std::uintptr_t GetProcAddress ( std::uintptr_t module_base, uint32_t function_hash ) {
        PIMAGE_DOS_HEADER dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( module_base );
        PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS64 >( module_base + dos_header->e_lfanew );
        PIMAGE_EXPORT_DIRECTORY export_directory = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( module_base + nt_headers->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

        const uint32_t* names = reinterpret_cast< uint32_t* >( module_base + export_directory->AddressOfNames );
        const uint16_t* ordinals = reinterpret_cast< uint16_t* >( module_base + export_directory->AddressOfNameOrdinals );
        const uint32_t* functions = reinterpret_cast< uint32_t* >( module_base + export_directory->AddressOfFunctions );

        for ( uint32_t i = 0; i < export_directory->NumberOfNames; ++i ) {
            const char* name = reinterpret_cast< const char* >( module_base + names [ i ] );
            uint32_t current_hash = fnv1a_32 ( name, strlen ( name ) );

            if ( current_hash == function_hash )
                return module_base + functions [ ordinals [ i ] ];
        }

        throw std::runtime_error ( "Failed to get function address" );
    }

    __forceinline static std::uintptr_t GetModuleHandle ( std::string_view module_name ) {
        PEB* peb = reinterpret_cast< PEB* >( __readgsqword ( 0x60 ) );
        PEB_LDR_DATA* ldr = peb->Ldr;
        LIST_ENTRY* first = &ldr->InMemoryOrderModuleList;
        LIST_ENTRY* current = first->Flink;

        while ( current != first ) {
            LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD ( current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
            if ( entry->BaseDllName.Length > 0 ) {
                std::wstring_view current_name ( entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof ( wchar_t ) );
                std::wstring wide_module_name ( module_name.begin ( ), module_name.end ( ) );

                if ( _wcsicmp ( current_name.data ( ), wide_module_name.c_str ( ) ) == 0 ) {
                    return reinterpret_cast< std::uintptr_t >( entry->DllBase );
                }
            }
            current = current->Flink;
        }
        return 0;
    }

    __forceinline static uint32_t GetSystemNumber ( uint32_t function_hash ) {
        const auto ntdll = GetModuleHandle ( "ntdll.dll" );
        if ( !ntdll )
            throw std::runtime_error ( "Failed to get ntdll.dll handle" );

        const auto function = GetProcAddress ( ntdll, function_hash );
        if ( !function )
            throw std::runtime_error ( "Failed to get function address" );

        uint8_t* function_bytes = reinterpret_cast< uint8_t* >( function );
        for ( int i = 0; i < 20; ++i ) {
            if ( function_bytes [ i ] == 0x4C && function_bytes [ i + 1 ] == 0x8B && function_bytes [ i + 2 ] == 0xD1 &&
                function_bytes [ i + 3 ] == 0xB8 && function_bytes [ i + 6 ] == 0x00 && function_bytes [ i + 7 ] == 0x00 ) {
                return *reinterpret_cast< uint32_t* >( &function_bytes [ i + 4 ] );
            }
        }
        throw std::runtime_error ( "Failed to find syscall number" );
    }

    __forceinline static void FillWithRandomBytes ( uint8_t* buffer, size_t size ) {
        static std::random_device rd;
        static std::mt19937 gen ( rd ( ) );
        static std::uniform_int_distribution<> dis ( 0, 255 );

        for ( size_t i = 0; i < size; ++i )
            buffer [ i ] = static_cast< uint8_t >( dis ( gen ) );
    }

    __forceinline static s_memory_block AllocateExecutableMemory ( size_t size ) {
        static pNtCreateSection NtCreateSection = reinterpret_cast< pNtCreateSection >( GetProcAddress ( GetModuleHandle ( "ntdll.dll" ), HASH ( "NtCreateSection" ) ) );
        static pNtMapViewOfSection NtMapViewOfSection = reinterpret_cast< pNtMapViewOfSection >( GetProcAddress ( GetModuleHandle ( "ntdll.dll" ), HASH ( "NtMapViewOfSection" ) ) );
        static pNtUnmapViewOfSection NtUnmapViewOfSection = reinterpret_cast< pNtUnmapViewOfSection >( GetProcAddress ( GetModuleHandle ( "ntdll.dll" ), HASH ( "NtUnmapViewOfSection" ) ) );

        HANDLE section_handle {};
        LARGE_INTEGER section_size {};
        section_size.QuadPart = size;

        NTSTATUS status = NtCreateSection ( &section_handle, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, NULL );
        if ( status != 0 ) {
            throw std::runtime_error ( "Failed to create section" );
        }

        PVOID base_address { nullptr };
        SIZE_T view_size { size };

        status = NtMapViewOfSection ( section_handle, GetCurrentProcess ( ), &base_address, 0, size, NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE );
        if ( status != 0 ) {
            CloseHandle ( section_handle );
            throw std::runtime_error ( "Failed to map view of section" );
        }

        std::memset ( base_address, 0xCC, size );
        return s_memory_block ( section_handle, base_address );
    }

    __forceinline static size_t GetRandomOffset ( size_t block_size, size_t instruction_size ) {
        static std::random_device rd;
        static std::mt19937 gen ( rd ( ) );
        std::uniform_int_distribution<> dis ( 16, block_size - instruction_size - 16 );
        return dis ( gen );
    }

    template<typename... Args>
    __forceinline static void BuildObfuscatedShellcode ( std::vector<s_memory_block>& memory_blocks, std::vector<size_t>& instruction_offsets, uint32_t syscall_number, Args... args ) {
        const size_t block_size = 8196;
        const size_t num_blocks = 6;
        static pNtMapViewOfSection NtMapViewOfSection = reinterpret_cast< pNtMapViewOfSection >( GetProcAddress ( GetModuleHandle ( "ntdll.dll" ), HASH ( "NtMapViewOfSection" ) ) );
        static pNtUnmapViewOfSection NtUnmapViewOfSection = reinterpret_cast< pNtUnmapViewOfSection >( GetProcAddress ( GetModuleHandle ( "ntdll.dll" ), HASH ( "NtUnmapViewOfSection" ) ) );

        std::vector<uint8_t> instructions [ ] = {
            {0x51},                          // push rcx
            {0x41, 0x5A},                    // pop r10
            {0xB8},                          // mov eax, ...
            {0x0F, 0x05},                    // syscall
            {0x48, 0x83, 0xC4, 0x08},        // add rsp, 8
            {0xFF, 0x64, 0x24, 0xF8},        // jmp qword ptr [rsp - 8]
        };

        instructions [ 2 ].insert ( instructions [ 2 ].end ( ),
            reinterpret_cast< uint8_t* >( &syscall_number ),
            reinterpret_cast< uint8_t* >( &syscall_number ) + sizeof ( syscall_number ) );

        for ( size_t i = 0; i < num_blocks; ++i ) {
            auto block = AllocateExecutableMemory ( block_size );
            memory_blocks.push_back ( block );

            FillWithRandomBytes ( static_cast< uint8_t* >( block.m_base_address ), block_size );

            size_t offset = GetRandomOffset ( block_size, instructions [ i ].size ( ) + 5 );
            instruction_offsets.push_back ( offset );

            std::memcpy ( static_cast< uint8_t* >( block.m_base_address ) + offset, instructions [ i ].data ( ), instructions [ i ].size ( ) );

            if ( i < num_blocks - 1 ) {
                uint8_t* jmp_location = static_cast< uint8_t* >( block.m_base_address ) + offset + instructions [ i ].size ( );
                jmp_location [ 0 ] = 0xE9;
                *reinterpret_cast< uint32_t* >( jmp_location + 1 ) = 0;
            }
        }

        // Fill in the correct JMP offsets
        for ( size_t i = 0; i < num_blocks - 1; ++i ) {
            uint8_t* current_block = static_cast< uint8_t* >( memory_blocks [ i ].m_base_address );
            uint8_t* next_block = static_cast< uint8_t* >( memory_blocks [ i + 1 ].m_base_address );

            uint64_t current_jmp_location = reinterpret_cast< uint64_t >( current_block ) + instruction_offsets [ i ] + instructions [ i ].size ( );
            uint64_t next_instruction_start = reinterpret_cast< uint64_t >( next_block ) + instruction_offsets [ i + 1 ];

            int32_t jmp_offset = static_cast< int32_t >( next_instruction_start - ( current_jmp_location + 5 ) );
            *reinterpret_cast< int32_t* >( current_jmp_location + 1 ) = jmp_offset;
        }

        // Remap all sections with PAGE_EXECUTE
        for ( auto& block : memory_blocks ) {
            NtUnmapViewOfSection ( GetCurrentProcess ( ), block.m_base_address );
            PVOID base_address = nullptr;
            SIZE_T view_size = block_size;
            NTSTATUS status = NtMapViewOfSection ( block.m_section_handle, GetCurrentProcess ( ), &base_address, 0, block_size, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE );
            if ( status != 0 ) {
                throw std::runtime_error ( "Failed to remap view of section" );
            }
        }
    }

public:
    template<typename ReturnType, typename... Args>
    __forceinline static ReturnType Syscall ( uint32_t function_hash, Args... args ) {
        uint32_t syscall_number = GetSystemNumber ( function_hash );
        std::vector<s_memory_block> memory_blocks;
        std::vector<size_t> instruction_offsets;
        BuildObfuscatedShellcode ( memory_blocks, instruction_offsets, syscall_number, args... );

        ReturnType result = reinterpret_cast< ReturnType ( * )( Args... ) >(
            static_cast< uint8_t* >( memory_blocks [ 0 ].m_base_address ) + instruction_offsets [ 0 ] )( args... );

        static pNtUnmapViewOfSection NtUnmapViewOfSection = reinterpret_cast< pNtUnmapViewOfSection >( GetProcAddress ( GetModuleHandle ( "ntdll.dll" ), HASH ( "NtUnmapViewOfSection" ) ) );
        for ( auto& block : memory_blocks ) {
            NtUnmapViewOfSection ( GetCurrentProcess ( ), block.m_base_address );
            CloseHandle ( block.m_section_handle );
        }

        return result;
    }
};