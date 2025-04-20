#ifndef SYSCALL_HPP
#define SYSCALL_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <fstream>
#include <mutex>

#include <shared/shared.hpp>

namespace syscall {
    static std::mutex g_syscall_mutex;

    struct syscall_entry {
        std::string name;
        uint32_t number;
        uint32_t offset;
    };

    static std::unordered_map<std::string, syscall_entry> g_syscall_map;
    static void* g_syscall_region = nullptr;
    static size_t g_region_size = 0;
    static bool g_initialized = false;

    static constexpr uint8_t syscall_shellcode[] = {
        0x51,                           // push rcx
        0x41, 0x5A,                     // pop r10
        0xB8, 0x37, 0x13, 0x37, 0x13,   // mov eax, 13371337
        0x0F, 0x05,                     // syscall
        0x48, 0x83, 0xC4, 0x08,         // add rsp, 8
        0xFF, 0x64, 0x24, 0xF8          // jmp qword ptr [rsp - 8]
    };

    static constexpr size_t syscall_stub_size = sizeof (syscall_shellcode);

    static uint32_t rva_to_offset (uint32_t rva, IMAGE_NT_HEADERS* nt_headers) {
        IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION (nt_headers);

        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER& section = sections[i];

            if (rva >= section.VirtualAddress &&
                rva < section.VirtualAddress + section.Misc.VirtualSize) {
                return rva - section.VirtualAddress + section.PointerToRawData;
            }
        }

        return rva;
    }

    bool extract_syscalls () {
        HMODULE ntdll_handle = GetModuleHandleA ("ntdll.dll");
        if (!ntdll_handle) {
            return false;
        }

        char ntdll_path[MAX_PATH];
        if (!GetModuleFileNameA (ntdll_handle, ntdll_path, MAX_PATH)) {
            return false;
        }

        std::ifstream ntdll_file (ntdll_path, std::ios::binary);
        if (!ntdll_file.is_open ()) {
            return false;
        }

        std::vector<uint8_t> ntdll_data ((std::istreambuf_iterator<char> (ntdll_file)), std::istreambuf_iterator<char> ());
        ntdll_file.close ();

        IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll_data.data ());
        IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(ntdll_data.data () + dos_header->e_lfanew);

        uint32_t export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        IMAGE_EXPORT_DIRECTORY* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            ntdll_data.data () + rva_to_offset (export_dir_rva, nt_headers));

        uint32_t* function_rvas = reinterpret_cast<uint32_t*>(
            ntdll_data.data () + rva_to_offset (export_dir->AddressOfFunctions, nt_headers));
        uint32_t* name_rvas = reinterpret_cast<uint32_t*>(
            ntdll_data.data () + rva_to_offset (export_dir->AddressOfNames, nt_headers));
        uint16_t* ordinals = reinterpret_cast<uint16_t*>(
            ntdll_data.data () + rva_to_offset (export_dir->AddressOfNameOrdinals, nt_headers));

        for (uint32_t i = 0; i < export_dir->NumberOfNames; i++) {
            const char* name = reinterpret_cast<const char*>(
                ntdll_data.data () + rva_to_offset (name_rvas[i], nt_headers));

            uint16_t ordinal = ordinals[i];
            uint32_t function_rva = function_rvas[ordinal];
            uint8_t* function_start = ntdll_data.data () + rva_to_offset (function_rva, nt_headers);

            // Check for the 4-byte signature: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...)
            if (*reinterpret_cast<uint32_t*> (function_start) == 0xB8D18B4C) {
                std::string func_name (name);
                uint32_t syscall_number = *reinterpret_cast<uint32_t*>(function_start + 4);

                syscall_entry entry;
                entry.name = func_name;
                entry.number = syscall_number;
                entry.offset = g_syscall_map.size () * syscall_stub_size;

                g_syscall_map[func_name] = entry;
            }
        }

        return !g_syscall_map.empty ();
    }

    static bool create_syscalls () {
        if (g_syscall_map.empty ()) {
            return false;
        }

        g_region_size = g_syscall_map.size () * syscall_stub_size;

        std::vector<uint8_t> temp_buffer (g_region_size);

        for (const auto& pair : g_syscall_map) {
            const syscall_entry& entry = pair.second;

            memcpy (temp_buffer.data () + entry.offset, syscall_shellcode, syscall_stub_size);

            *reinterpret_cast<uint32_t*>(temp_buffer.data () + entry.offset + 4) = entry.number;
        }

        HANDLE section_handle = nullptr;

        LARGE_INTEGER section_size;
        section_size.QuadPart = g_region_size;

        auto nt_create_section = reinterpret_cast<_NtCreateSection>(
            GetProcAddress (GetModuleHandleA ("ntdll.dll"), "NtCreateSection"));

        auto nt_map_view_of_section = reinterpret_cast<_NtMapViewOfSection>(
            GetProcAddress (GetModuleHandleA ("ntdll.dll"), "NtMapViewOfSection"));

        if (!nt_create_section || !nt_map_view_of_section) {
            return false;
        }

        NTSTATUS status = nt_create_section (
            &section_handle,
            SECTION_ALL_ACCESS,
            nullptr,
            &section_size,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT | SEC_NO_CHANGE,
            nullptr
        );

        if (!NT_SUCCESS (status)) {
            return false;
        }

        void* temp_view = nullptr;
        SIZE_T view_size = g_region_size;

        status = nt_map_view_of_section (
            section_handle,
            NtCurrentProcess (),
            &temp_view,
            0,
            0,
            nullptr,
            &view_size,
            ViewShare,
            0,
            PAGE_READWRITE
        );

        if (!NT_SUCCESS (status)) {
            CloseHandle (section_handle);
            return false;
        }

        memcpy (temp_view, temp_buffer.data (), g_region_size);

        auto nt_unmap_view_of_section = reinterpret_cast<_NtUnmapViewOfSection>(
            GetProcAddress (GetModuleHandleA ("ntdll.dll"), "NtUnmapViewOfSection"));

        if (!nt_unmap_view_of_section) {
            CloseHandle (section_handle);
            return false;
        }

        status = nt_unmap_view_of_section (NtCurrentProcess (), temp_view);

        if (!NT_SUCCESS (status)) {
            CloseHandle (section_handle);
            return false;
        }

        g_syscall_region = nullptr;
        view_size = g_region_size;

        status = nt_map_view_of_section (
            section_handle,
            NtCurrentProcess (),
            &g_syscall_region,
            0,
            0,
            nullptr,
            &view_size,
            ViewShare,
            0,
            PAGE_EXECUTE_READ
        );

        CloseHandle (section_handle);

        if (!NT_SUCCESS (status) || !g_syscall_region) {
            return false;
        }

        return true;
    }

    static bool initialize () {
        if (g_initialized) {
            return true;
        }

        std::lock_guard<std::mutex> lock (g_syscall_mutex);

        if (extract_syscalls ()) {
            g_initialized = create_syscalls ();
        }

        return g_initialized;
    }

    static bool is_initialized () {
        std::lock_guard<std::mutex> lock (g_syscall_mutex);
        return g_initialized;
    }

    static std::optional<uint32_t> get_syscall_number (const std::string& function_name) {
        std::lock_guard<std::mutex> lock (g_syscall_mutex);

        auto it = g_syscall_map.find (function_name);
        if (it != g_syscall_map.end ()) {
            return it->second.number;
        }
        return std::nullopt;
    }

    template<typename T>
    static T get_syscall_func (const std::string& function_name) {
        std::lock_guard<std::mutex> lock (g_syscall_mutex);

        if (!g_initialized || !g_syscall_region) {
            return nullptr;
        }

        auto it = g_syscall_map.find (function_name);
        if (it == g_syscall_map.end ()) {
            return nullptr;
        }

        uint8_t* stub_address = reinterpret_cast<uint8_t*>(g_syscall_region) + it->second.offset;
        return reinterpret_cast<T>(stub_address);
    }

    template<typename Ret, typename... Args>
    static Ret invoke (const std::string& syscall_name, Args... args) {
        bool needs_init = false;
        {
            std::lock_guard<std::mutex> lock (g_syscall_mutex);
            needs_init = !g_initialized;
        }

        if (needs_init) {
            initialize ();
        }

        using func_t = Ret (NTAPI*)(Args...);
        func_t func = get_syscall_func<func_t> (syscall_name);

        if (func) {
            return func (std::forward<Args> (args)...);
        }

        return Ret {};
    }
}

#endif
