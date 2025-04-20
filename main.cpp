#include <syscall/syscall.hpp>
#include <iostream>

bool is_debugged () {
    uint64_t being_debugged = 0;
    uint64_t return_length = 0;

    NTSTATUS status = syscall::invoke<NTSTATUS> ("NtQueryInformationProcess",
        NtCurrentProcess (),
        ProcessDebugPort,
        &being_debugged,
        sizeof (uint64_t),
        &return_length);

    printf ("[*] NtQueryInformationProcess: 0x%X\n", status);

    if (!NT_SUCCESS (status)) {
        return false;
    }

    return being_debugged != 0;
}

NTSTATUS alloc_memory (
    HANDLE process_handle,
    PVOID* base_address,
    SIZE_T region_size,
    ULONG allocation_type,
    ULONG protection
) {
    return syscall::invoke<NTSTATUS> (
        "NtAllocateVirtualMemory",
        process_handle,
        base_address,
        0,
        &region_size,
        allocation_type,
        protection
    );
}

NTSTATUS protect_memory (
    HANDLE process_handle,
    PVOID* base_address,
    SIZE_T* region_size,
    ULONG new_protection,
    PULONG old_protection
) {
    return syscall::invoke<NTSTATUS> (
        "NtProtectVirtualMemory",
        process_handle,
        base_address,
        region_size,
        new_protection,
        old_protection
    );
}

int main () {
    if (!syscall::initialize ()) {
        printf ("[*] Failed to initialize syscalls!\n");
        return 1;
    }

    printf ("[*] Allocating memory...\n");

    PVOID base_address = nullptr;
    SIZE_T region_size = 0x1000;

    NTSTATUS status = alloc_memory (
        NtCurrentProcess (),
        &base_address,
        region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NT_SUCCESS (status)) {
        printf ("[*] Successfully allocated memory at 0x%p\n", base_address);

        ULONG old_protection = 0;
        status = protect_memory (
            NtCurrentProcess (),
            &base_address,
            &region_size,
            PAGE_NOACCESS,
            &old_protection
        );

        if (NT_SUCCESS (status)) {
            printf ("[*] Successfully changed memory protection to PAGE_NOACCESS\n\n");
        } else {
            printf ("[*] Failed to change memory protection: 0x%X\n\n", status);
        }
    } else {
        printf ("[*] Failed to allocate memory: 0x%X\n\n", status);
    }

    printf ("[*] Checking if process is debugged\n");

    if (is_debugged ()) {
        printf ("[*] Process is debugged\n\n");
    } else {
        printf ("[*] Process is not debugged\n\n");
    }

    printf ("[*] NtContinue number: 0x%X\n\n", syscall::get_syscall_number ("NtContinue").value_or (0));

    printf ("[*] End!\n");
    std::cin.get ();

    return 0;
}