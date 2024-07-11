# sec_no_syscalls

sec_no_syscalls is a x64 library that allows you to call syscall directly using the SEC_NO_CHANGE flag.

# How it works?

For each shellcode instruction, a new region with SEC_NO_CHANGE flag is prepared, when this instruction is executed, it passes control to the next region, where the next shellcode instruction is executed, and the region itself, in addition to the two instructions, is filled with random bytes to break the disassembler when scrolling.

Example:
```cpp
... random bytes
push rcx
jmp to_next_region
... random bytes

next_region:
... random bytes
pop r10
jmp to_next_region2
... random bytes

next_region2:
... random bytes
pop r10
jmp to_next_region3
... random bytes

next_region3:
... random bytes
mov eax, system_number
jmp to_next_region4
... random bytes

next_region4:
... random bytes
syscall
jmp to_next_region5
... random bytes

next_region5:
... random bytes
add rsp, 8
jmp to_next_region6
... random bytes

next_region6:
... random bytes
add rsp, 8
jmp to_next_region7
... random bytes

next_region7:
... random bytes
jmp qword ptr ds:[rsp-8]
... random bytes
```

The regions themselves are mapped several times, the first time the regions are given access to "PAGE_READWRITE" to be able to fill in the shellcode, then after the installation of the shellcodes, the second remapping takes place with the protection of "PAGE_EXECUTE" so that nothing can be written to the region in the future.

# Example of using

```cpp
#include "syscall/Syscall.hpp"

namespace antidebug {
    void HideThread ( ) {
        try {
            const auto res = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtSetInformationThread" ), GetCurrentThread ( ), 0x11, 0, 0 );
            std::printf ( "NtSetInformationThread result: 0x%X\n", res );
        }
        catch ( std::exception& ex ) {
            std::printf ( "%s\n", ex.what ( ) );
        }
    }

    void CheckDebugObjectHandle ( ) {
        try {
            HANDLE debug_object;
            ULONG ret = NULL;

            const auto res = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), GetCurrentProcess ( ), 0x1E, &debug_object, sizeof ( DWORD64 ), &ret );
            std::printf ( "NtQueryInformationProcess result: 0x%X\n", res );
        }
        catch ( std::exception& ex ) {
            std::printf ( "%s\n", ex.what ( ) );
        }
    }

    void CheckProcessDebugFlags ( ) {
        try {
            DWORD64 debug_flags;
            ULONG ret = NULL;

            const auto res = c_syscall::Syscall<NTSTATUS> ( HASH ( "NtQueryInformationProcess" ), GetCurrentProcess ( ), 0x1F, &debug_flags, sizeof ( DWORD ), &ret );
            std::printf ( "NtQueryInformationProcess result: 0x%X:0x%X\n", res, debug_flags );
        }
        catch ( std::exception& ex ) {
            std::printf ( "%s\n", ex.what ( ) );
        }
    }
}

int main ( ) {
    antidebug::HideThread ( );
    antidebug::CheckDebugObjectHandle ( );
    antidebug::CheckProcessDebugFlags ( );

    while ( true );
    return 0;
}
```

# Problems
Despite all this, the library itself creates many potential patterns for the reverse engineer, for example: calling PEB or calling the GetCurrentProcess import, which I happily forgot about.

In general, you can cover this library with a mutation from private protectors, like VMProtect.

I don't think I'll be making any changes to this library. Enjoy!