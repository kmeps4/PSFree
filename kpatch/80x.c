/* Copyright (C) 2024 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#include <stddef.h>

#include "types.h"

void enable_cr0_wp(void) {
    asm(
        "mov rax, cr0\n"
        "or rax, 0x10000\n"
        "mov cr0, rax\n"
    );
}

void disable_cr0_wp(void) {
    asm(
        "mov rax, cr0\n"
        "and rax, ~0x10000\n"
        "mov cr0, rax\n"
    );
}

inline void write8(void *addr, size_t offset, u8 value) {
    *(u8 *)(addr + offset) = value;
}

inline void write16(void *addr, size_t offset, u16 value) {
    *(u16 *)(addr + offset) = value;
}

inline void write32(void *addr, size_t offset, u32 value) {
    *(u32 *)(addr + offset) = value;
}

inline void write64(void *addr, size_t offset, u64 value) {
    *(u64 *)(addr + offset) = value;
}

// Args:
//   kbase: kernel base address
//   res:
//     Needed value to return (as to not crash) if the caller of the hijacked
//     function is expecting some valid value.
//   error:
//     Address to return an error. 0 for success.
__attribute__((section (".text.start")))
u64 kpatch(void *kbase, u64 res, u64 *error) {
    if (kbase == NULL) {
        if (error != NULL) {
            *error = -1;
        }

        goto end;
    }

    disable_cr0_wp();

    // patch amd64_syscall() to allow calling syscalls everywhere
    write32(kbase, 0x490, 0);
    write16(kbase, 0x4b5, 0x9090);
    write16(kbase, 0x4b9, 0x9090);
    write8(kbase, 0x4c2, 0xeb);

    // patch sys_mmap() to allow rwx mappings

    // patch maximum cpu mem protection: 0x33 -> 0x37
    // the ps4 added custom protections for their gpu memory accesses
    // GPU R: 0x10, W: 0x20, X:, 0x40
    // that's why you see other bits set
    write8(kbase, 0xfd03a, 0x37);
    write8(kbase, 0xfd03d, 0x37);

    // patch vm_map_protect() (called by sys_mprotect()) to allow rwx mappings
    write32(kbase, 0x3ec68d, 0);

    // patch sys_dynlib_dlsym() to allow dynamic symbol resolution everywhere

    // patch to alway jump regardless of the check before
    write8(kbase, 0x31953f, 0xeb);
    // patch called function to always return 0
    write32(kbase, 0x951c0, 0xC3C03148);

    // patch sys_setuid() to allow freely changing the effective user ID

    // patch to alway jump regardless of the check before
    write8(kbase, 0x34d696, 0xeb);

    // overwrite the entry of syscall 11 (unimplemented) in sysent
    //
    // struct args {
    //     u64 rdi;
    //     u64 rsi;
    //     u64 rdx;
    //     u64 rdx;
    //     u64 r8;
    //     u64 r9;
    // }
    //
    // jumps to uap->rdi
    // u64 sys_kexec(struct thread td, struct args *uap)

    // sysent[11]
    const size_t offset_sysent_11 = 0x10fc6e0;
    // .sy_narg = 2
    write32(kbase, offset_sysent_11, 2);
    // .sy_call = gadgets['jmp qword ptr [rsi]']
    write64(kbase, offset_sysent_11 + 8, kbase + 0xe629c);
    // .sy_thrcnt = SY_THR_STATIC
    write32(kbase, offset_sysent_11 + 0x2c, 1);

    // restore socketops.fo_chmod
    // it was used to initially to perform kernel code execution
    write64(kbase, 0x1a76060, kbase + 0x3d0a60);

    enable_cr0_wp();

    if (error != NULL) {
        *error = 0;
    }
end:
    return res;
}
