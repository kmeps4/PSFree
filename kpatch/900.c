/* Copyright (C) 2024-2025 anonymous

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

// 9.00

#include <stddef.h>

#include "types.h"
#include "utils.h"

struct kexec_args {
    u64 entry;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
};

void do_patch(void *kbase);
void patch_aio(void *kbase);
void restore(void *kbase, struct kexec_args *uap);

__attribute__((section (".text.start")))
int kpatch(void *td, struct kexec_args *uap) {
    const u64 xfast_syscall_off = 0x1c0;
    void * const kbase = (void *)rdmsr(0xc0000082) - xfast_syscall_off;

    do_patch(kbase);
    patch_aio(kbase);
    restore(kbase, uap);

    return 0;
}

void restore(void *kbase, struct kexec_args *uap) {
    u8 *pipe = uap->arg1;
    u8 *pipebuf = uap->arg2;
    for (size_t i = 0; i < 0x18; i++) {
        pipe[i] = pipebuf[i];
    }
    u64 *pktinfo_field = uap->arg3;
    *pktinfo_field = 0;
    u64 *pktinfo_field2 = uap->arg4;
    *pktinfo_field2 = 0;

    u64 *sysent_661_save = uap->arg5;
    for (int i = 0; i < 0x30; i += 8) {
        write64(kbase, 0x1107f00 + i, sysent_661_save[i / 8]);
    }
}

void patch_aio(void *kbase) {
    disable_cr0_wp();

    const u64 aio_off = 0x415A01;

    // patch = {0xeb, 0x48}
    write16(kbase, aio_off, 0x48eb);

    // offset = 0x42
    // patch = {0xeb, 0x06}
    write16(kbase, aio_off + 0x42, 0x06eb);

    // offset = 0x4a
    // patch = {0x41, 0x83, 0xbf, 0xa0, 0x04, 0x00, 0x00, 0x00}
    write64(kbase, aio_off + 0x4a, 0x00000004a0bf8341);

    // offset = 0x58
    // patch = {0x49, 0x8b, 0x87, 0xd0, 0x04, 0x00, 0x00}
    write32(kbase, aio_off + 0x58, 0xd0878b49);
    write16(kbase, aio_off + 0x5c, 0x0004);
    write8(kbase, aio_off + 0x5e, 0x00);

    // offset = 0x65
    // patch = {0x49, 0x8b, 0xb7, 0xb0, 0x04, 0x00, 0x00}
    write32(kbase, aio_off + 0x65, 0xb0b78b49);
    write16(kbase, aio_off + 0x69, 0x0004);
    write8(kbase, aio_off + 0x6b, 0x00);

    // offset = 0x7d
    // patch = {0x49, 0x8b, 0x87, 0x40, 0x05, 0x00, 0x00}
    write32(kbase, aio_off + 0x7d, 0x40878b49);
    write16(kbase, aio_off + 0x81, 0x0005);
    write8(kbase, aio_off + 0x83, 0x00);

    // offset = 0x8a
    // patch = {0x49, 0x8b, 0xb7, 0x20, 0x05, 0x00, 0x00}
    write32(kbase, aio_off + 0x8a, 0x20b78b49);
    write16(kbase, aio_off + 0x8e, 0x0005);
    write8(kbase, aio_off + 0x90, 0x00);

    // offset = 0xa2
    // patch = {0x49, 0x8d, 0xbf, 0xc0, 0x00, 0x00, 0x00}
    write32(kbase, aio_off + 0xa2, 0xc0bf8d49);
    write16(kbase, aio_off + 0xa6, 0x0000);
    write8(kbase, aio_off + 0xa8, 0x00);

    // offset = 0xae
    // patch = {0x49, 0x8d, 0xbf, 0xe0, 0x00, 0x00, 0x00}
    write32(kbase, aio_off + 0xae, 0xe0bf8d49);
    write16(kbase, aio_off + 0xb2, 0x0000);
    write8(kbase, aio_off + 0xb4, 0x00);

    // offset = 0xc1
    // patch = {0x49, 0x8d, 0xbf, 0x00, 0x01, 0x00, 0x00}
    write32(kbase, aio_off + 0xc1, 0x00bf8d49);
    write16(kbase, aio_off + 0xc5, 0x0001);
    write8(kbase, aio_off + 0xc7, 0x00);

    // offset = 0xcd
    // patch = {0x49, 0x8d, 0xbf, 0x20, 0x01, 0x00, 0x00}
    write32(kbase, aio_off + 0xcd, 0x20bf8d49);
    write16(kbase, aio_off + 0xd1, 0x0001);
    write8(kbase, aio_off + 0xd3, 0x00);

    // offset = 0xde
    // patch = {0x49, 0x8b, 0xff}
    write16(kbase, aio_off + 0xde, 0x8b49);
    write8(kbase, aio_off + 0xe0, 0xff);

    enable_cr0_wp();
}

void do_patch(void *kbase) {
    disable_cr0_wp();

    // ChendoChap's patches from pOOBs4 ///////////////////////////////////////

    // Initial patches
    write16(kbase, 0x626874, 0x00eb); // veriPatch
    write8(kbase, 0xacd, 0xeb); // bcopy
    write8(kbase, 0x2713fd, 0xeb); // bzero
    write8(kbase, 0x271441, 0xeb); // pagezero
    write8(kbase, 0x2714bd, 0xeb); // memcpy
    write8(kbase, 0x271501, 0xeb); // pagecopy
    write8(kbase, 0x2716ad, 0xeb); // copyin
    write8(kbase, 0x271b5d, 0xeb); // copyinstr
    write8(kbase, 0x271c2d, 0xeb); // copystr

    // stop sysVeri from causing a delayed panic on suspend
    write16(kbase, 0x62715f, 0x00eb);

    // patch amd64_syscall() to allow calling syscalls everywhere
    // struct syscall_args sa; // initialized already
    // u64 code = get_u64_at_user_address(td->tf_frame-tf_rip);
    // int is_invalid_syscall = 0
    //
    // // check the calling code if it looks like one of the syscall stubs at a
    // // libkernel library and check if the syscall number correponds to the
    // // proper stub
    // if ((code & 0xff0000000000ffff) != 0x890000000000c0c7
    //     || sa.code != (u32)(code >> 0x10)
    // ) {
    //     // patch this to " = 0" instead
    //     is_invalid_syscall = -1;
    // }
    write32(kbase, 0x490, 0);
    // these code corresponds to the check that ensures that the caller's
    // instruction pointer is inside the libkernel library's memory range
    //
    // // patch the check to always go to the "goto do_syscall;" line
    // void *code = td->td_frame->tf_rip;
    // if (libkernel->start <= code && code < libkernel->end
    //     && is_invalid_syscall == 0
    // ) {
    //     goto do_syscall;
    // }
    //
    // do_syscall:
    //     ...
    //     lea     rsi, [rbp - 0x78]
    //     mov     rdi, rbx
    //     mov     rax, qword [rbp - 0x80]
    //     call    qword [rax + 8] ; error = (sa->callp->sy_call)(td, sa->args)
    //
    // sy_call() is the function that will execute the requested syscall.
    write8(kbase, 0x4c2, 0xeb);
    write16(kbase, 0x4b9, 0x00eb);
    write16(kbase, 0x4b5, 0x00eb);

    // patch sys_setuid() to allow freely changing the effective user ID
    // ; PRIV_CRED_SETUID = 50
    // call priv_check_cred(oldcred, PRIV_CRED_SETUID, 0)
    // test eax, eax
    // je ... ; patch je to jmp
    write8(kbase, 0x1a06, 0xeb);

    // patch vm_map_protect() (called by sys_mprotect()) to allow rwx mappings
    //
    // this check is skipped after the patch
    //
    // if ((new_prot & current->max_protection) != new_prot) {
    //     vm_map_unlock(map);
    //     return (KERN_PROTECTION_FAILURE);
    // }
    write16(kbase, 0x80b8b, 0x04eb);

    // TODO: Description of this patch. patch sys_dynlib_load_prx()
    write16(kbase, 0x23aec4, 0xe990);

    // patch sys_dynlib_dlsym() to allow dynamic symbol resolution everywhere
    // call    ...
    // mov     r14, qword [rbp - 0xad0]
    // cmp     eax, 0x4000000
    // jb      ... ; patch jb to jmp
    write8(kbase, 0x23b67f, 0xeb);
    // patch called function to always return 0
    //
    // sys_dynlib_dlsym:
    //     ...
    //     mov     edi, 0x10 ; 16
    //     call    patched_function ; kernel_base + 0x951c0
    //     test    eax, eax
    //     je      ...
    //     mov     rax, qword [rbp - 0xad8]
    //     ...
    // patched_function: ; patch to "xor eax, eax; ret"
    //     push    rbp
    //     mov     rbp, rsp
    //     ...
    write32(kbase, 0x221b40, 0xc3c03148);

    // patch sys_mmap() to allow rwx mappings
    // patch maximum cpu mem protection: 0x33 -> 0x37
    // the ps4 added custom protections for their gpu memory accesses
    // GPU X: 0x8 R: 0x10 W: 0x20
    // that's why you see other bits set
    // ref: https://cturt.github.io/ps4-2.html
    write8(kbase, 0x16632a, 0x37);
    write8(kbase, 0x16632d, 0x37);

    // overwrite the entry of syscall 11 (unimplemented) in sysent
    //
    // struct args {
    //     u64 rdi;
    //     u64 rsi;
    //     u64 rdx;
    //     u64 rcx;
    //     u64 r8;
    //     u64 r9;
    // };
    //
    // int sys_kexec(struct thread td, struct args *uap) {
    //     asm("jmp qword ptr [rsi]");
    // }
    // .sy_narg = 2
    write32(kbase, 0x1100520, 2);
    // .sy_call = gadgets['jmp qword ptr [rsi]']
    write64(kbase, 0x1100520 + 8, kbase + 0x4c7ad);
    // .sy_thrcnt = SY_THR_STATIC
    write32(kbase, 0x1100520 + 0x2c, 1);

    enable_cr0_wp();
}
