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

void do_patch(void);
void restore(struct kexec_args *uap);

__attribute__((section (".text.start")))
int kpatch(void *td, struct kexec_args *uap) {
    do_patch();
    //restore(uap); Disable to backtrace
    return 0;
}

void restore(struct kexec_args *uap) {
    u8 *pipe = uap->arg1;
    u8 *pipebuf = uap->arg2;
    for (size_t i = 0; i < 0x18; i++) {
        pipe[i] = pipebuf[i];
    }
    u64 *pktinfo_field = uap->arg3;
    *pktinfo_field = 0;
    u64 *pktinfo_field2 = uap->arg4;
    *pktinfo_field2 = 0;
}

void do_patch(void) {
    // offset to fast_syscall()
    const size_t off_fast_syscall = 0x1C0;
    void * const kbase = (void *)rdmsr(0xC0000082) - off_fast_syscall;

    disable_cr0_wp();
    //ChendoChap Patches For 900
    const size_t KERNEL_enable_syscalls_1 = 0x490;
    const size_t KERNEL_enable_syscalls_2 = 0x4B5;
    const size_t KERNEL_enable_syscalls_3 = 0x4B9;
    const size_t KERNEL_enable_syscalls_4 = 0x4C2;
    const size_t KERNEL_mprotect = 0x80B8D;
    const size_t KERNEL_prx = 0x23AEC4;
    const size_t KERNEL_mmap_1 = 0x16632A;
    const size_t KERNEL_mmap_2 = 0x16632D;
    const size_t KERNEL_dlsym_1 = 0x23B67F;
    const size_t KERNEL_dlsym_2 = 0x221b40;
    const size_t KERNEL_setuid = 0x1A06;
    const size_t KERNEL_bzero = 0x2713FD;
    const size_t KERNEL_pagezero = 0x271441;
    const size_t KERNEL_memcpy = 0x2714BD;
    const size_t KERNEL_pagecopy = 0x271501;
    const size_t KERNEL_copyin = 0x2716AD;
    const size_t KERNEL_copyinstr = 0x271B5D;
    const size_t KERNEL_copystr = 0x271C2D;
    const size_t KERNEL_veriPatch = 0x626874;
    const size_t KERNEL_setcr0_patch = 0x3ade3B;
    write32(kbase, KERNEL_enable_syscalls_1, 0);
    write16(kbase, KERNEL_enable_syscalls_2, 0x9090);
    write16(kbase, KERNEL_enable_syscalls_3, 0x9090);
    write8(kbase, KERNEL_enable_syscalls_4, 0xEB);  
    write8(kbase, KERNEL_mmap_1, 0x37);
    write8(kbase, KERNEL_mmap_2, 0x37);
    write32(kbase, KERNEL_mprotect, 0);      
    write8(kbase, KERNEL_dlsym_1, 0xEB);
    write32(kbase, KERNEL_dlsym_2, 0xC3C03148);
    write8(kbase, KERNEL_setuid, 0xEB);
    write16(kbase, KERNEL_prx, 0xE990);
    write8(kbase, KERNEL_bzero, 0xEB);
    write8(kbase, KERNEL_pagezero, 0xEB);
    write8(kbase, KERNEL_memcpy, 0xEB);
    write8(kbase, KERNEL_pagecopy, 0xEB);
    write8(kbase, KERNEL_copyin, 0xEB);
    write8(kbase, KERNEL_copyinstr, 0xEB);
    write8(kbase, KERNEL_copystr, 0xEB);
    write16(kbase, KERNEL_veriPatch, 0x9090);
    write32(kbase, KERNEL_setcr0_patch, 0xC3C7220F);        
    const size_t offset_sysent_11 = 0x1100520;
    write32(kbase, offset_sysent_11, 2);
    write64(kbase, offset_sysent_11 + 8, kbase + 0x4c7ad);
    write32(kbase, offset_sysent_11 + 0x2c, 1);  
   
    enable_cr0_wp();
}