/* Copyright (C) 2023-2025 anonymous

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

import { Int, lohi_from_one } from './int64.mjs';
import { get_view_vector } from './memtools.mjs';
import { Addr } from './mem.mjs';
import * as config from '../config.mjs';

// put the sycall names that you want to use here
export const syscall_map = new Map(Object.entries({
    'read' : 3,
    'write' : 4,
    'open' : 5,
    'close' : 6,
    'getpid' : 20,
    'setuid' : 23,
    'getuid' : 24,
    'accept' : 30,
    'pipe' : 42,
    'ioctl' : 54,
    'munmap' : 73,
    'mprotect' : 74,
    'fcntl' : 92,
    'socket' : 97,
    'connect' : 98,
    'bind' : 104,
    'setsockopt' : 105,
    'listen' : 106,
    'getsockopt' : 118,
    'fchmod' : 124,
    'socketpair' : 135,
    'fstat' : 189,
    'getdirentries' : 196,
    '__sysctl' : 202,
    'mlock' : 203,
    'clock_gettime' : 232,
    'nanosleep' : 240,
    'sched_yield' : 331,
    'kqueue' : 362,
    'kevent' : 363,
    'rtprio_thread' : 466,
    'mmap' : 477,
    'ftruncate' : 480,
    'shm_open' : 482,
    'cpuset_getaffinity' : 487,
    'cpuset_setaffinity' : 488,
    'jitshm_create' : 533,
    'jitshm_alias' : 534,
    'evf_create' : 538,
    'evf_delete' : 539,
    'evf_set' : 544,
    'evf_clear' : 545,
    'set_vm_container' : 559,
    'dmem_container' : 586,
    'dynlib_dlsym' : 591,
    'dynlib_get_list' : 592,
    'dynlib_get_info' : 593,
    'dynlib_load_prx' : 594,
    'randomized_path' : 602,
    'budget_get_ptype' : 610,
    'thr_suspend_ucontext' : 632,
    'thr_resume_ucontext' : 633,
    'blockpool_open' : 653,
    'blockpool_map' : 654,
    'blockpool_unmap' : 655,
    'blockpool_batch' : 657,
    // syscall 661 is unimplemented so free for use. a kernel exploit will
    // install "kexec" here
    'aio_submit' : 661,
    'kexec' : 661,
    'aio_multi_delete' : 662,
    'aio_multi_wait' : 663,
    'aio_multi_poll' : 664,
    'aio_multi_cancel' : 666,
    'aio_submit_cmd' : 669,
    'blockpool_move' : 673,
}));

const argument_pops = [
    'pop rdi; ret',
    'pop rsi; ret',
    'pop rdx; ret',
    'pop rcx; ret',
    'pop r8; ret',
    'pop r9; ret',
];

// implementations are expected to have these gadgets:
// * libSceLibcInternal:
//   * __errno - FreeBSD's function to get the location of errno
//   * setcontext - what we call Sony's own version of _Ux86_64_setcontext
//   * getcontext - what we call Sony's own version of _Ux86_64_getcontext
// * anywhere:
//   * the gadgets at argument_pops
//   * ret
//
// setcontext/getcontext naming came from this project:
// https://github.com/libunwind/libunwind
//
// setcontext(context *ctx):
//     mov     rax, qword [rdi + 0x38]
//     sub     rax, 0x10 ; 16
//     mov     qword [rdi + 0x38], rax
//     mov     rbx, qword [rdi + 0x20]
//     mov     qword [rax], rbx
//     mov     rbx, qword [rdi + 0x80]
//     mov     qword [rax + 8], rbx
//     mov     rax, qword [rdi]
//     mov     rbx, qword [rdi + 8]
//     mov     rcx, qword [rdi + 0x10]
//     mov     rdx, qword [rdi + 0x18]
//     mov     rsi, qword [rdi + 0x28]
//     mov     rbp, qword [rdi + 0x30]
//     mov     r8, qword [rdi + 0x40]
//     mov     r9, qword [rdi + 0x48]
//     mov     r10, qword [rdi + 0x50]
//     mov     r11, qword [rdi + 0x58]
//     mov     r12, qword [rdi + 0x60]
//     mov     r13, qword [rdi + 0x68]
//     mov     r14, qword [rdi + 0x70]
//     mov     r15, qword [rdi + 0x78]
//     cmp     qword [rdi + 0xb0], 0x20001
//     jne     done
//     cmp     qword [rdi + 0xb8], 0x10002
//     jne     done
//     fxrstor [rdi + 0xc0]
// done:
//     mov     rsp, qword [rdi + 0x38]
//     pop     rdi
//     ret
//
//  getcontext(context *ctx):
//     mov     qword [rdi], rax
//     mov     qword [rdi + 8], rbx
//     mov     qword [rdi + 0x10], rcx
//     mov     qword [rdi + 0x18], rdx
//     mov     qword [rdi + 0x20], rdi
//     mov     qword [rdi + 0x28], rsi
//     mov     qword [rdi + 0x30], rbp
//     mov     qword [rdi + 0x38], rsp
//     add     qword [rdi + 0x38], 8
//     mov     qword [rdi + 0x40], r8
//     mov     qword [rdi + 0x48], r9
//     mov     qword [rdi + 0x50], r10
//     mov     qword [rdi + 0x58], r11
//     mov     qword [rdi + 0x60], r12
//     mov     qword [rdi + 0x68], r13
//     mov     qword [rdi + 0x70], r14
//     mov     qword [rdi + 0x78], r15
//     mov     rsi, qword [rsp]
//     mov     qword [rdi + 0x80], rsi
//     fxsave  [rdi + 0xc0]
//     mov     qword [rdi + 0xb0], 0x20001
//     mov     qword [rdi + 0xb8], 0x10002
//     xor     eax, eax
//     ret

// ROP chain manager base class
//
// Args:
//   stack_size: the size of the stack
//   upper_pad: the amount of extra space above stack
export class ChainBase {
    constructor(stack_size=0x1000, upper_pad=0x10000) {
        this._is_dirty = false;
        this.position = 0;

        const return_value = new Uint32Array(4);
        this._return_value = return_value;
        this.retval_addr = get_view_vector(return_value);

        const errno = new Uint32Array(1);
        this._errno = errno;
        this.errno_addr = get_view_vector(errno);

        const full_stack_size = upper_pad + stack_size;
        const stack_buffer = new ArrayBuffer(full_stack_size);
        const stack = new DataView(stack_buffer, upper_pad);
        this.stack = stack;
        this.stack_addr = get_view_vector(stack);
        this.stack_size = stack_size;
        this.full_stack_size = full_stack_size;
    }

    // use this if you want to write a new ROP chain but don't want to allocate
    // a new instance
    empty() {
        this.position = 0;
    }

    // flag indicating whether .run() was ever called with this chain
    get is_dirty() {
        return this._is_dirty;
    }

    clean() {
        this._is_dirty = false;
    }

    dirty() {
        this._is_dirty = true;
    }

    check_allow_run() {
        if (this.position === 0) {
            throw Error('chain is empty');
        }
        if (this.is_dirty) {
            throw Error('chain already ran, clean it first');
        }
    }

    reset() {
        this.empty();
        this.clean();
    }

    get retval_int() {
        return this._return_value[0] | 0;
    }

    get retval() {
        return new Int(this._return_value[0], this._return_value[1]);
    }

    // return value as a pointer
    get retval_ptr() {
        return new Addr(this._return_value[0], this._return_value[1]);
    }

    set retval(value) {
        const values = lohi_from_one(value);
        const retval = this._return_value;
        retval[0] = values[0];
        retval[1] = values[1];
    }

    get retval_all() {
        const retval = this._return_value;
        return [new Int(retval[0], retval[1]), new Int(retval[2], retval[3])];
    }

    set retval_all(values) {
        const [a, b] = [lohi_from_one(values[0]), lohi_from_one(values[1])];
        const retval = this._return_value;
        retval[0] = a[0];
        retval[1] = a[1];
        retval[2] = b[0];
        retval[3] = b[1];
    }

    get errno() {
        return this._errno[0];
    }

    set errno(value) {
        this._errno[0] = value;
    }

    push_value(value) {
        const position = this.position;
        if (position >= this.stack_size) {
            throw Error(`no more space on the stack, pushed value: ${value}`);
        }

        const values = lohi_from_one(value);
        const stack = this.stack;
        stack.setUint32(position, values[0], true);
        stack.setUint32(position + 4, values[1], true);

        this.position += 8;
    }

    get_gadget(insn_str) {
        const addr = this.gadgets.get(insn_str);
        if (addr === undefined) {
            throw Error(`gadget not found: ${insn_str}`);
        }

        return addr;
    }

    push_gadget(insn_str) {
        this.push_value(this.get_gadget(insn_str));
    }

    push_call(func_addr, ...args) {
        if (args.length > 6) {
            throw TypeError(
                'push_call() does not support functions that have more than 6'
                + ' arguments');
        }

        for (let i = 0; i < args.length; i++) {
            this.push_gadget(argument_pops[i]);
            this.push_value(args[i]);
        }

        // The address of our buffer seems to be always aligned to 8 bytes.
        // SysV calling convention requires the stack is aligned to 16 bytes on
        // function entry, so push an additional 8 bytes to pad the stack. We
        // pushed a "ret" gadget for a noop.
        if ((this.position & (0x10 - 1)) !== 0) {
            this.push_gadget('ret');
        }

        if (typeof func_addr === 'string') {
            this.push_gadget(func_addr);
        } else {
            this.push_value(func_addr);
        }
    }

    push_syscall(syscall_name, ...args) {
        if (typeof syscall_name !== 'string') {
            throw TypeError(`syscall_name not a string: ${syscall_name}`);
        }

        const sysno = syscall_map.get(syscall_name);
        if (sysno === undefined) {
            throw Error(`syscall_name not found: ${syscall_name}`);
        }

        const syscall_addr = this.syscall_array[sysno];
        if (syscall_addr === undefined) {
            throw Error(`syscall number not in syscall_array: ${sysno}`);
        }

        this.push_call(syscall_addr, ...args);
    }

    // Sets needed class properties
    //
    // Args:
    //   gadgets:
    //     A Map-like object mapping instruction strings (e.g. "pop rax; ret")
    //     to their addresses in memory.
    //   syscall_array:
    //     An array whose indices correspond to syscall numbers. Maps syscall
    //     numbers to their addresses in memory. Defaults to an empty Array.
    static init_class(gadgets, syscall_array=[]) {
        this.prototype.gadgets = gadgets;
        this.prototype.syscall_array = syscall_array;
    }

    // START: implementation-dependent parts
    //
    // the user doesn't need to implement all of these. just the ones they need

    // Firmware specific method to launch a ROP chain
    //
    // Proper implementations will check if .position is nonzero before
    // running. Implementations can optionally check .is_dirty to enforce
    // single-run gadget sequences
    run() {
        throw Error('not implemented');
    }

    // anything you need to do before the ROP chain jumps back to JavaScript
    push_end() {
        throw Error('not implemented');
    }

    push_get_errno() {
        throw Error('not implemented');
    }

    push_clear_errno() {
        throw Error('not implemented'); 
    }

    // get the rax register
    push_get_retval() {
        throw Error('not implemented');
    }

    // get the rax and rdx registers
    push_get_retval_all() {
        throw Error('not implemented');
    }

    // END: implementation-dependent parts

    // note that later firmwares (starting around > 5.00?), the browser doesn't
    // have a JIT compiler. we programmed in a way that tries to make the
    // resulting bytecode be optimal
    //
    // we intentionally have an incomplete set (there's no function to get a
    // full 128-bit result). we only implemented what we think are the common
    // cases. the user will have to implement those other functions if they
    // need it

    do_call(...args) {
        if (this.position) {
            throw Error('chain not empty');
        }
        try {
            this.push_call(...args);
            this.push_get_retval();
            this.push_get_errno();
            this.push_end();
            this.run();
        } finally {
            this.reset();
        }
    }

    call_void(...args) {
        this.do_call(...args);
    }

    call_int(...args) {
        this.do_call(...args);
        // x | 0 will always be a signed integer
        return this._return_value[0] | 0;
    }

    call(...args) {
        this.do_call(...args);
        const retval = this._return_value;
        return new Int(retval[0], retval[1]);
    }

    do_syscall(...args) {
        if (this.position) {
            throw Error('chain not empty');
        }
        try {
            this.push_syscall(...args);
            this.push_get_retval();
            this.push_get_errno();
            this.push_end();
            this.run();
        } finally {
            this.reset();
        }
    }

    syscall_void(...args) {
        this.do_syscall(...args);
    }

    syscall_int(...args) {
        this.do_syscall(...args);
        // x | 0 will always be a signed integer
        return this._return_value[0] | 0;
    }

    syscall(...args) {
        this.do_syscall(...args);
        const retval = this._return_value;
        return new Int(retval[0], retval[1]);
    }

    syscall_ptr(...args) {
        this.do_syscall(...args);
        const retval = this._return_value;
        return new Addr(retval[0], retval[1]);
    }

    // syscall variants that throw an error on errno

    do_syscall_clear_errno(...args) {
        if (this.position) {
            throw Error('chain not empty');
        }
        try {
            this.push_clear_errno();
            this.push_syscall(...args);
            this.push_get_retval();
            this.push_get_errno();
            this.push_end();
            this.run();
        } finally {
            this.reset();
        }
    }

    sysi(...args) {
        const errno = this._errno;
        this.do_syscall_clear_errno(...args);

        const err = errno[0];
        if (err !== 0) {
            throw Error(`syscall(${args[0]}) errno: ${err}`);
        }

        // x | 0 will always be a signed integer
        return this._return_value[0] | 0;
    }

    sys(...args) {
        const errno = this._errno;
        this.do_syscall_clear_errno(...args);

        const err = errno[0];
        if (err !== 0) {
            throw Error(`syscall(${args[0]}) errno: ${err}`);
        }

        const retval = this._return_value;
        return new Int(retval[0], retval[1]);
    }

    sysp(...args) {
        const errno = this._errno;
        this.do_syscall_clear_errno(...args);

        const err = errno[0];
        if (err !== 0) {
            throw Error(`syscall(${args[0]}) errno: ${err}`);
        }

        const retval = this._return_value;
        return new Addr(retval[0], retval[1]);
    }

}

export function get_gadget(map, insn_str) {
    const addr = map.get(insn_str);
    if (addr === undefined) {
        throw Error(`gadget not found: ${insn_str}`);
    }

    return addr;
}

function load_fw_specific(version) {
    if (version & 0x10000) {
        throw RangeError('ps5 not supported yet');
    }

    const value = version & 0xffff;
    // we don't want to bother with very old firmwares that don't support
    // ECMAScript 2015. 6.xx WebKit poisons the pointer fields of some types
    // which can be annoying to deal with
    if (value < 0x700) {
        throw RangeError("PS4 firmwares < 7.00 isn't supported");
    }

    if (0x800 <= value && value <= 0x900) {
        return import('../rop/900.mjs');
    }

    throw RangeError('firmware not supported');
}

export let gadgets = null;
export let libwebkit_base = null;
export let libkernel_base = null;
export let libc_base = null;
export let init_gadget_map = null;
export let Chain = null;

export async function init() {
    const module = await load_fw_specific(config.target);
    Chain = module.Chain;
    module.init(Chain);
    ({
        gadgets,
        libwebkit_base,
        libkernel_base,
        libc_base,
        init_gadget_map,
    } = module);
}
