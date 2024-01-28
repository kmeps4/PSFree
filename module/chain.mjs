/* Copyright (C) 2023 anonymous

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

import { Int } from './int64.mjs';
import { get_view_vector } from './memtools.mjs';
import { Addr, mem } from './mem.mjs';

import {
    read64,
    write64,
} from './rw.mjs';

import * as o from './offset.mjs';

// put the sycall names that you want to use here
export const syscall_map = new Map(Object.entries({
    'close': 6,
    'setuid' : 23,
    'getuid' : 24,
    'mprotect': 74,
    'socket' : 97,
    'fchmod' : 124,
    'mlock' : 203,
    'kqueue' : 362,
    'kevent' : 363,
    'mmap' : 477,
    // for JIT shared memory
    'jitshm_create' : 533,
    'jitshm_alias' : 534,
}));

// Extra space to allow a ROP chain to push temporary values. It must pop all
// of it before reaching a "ret" instruction, else the instruction will pop one
// of the temporaries as its return address.
//
// Also space for additional frames when we call a function since we do not
// pivot the call to another stack (the called function's stack pointer is
// pointing to our ROP stack as well).
const upper_pad = 0x10000;
// maximum size of the ROP stack
const stack_size = 0x10000;
const total_size = upper_pad + stack_size;

const argument_pops = [
    'pop rdi; ret',
    'pop rsi; ret',
    'pop rdx; ret',
    'pop rcx; ret',
    'pop r8; ret',
    'pop r9; ret',
];

export class ChainBase {
    constructor() {
        this.is_stale = false;
        this.position = 0;
        this._return_value = new Uint8Array(8);
        this.retval_addr = get_view_vector(this._return_value);

        const stack_buffer = new ArrayBuffer(total_size);
        this.stack_buffer = stack_buffer;
        this.stack = new Uint8Array(stack_buffer, upper_pad, stack_size);
        this.stack_addr = get_view_vector(this.stack);
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

    clean() {
        this.position = 0;
        this.is_stale = false;
    }

    // this will raise an error if the value is not an Int
    push_value(value) {
        if (this.position >= stack_size) {
            throw Error(`no more space on the stack, pushed value: ${value}`);
        }
        write64(this.stack, this.position, value);
        this.position += 8;
    }

    // converts value to Int first
    push_constant(value) {
        this.push_value(new Int(value));
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
                'call() does not support functions that have more than 6'
                + ' arguments'
            );
        }

        for (let i = 0; i < args.length; i++) {
            this.push_gadget(argument_pops[i]);
            this.push_constant(args[i]);
        }

        // The address of our buffer seems to be always aligned to 8 bytes.
        // SysV calling convention requires the stack is aligned to 16 bytes on
        // function entry, so push an additional 8 bytes to pad the stack. We
        // pushed a "ret" gadget for a noop.
        if ((this.position & (0x10 - 1)) !== 0) {
            this.push_gadget('ret');
        }

        this.push_value(func_addr);
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

    // ROP chain to retrieve rax
    push_get_retval() {
        throw Error('push_get_retval() not implemented');
    }

    // Firmware specific method to launch a ROP chain
    //
    // Implementations must call check_stale() and check_is_empty() before
    // trying to launch the chain.
    run() {
        throw Error('run() not implemented');
    }

    get return_value() {
        return read64(this._return_value, 0);
    }

    // Sets needed class properties
    //
    // Args:
    //   gadgets:
    //     A Map-like object mapping instruction strings (e.g "pop rax; ret")
    //     to their addresses in memory.
    //   syscall_array:
    //     An array whose indices correspond to syscall numbers. Maps syscall
    //     numbers to their addresses in memory. Defaults to an empty Array.
    //
    // Raises:
    //   Error:
    //     For missing bare minimum gadgets
    static init_class(gadgets, syscall_array=[]) {
        for (const insn of argument_pops) {
            if (!gadgets.has(insn)) {
                throw Error(`gadget map must contain this gadget: ${insn}`);
            }
        }
        this.prototype.gadgets = gadgets;
        this.prototype.syscall_array = syscall_array;
    }
}
