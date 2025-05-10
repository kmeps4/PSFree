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

import { Int } from './int64.mjs';

export class DieError extends Error {
    constructor(...args) {
        super(...args);
        this.name = this.constructor.name;
    }
}

export function die(msg='') {
    throw new DieError(msg);
}

const console = document.getElementById('console');
export function log(msg='') {
    console.append(msg + '\n');
}

export function clear_log() {
    console.innerHTML = null;
}

// alignment must be 32 bits and is a power of 2
export function align(a, alignment) {
    if (!(a instanceof Int)) {
        a = new Int(a);
    }
    const mask = -alignment & 0xffffffff;
    let type = a.constructor;
    let low = a.lo & mask;
    return new type(low, a.hi);
}

export async function send(url, buffer, file_name, onload=() => {}) {
    const file = new File(
        [buffer],
        file_name,
        {type:'application/octet-stream'}
    );
    const form = new FormData();
    form.append('upload', file);

    log('send');
    const response = await fetch(url, {method: 'POST', body: form});

    if (!response.ok) {
        throw Error(`Network response was not OK, status: ${response.status}`);
    }
    onload();
}

// mostly used to yield to the GC. marking is concurrent but collection isn't
//
// yielding also lets the DOM update. which is useful since we use the DOM for
// logging and we loop when waiting for a collection to occur
export function sleep(ms=0) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function hex(number) {
    return '0x' + number.toString(16);
}

// no "0x" prefix
export function hex_np(number) {
    return number.toString(16);
}

// expects a byte array
export function hexdump(view) {
    const num_16 = view.length & ~15;
    const residue = view.length - num_16;
    const max_off_len = hex_np(((view.length + 7) & ~7) - 1).length;

    function chr(i) {
        if (0x20 <= i && i <= 0x7e) {
            return String.fromCodePoint(i);
        }
        return '.';
    }

    function to_hex(view, offset, length) {
        return (
            [...view.slice(offset, offset + length)]
            .map(e => hex_np(e).padStart(2, '0'))
            .join(' ')
        );
    }

    let bytes = [];
    for (let i = 0; i < num_16; i += 16) {
        const long1 = to_hex(view, i, 8);
        const long2 = to_hex(view, i + 8, 8);

        let print = '';
        for (let j = 0; j < 16; j++) {
            print += chr(view[j]);
        }

        bytes.push([`${long1}  ${long2}`, print]);
    }

    if (residue) {
        const small = residue <= 8;
        const long1_len = small ? residue : 8;

        let long1 = to_hex(view, num_16, long1_len);
        if (small) {
            for (let i = 0; i < 8 - residue; i++) {
                long1 += ' xx';
            }
        }

        const long2 = (() => {
            if (small) {
                return Array(8).fill('xx').join(' ');
            }

            let res = to_hex(view, num_16 + 8, residue - 8);
            for (let i = 0; i < 16 - residue; i++) {
                res += ' xx';
            }

            return res;
        })();

        let print = '';
        for (let i = 0; i < residue; i++) {
            print += chr(view[num_16 + i]);
        }
        for (let i = 0; i < 16 - residue; i++) {
            print += ' ';
        }

        bytes.push([`${long1}  ${long2}`, print]);
    }

    for (const [pos, [val, print]] of bytes.entries()) {
        const off = hex_np(pos * 16).padStart(max_off_len, '0');
        log(`${off} | ${val} |${print}|`);
    }
}

// make a JavaScript string
export function jstr(buffer) {
    let res = '';
    for (const item of buffer) {
        if (item === 0) {
            break;
        }
        res += String.fromCodePoint(item);
    }
    // convert to primitive string
    return String(res);
}
