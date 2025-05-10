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

// DataView's accessors are constant time and are faster when doing multi-byte
// accesses but the single-byte accessors are slightly slower compared to just
// indexing the Uint8Array
//
// to get the best of both worlds, BufferView uses a DataView for multi-byte
// accesses and a Uint8Array for single-byte
//
// instances of BufferView will their have m_mode set to WastefulTypedArray
// since we use the .buffer getter to create a DataView
export class BufferView extends Uint8Array {
    constructor(...args) {
        super(...args);
        this._dview = new DataView(this.buffer, this.byteOffset);
    }

    read16(offset) {
        return this._dview.getUint16(offset, true);
    }

    read32(offset) {
        return this._dview.getUint32(offset, true);
    }

    read64(offset) {
        return new Int(
            this._dview.getUint32(offset, true),
            this._dview.getUint32(offset + 4, true),
        );
    }

    write16(offset, value) {
        this._dview.setUint16(offset, value, true);
    }

    write32(offset, value) {
        this._dview.setUint32(offset, value, true);
    }

    write64(offset, value) {
        const values = lohi_from_one(value);
        this._dview.setUint32(offset, values[0], true);
        this._dview.setUint32(offset + 4, values[1], true);
    }
}

// WARNING: These functions are now deprecated. use BufferView instead.

// view.buffer is the underlying ArrayBuffer of a TypedArray, but since we will
// be corrupting the m_vector of our target views later, the ArrayBuffer's
// buffer will not correspond to our fake m_vector anyway.
//
// can't use:
//
// function read32(u8_view, offset) {
//     let res = new Uint32Array(u8_view.buffer, offset, 1);
//     return res[0];
// }
//
// to implement read32, we need to index the view instead:
//
// function read32(u8_view, offset) {
//     let res = 0;
//     for (let i = 0; i < 4; i++) {
//         res += u8_view[offset + i] << i*8;
//     }
//     // << returns a signed integer, >>> converts it to unsigned
//     return res >>> 0;
// }

// for reads less than 8 bytes
function read(u8_view, offset, size) {
    let res = 0;
    for (let i = 0; i < size; i++) {
        res += u8_view[offset + i] << i*8;
    }
    // << returns a signed integer, >>> converts it to unsigned
    return res >>> 0;
}

export function read16(u8_view, offset) {
    return read(u8_view, offset, 2);
}

export function read32(u8_view, offset) {
    return read(u8_view, offset, 4);
}

export function read64(u8_view, offset) {
    return new Int(read32(u8_view, offset), read32(u8_view, offset + 4));
}

// for writes less than 8 bytes
function write(u8_view, offset, value, size) {
    for (let i = 0; i < size; i++) {
        u8_view[offset + i]  = (value >>> i*8) & 0xff;
    }
}

export function write16(u8_view, offset, value) {
    write(u8_view, offset, value, 2);
}

export function write32(u8_view, offset, value) {
    write(u8_view, offset, value, 4);
}

export function write64(u8_view, offset, value) {
    if (!(value instanceof Int)) {
        throw TypeError('write64 value must be an Int');
    }

    let low = value.lo;
    let high = value.hi;

    for (let i = 0; i < 4; i++) {
        u8_view[offset + i]  = (low >>> i*8) & 0xff;
    }
    for (let i = 0; i < 4; i++) {
        u8_view[offset + 4 + i]  = (high >>> i*8) & 0xff;
    }
}
