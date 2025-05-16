/* Copyright (C) 2025 anonymous

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
import { Addr } from './mem.mjs';
import { BufferView } from './rw.mjs';

import * as config from '../config.mjs';
import * as mt from './memtools.mjs';

// View constructors will always get the buffer property in order to make sure
// that the JSArrayBufferView is a WastefulTypedArray. m_vector may change if
// m_mode < WastefulTypedArray. This is to make caching the m_view field
// possible. Users don't have to worry if the m_view they got from addr() is
// possibly stale.
//
// see possiblySharedBuffer() from
// WebKit/Source/JavaScriptCore/runtime/JSArrayBufferViewInlines.h
// at PS4 8.03
//
// Subclasses of TypedArray are still implemented as a JSArrayBufferView, so
// get_view_vector() still works on them.

function ViewMixin(superclass) {
    const res = class extends superclass {
        constructor(...args) {
            super(...args);
            this.buffer;
        }

        get addr() {
            let res = this._addr_cache;
            if (res !== undefined) {
                return res;
            }
            res = mt.get_view_vector(this);
            this._addr_cache = res;
            return res;
        }

        get size() {
            return this.byteLength;
        }

        addr_at(index) {
            const size = this.BYTES_PER_ELEMENT;
            return this.addr.add(index * size);
        }

        sget(index) {
            return this[index] | 0;
        }
    };

    // workaround for known affected versions: ps4 [6.00, 10.00)
    //
    // see from() and of() from
    // WebKit/Source/JavaScriptCore/builtins/TypedArrayConstructor.js at PS4
    // 8.0x
    //
    // @getByIdDirectPrivate(this, "allocateTypedArray") will fail when "this"
    // isn't one of the built-in TypedArrays. this is a violation of the
    // ECMAScript spec at that time
    //
    // TODO assumes ps4, support ps5 as well
    // FIXME define the from/of workaround functions once
    if (0x600 <= config.target && config.target < 0x1000) {
        res.from = function from(...args) {
            const base = this.__proto__;
            return new this(base.from(...args).buffer);
        };

        res.of = function of(...args) {
            const base = this.__proto__;
            return new this(base.of(...args).buffer);
        };
    }

    return res;
}

export class View1 extends ViewMixin(Uint8Array) {}
export class View2 extends ViewMixin(Uint16Array) {}
export class View4 extends ViewMixin(Uint32Array) {}

export class Buffer extends BufferView {
    get addr() {
        let res = this._addr_cache;
        if (res !== undefined) {
            return res;
        }
        res = mt.get_view_vector(this);
        this._addr_cache = res;
        return res;
    }

    get size() {
        return this.byteLength;
    }

    addr_at(index) {
        return this.addr.add(index);
    }
}
// see from() and of() comment above
if (0x600 <= config.target && config.target < 0x1000) {
    Buffer.from = function from(...args) {
        const base = this.__proto__;
        return new this(base.from(...args).buffer);
    };
    Buffer.of = function of(...args) {
        const base = this.__proto__;
        return new this(base.of(...args).buffer);
    };
}

const VariableMixin = superclass => class extends superclass {
    constructor(value=0) {
        // unlike the View classes, we don't allow number coercion. we
        // explicitly allow floats unlike Int
        if (typeof value !== 'number') {
            throw TypeError('value not a number');
        }
        super([value]);
    }

    addr_at(...args) {
        throw TypeError('unimplemented method');
    }

    [Symbol.toPrimitive](hint) {
        return this[0];
    }

    toString(...args) {
        return this[0].toString(...args);
    }
};

export class Byte extends VariableMixin(View1) {}
export class Short extends VariableMixin(View2) {}
// Int was already taken by int64.mjs
export class Word extends VariableMixin(View4) {}

export class LongArray {
    constructor(length) {
        this.buffer = new DataView(new ArrayBuffer(length * 8));
    }

    get addr() {
        return mt.get_view_vector(this.buffer);
    }

    addr_at(index) {
        return this.addr.add(index * 8);
    }

    get length() {
        return this.buffer.length / 8;
    }

    get size() {
        return this.buffer.byteLength;
    }

    get byteLength() {
        return this.size;
    }

    get(index) {
        const buffer = this.buffer;
        const base = index * 8;
        return new Int(
            buffer.getUint32(base, true),
            buffer.getUint32(base + 4, true),
        );
    }

    set(index, value) {
        const buffer = this.buffer;
        const base = index * 8;
        const values = lohi_from_one(value);

        buffer.setUint32(base, values[0], true);
        buffer.setUint32(base + 4, values[1], true);
    }
}

// mutable Int (we are explicitly using Int's private fields)
const Word64Mixin = superclass => class extends superclass {
    constructor(...args) {
        if (!args.length) {
            return super(0);
        }
        super(...args);
    }

    get addr() {
        // assume this is safe to cache
        return mt.get_view_vector(this._u32);
    }

    get length() {
        return 1;
    }

    get size() {
        return 8;
    }

    get byteLength() {
        return 8;
    }

    // no setters for top and bot since low/high can accept negative integers

    get lo() {
        return super.lo;
    }

    set lo(value) {
        this._u32[0] = value;
    }

    get hi() {
        return super.hi;
    }

    set hi(value) {
        this._u32[1] = value;
    }

    set(value) {
        const buffer = this._u32;
        const values = lohi_from_one(value);

        buffer[0] = values[0];
        buffer[1] = values[1];
    }
};

export class Long extends Word64Mixin(Int) {
    as_addr() {
        return new Addr(this);
    }
}
export class Pointer extends Word64Mixin(Addr) {}
