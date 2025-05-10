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

// webkitgtk 2.34.4 was used to develop the portable parts of the exploit
// before moving on to ps4 8.03
//
// webkitgtk 2.34.4 was built with cmake variable ENABLE_JIT=OFF, that variable
// can affect the size of SerializedScriptValue
//
// this target is no longer supported

// target firmware format used by PSFree
//
// 0xC_MM_mm
//
// * C console - PS4 (0) or PS5 (1) (1 bit)
// * MM major version - integer part of the firmware version (8 bits)
// * mm minor version - fractional part of the firmware version (8 bits)
//
// examples:
// * PS4 10.00 -> C = 0 MM = 10 mm = 0 -> 0x0_10_00
// * PS5 4.51 -> C = 1 MM = 4 mm = 51 -> 0x1_04_51

// check if value is in Binary Coded Decimal format
// assumes integer and is in the range [0, 0xffff]
function check_bcd(value) {
    for (let i = 0; i <= 12; i += 4) {
        const nibble = (value >>> i) & 0xf;

        if (nibble > 9) {
            return false;
        }
    }

    return true;
}

export function set_target(value) {
    if (!Number.isInteger(value)) {
        throw TypeError(`value not an integer: ${value}`);
    }

    if (value >= 0x20000 || value < 0) {
        throw RangeError(`value >= 0x20000 or value < 0: ${value}`);
    }

    const version = value & 0xffff;
    if (!check_bcd(version)) {
        throw RangeError(`value & 0xffff not in BCD format ${version}`);
    }

    target = value;
}

export let target = null;
set_target(0x900);
