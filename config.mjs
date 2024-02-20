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

// webkitgtk 2.34.4 was used to develop the portable parts of the exploit
// before moving on to ps4 8.03
//
// webkitgtk 2.34.4 was built with cmake variable ENABLE_JIT=OFF, that variable
// can affect the size of SerializedScriptValue
//
// this target is no longer supported
//
//export const gtk_2_34_4 = 0;

// the original target platform was 8.03, this version confirmed works on ps4
// 7.xx-8.xx
export const ps4_8_03 = 1;

// this version for 9.xx
export const ps4_9_00 = 2;

// version 9.xx is for ps5 1.xx-5.xx as well
export const ps5_5_00 = ps4_9_00;

// this version for 6.50-6.72
export const ps4_6_50 = 3;

// this version for 6.00-6.20
export const ps4_6_00 = 4;

export function set_target(value) {
    switch (value) {
        case ps4_8_03:
        case ps4_9_00:
        case ps4_6_00:
        case ps4_6_50: {
            break;
        }
        default: {
            throw RangeError('invalid target: ' + target);
        }
    }

    target = value;
}

if (navigator.userAgent.includes('PlayStation 4')) {
    var UA = navigator.userAgent.substring(navigator.userAgent.indexOf('5.0 (') + 19, navigator.userAgent.indexOf(') Apple')).replace("PlayStation 4/","");
    if (["6.00", "6.02", "6.10", "6.20"].includes(UA)) {
        return ps4_6_00;
    } else if (["6.50", "6.70", "6.71", "6.72"].includes(UA)) {
	return  ps4_6_50;
    } else if (["7.01", "7.02", "7.50", "7.51", "7.55", "8.00", "8.01", "8.03"].includes(UA)) {
	return ps4_8_03;
    } else {
        var UA = navigator.userAgent.substring(navigator.userAgent.indexOf('5.0 (') + 18, navigator.userAgent.indexOf(') Apple')).replace("PlayStation 4/","");
        if (["8.50", "8.51"].includes(UA)) {
	return ps4_8_03;
        } else {
        var UA = navigator.userAgent.substring(navigator.userAgent.indexOf('5.0 (') + 18, navigator.userAgent.indexOf(') Apple')).replace("PlayStation 4/","");
        if (["9.00", "9.03", "9.04", "9.50", "9.51", "9.60"].includes(UA)) {
	return  ps4_9_00;
        }
      }
    }
} else if (navigator.userAgent.includes('PlayStation 5')) {
    var UA = navigator.userAgent.substring(navigator.userAgent.indexOf('5.0 (') + 32, navigator.userAgent.indexOf(') Apple')).replace("PlayStation 5/","");
    if (["1.00", "1.01", "1.02", "1.05", "1.12", "1.14", "2.00", "2.10", "2.20", "2.25", "2.26", "2.30", "2.50", "2.70", "3.00", "3.10", "3.20", "3.21", "4.00", "4.02", "4.03", "4.50", "4.51", "5.00", "5.02", "5.10", "5.50"].includes(UA)) { 
	return ps5_5_00;
    }
  }
}

export let target = DetectFirmwareVersion();
