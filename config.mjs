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

function DetectFirmwareVersion() { //function by kameleon :)

if (navigator.userAgent.includes('PlayStation 4')) {
    var UA = navigator.userAgent.substring(navigator.userAgent.indexOf('5.0 (') + 19, navigator.userAgent.indexOf(') Apple')).replace("PlayStation 4/","");
    if (UA == "6.00" || UA == "6.02" || UA == "6.10" || UA == "6.20") { 
        return ps4_6_00;
    } else if (UA == "6.50" || UA == "6.70" || UA == "6.71" || UA == "6.72") { 
	return  ps4_6_50;
    } else if (UA == "7.01" || UA == "7.02" || UA == "7.50" || UA == "7.51" || UA == "7.55" || UA == "8.00" || UA == "8.01" || UA == "8.03" || UA == "8.50" || UA == "8.51") { 
	return ps4_8_03;
    } else {
        var UA = navigator.userAgent.substring(navigator.userAgent.indexOf('5.0 (') + 18, navigator.userAgent.indexOf(') Apple')).replace("PlayStation 4/","");
        if (UA == "9.00" || UA == "9.03" || UA == "9.04" || UA == "9.50" ||  UA == "9.51" || UA == "9.60") {
	return  ps4_9_00;
        }
    }
} else if (navigator.userAgent.includes('PlayStation 5')) {
    var UA = navigator.userAgent.substring(navigator.userAgent.indexOf('5.0 (') + 32, navigator.userAgent.indexOf(') Apple')).replace("PlayStation 5/","");
    if (UA == "1.00" || UA == "1.01" || UA == "1.02" || UA == "1.05" || UA == "1.12" || UA == "1.14" || UA == "2.00" || UA == "2.10" || UA == "2.20" || UA == "2.25" || UA == "2.26" || UA == "2.30" || UA == "2.50" || UA == "2.70" || UA == "3.00" || UA == "3.10" || UA == "3.20" || UA == "3.21" || UA == "4.00" || UA == "4.02" || UA == "4.03" || UA == "4.50" || UA == "4.51" || UA == "5.00" || UA == "5.02" || UA == "5.10" || UA == "5.50")  { 
	return ps5_5_00;
    }
}
}

export let target = DetectFirmwareVersion();