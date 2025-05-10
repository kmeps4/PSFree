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

// We can't just open a console on the ps4 browser, make sure the errors thrown
// by our program are alerted.

// We don't use a custom logging function to avoid a dependency on a logging
// module since we want this file to stand alone. We don't want to copy the
// log function here either for the sake avoiding dependencies since using
// alert() is good enough.

// We log the line and column numbers as well since some exceptions (like
// SyntaxError) do not show it in the stack trace.

addEventListener('unhandledrejection', event => {
    const reason = event.reason;
    alert(
        'Unhandled rejection\n'
        + `${reason}\n`
        + `${reason.sourceURL}:${reason.line}:${reason.column}\n`
        + `${reason.stack}`
    );
});

addEventListener('error', event => {
    const reason = event.error;
    alert(
        'Unhandled error\n'
        + `${reason}\n`
        + `${reason.sourceURL}:${reason.line}:${reason.column}\n`
        + `${reason.stack}`
    );
    return true;
});

// we have to dynamically import the program if we want to catch its syntax
// errors
import('./psfree.mjs');
