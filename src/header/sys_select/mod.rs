//! sys/select.h implementation

use platform::types::*;
use platform::{Pal, Sys};

// fd_set is defined in C because cbindgen is incompatible with mem::size_of booo

#[no_mangle]
pub extern "C" fn select(
    nfds: c_int,
    readfds: *mut fd_set,
    writefds: *mut fd_set,
    exceptfds: *mut fd_set,
    timeout: *mut timeval,
) -> c_int {
    Sys::select(nfds, readfds, writefds, exceptfds, timeout)
}
