//! termios implementation, following http://pubs.opengroup.org/onlinepubs/7908799/xsh/termios.h.html

use platform;
use platform::types::*;
use platform::{Pal, Sys};

pub type cc_t = u8;
pub type speed_t = u32;
pub type tcflag_t = u32;

pub const NCCS: usize = 32;

#[repr(C)]
pub struct termios {
    c_iflag: tcflag_t,
    c_oflag: tcflag_t,
    c_cflag: tcflag_t,
    c_lflag: tcflag_t,
    c_line: cc_t,
    c_cc: [cc_t; NCCS],
    __c_ispeed: speed_t,
    __c_ospeed: speed_t,
}

#[no_mangle]
pub extern "C" fn tcgetattr(fd: c_int, out: *mut termios) -> c_int {
    Sys::tcgetattr(fd, out as *mut platform::types::termios)
}

#[no_mangle]
pub extern "C" fn tcsetattr(fd: c_int, act: c_int, value: *mut termios) -> c_int {
    Sys::tcsetattr(fd, act, value as *mut platform::types::termios)
}

pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSWTC: usize = 7;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const VEOL2: usize = 16;

pub const IGNBRK: usize = 0o000001;
pub const BRKINT: usize = 0o000002;
pub const IGNPAR: usize = 0o000004;
pub const PARMRK: usize = 0o000010;
pub const INPCK: usize = 0o000020;
pub const ISTRIP: usize = 0o000040;
pub const INLCR: usize = 0o000100;
pub const IGNCR: usize = 0o000200;
pub const ICRNL: usize = 0o000400;
pub const IUCLC: usize = 0o001000;
pub const IXON: usize = 0o002000;
pub const IXANY: usize = 0o004000;
pub const IXOFF: usize = 0o010000;
pub const IMAXBEL: usize = 0o020000;
pub const IUTF8: usize = 0o040000;

pub const OPOST: usize = 0o000001;
pub const OLCUC: usize = 0o000002;
pub const ONLCR: usize = 0o000004;
pub const OCRNL: usize = 0o000010;
pub const ONOCR: usize = 0o000020;
pub const ONLRET: usize = 0o000040;
pub const OFILL: usize = 0o000100;
pub const OFDEL: usize = 0o000200;

pub const VTDLY: usize = 0o040000;
pub const VT0: usize = 0o000000;
pub const VT1: usize = 0o040000;

pub const B0: usize = 0o000000;
pub const B50: usize = 0o000001;
pub const B75: usize = 0o000002;
pub const B110: usize = 0o000003;
pub const B134: usize = 0o000004;
pub const B150: usize = 0o000005;
pub const B200: usize = 0o000006;
pub const B300: usize = 0o000007;
pub const B600: usize = 0o000010;
pub const B1200: usize = 0o000011;
pub const B1800: usize = 0o000012;
pub const B2400: usize = 0o000013;
pub const B4800: usize = 0o000014;
pub const B9600: usize = 0o000015;
pub const B19200: usize = 0o000016;
pub const B38400: usize = 0o000017;

pub const B57600: usize = 0o010001;
pub const B115200: usize = 0o010002;
pub const B230400: usize = 0o010003;
pub const B460800: usize = 0o010004;
pub const B500000: usize = 0o010005;
pub const B576000: usize = 0o010006;
pub const B921600: usize = 0o010007;
pub const B1000000: usize = 0o010010;
pub const B1152000: usize = 0o010011;
pub const B1500000: usize = 0o010012;
pub const B2000000: usize = 0o010013;
pub const B2500000: usize = 0o010014;
pub const B3000000: usize = 0o010015;
pub const B3500000: usize = 0o010016;
pub const B4000000: usize = 0o010017;

pub const CSIZE: usize = 0o000060;
pub const CS5: usize = 0o000000;
pub const CS6: usize = 0o000020;
pub const CS7: usize = 0o000040;
pub const CS8: usize = 0o000060;
pub const CSTOPB: usize = 0o000100;
pub const CREAD: usize = 0o000200;
pub const PARENB: usize = 0o000400;
pub const PARODD: usize = 0o001000;
pub const HUPCL: usize = 0o002000;
pub const CLOCAL: usize = 0o004000;

pub const ISIG: usize = 0o000001;
pub const ICANON: usize = 0o000002;
pub const ECHO: usize = 0o000010;
pub const ECHOE: usize = 0o000020;
pub const ECHOK: usize = 0o000040;
pub const ECHONL: usize = 0o000100;
pub const NOFLSH: usize = 0o000200;
pub const TOSTOP: usize = 0o000400;
pub const IEXTEN: usize = 0o100000;

pub const TCOOFF: usize = 0;
pub const TCOON: usize = 1;
pub const TCIOFF: usize = 2;
pub const TCION: usize = 3;

pub const TCIFLUSH: usize = 0;
pub const TCOFLUSH: usize = 1;
pub const TCIOFLUSH: usize = 2;

pub const TCSANOW: usize = 0;
pub const TCSADRAIN: usize = 1;
pub const TCSAFLUSH: usize = 2;
