use core::mem;

#[cfg(target_os = "redox")]
use syscall::data::TimeSpec as redox_timespec;
// Use repr(u8) as LLVM expects `void*` to be the same as `i8*` to help enable
// more optimization opportunities around it recognizing things like
// malloc/free.
#[repr(u8)]
pub enum c_void {
    // Two dummy variants so the #[repr] attribute can be used.
    #[doc(hidden)]
    __variant1,
    #[doc(hidden)]
    __variant2,
}

pub type int8_t = i8;
pub type int16_t = i16;
pub type int32_t = i32;
pub type int64_t = i64;
pub type uint8_t = u8;
pub type uint16_t = u16;
pub type uint32_t = u32;
pub type uint64_t = u64;

pub type c_schar = i8;
pub type c_uchar = u8;
pub type c_short = i16;
pub type c_ushort = u16;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_float = f32;
pub type c_double = f64;
pub type c_longlong = i64;
pub type c_ulonglong = u64;
pub type intmax_t = i64;
pub type uintmax_t = u64;

pub type size_t = usize;
pub type ptrdiff_t = isize;
pub type intptr_t = isize;
pub type uintptr_t = usize;
pub type ssize_t = isize;

pub type c_char = i8;
pub type c_long = i64;
pub type c_ulong = u64;

pub type wchar_t = i32;
pub type wint_t = u32;
pub type wctype_t = i64;

pub type off_t = i64;
pub type mode_t = u16;
pub type time_t = i64;
pub type pid_t = usize;
pub type id_t = usize;
pub type gid_t = usize;
pub type uid_t = usize;
pub type dev_t = usize;
pub type ino_t = usize;
pub type nlink_t = usize;
pub type blksize_t = isize;
pub type blkcnt_t = u64;

pub type useconds_t = c_uint;
pub type suseconds_t = c_int;

pub type clock_t = i64;
pub type clockid_t = i32;
pub type timer_t = c_void;

#[repr(C)]
#[derive(Default)]
pub struct timespec {
    pub tv_sec: time_t,
    pub tv_nsec: c_long,
}

#[cfg(target_os = "redox")]
impl<'a> From<&'a timespec> for redox_timespec {
    fn from(tp: &timespec) -> redox_timespec {
        redox_timespec {
            tv_sec: tp.tv_sec,
            tv_nsec: tp.tv_nsec as i32,
        }
    }
}

#[repr(C)]
pub struct stat {
    pub st_dev: dev_t,
    pub st_ino: ino_t,
    pub st_nlink: nlink_t,
    pub st_mode: mode_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pub st_rdev: dev_t,
    pub st_size: off_t,
    pub st_blksize: blksize_t,
    pub st_blocks: blkcnt_t,

    pub st_atim: time_t,
    pub st_mtim: time_t,
    pub st_ctim: time_t,

    // Compared to glibc, our struct is for some reason 48 bytes too small.
    // Accessing atime works, so clearly the struct isn't incorrect...
    // This works.
    pub _pad: [u8; 48],
}

impl Default for stat {
    fn default() -> stat { 
        stat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,

            st_atim: 0,
            st_mtim: 0,
            st_ctim: 0,

            _pad: [0u8; 48],
        }
    }
}


pub const AF_INET: c_int = 2;
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_NONBLOCK: c_int = 0o4000;
pub const SOCK_CLOEXEC: c_int = 0o2000000;

pub const SIG_BLOCK: c_int = 0;
pub const SIG_UNBLOCK: c_int = 1;
pub const SIG_SETMASK: c_int = 2;

pub type in_addr_t = [u8; 4];
pub type in_port_t = u16;
pub type sa_family_t = u16;
pub type socklen_t = u32;

#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub data: [c_char; 14],
}

#[repr(C)]
pub struct sigaction {
    pub sa_handler: extern "C" fn(c_int),
    pub sa_flags: c_ulong,
    pub sa_restorer: unsafe extern "C" fn(),
    pub sa_mask: sigset_t
}

const NSIG: usize = 64;

pub type sigset_t = [c_ulong; NSIG / (8 * mem::size_of::<c_ulong>())];

const UTSLENGTH: usize = 65;

#[repr(C)]
pub struct utsname {
    pub sysname: [c_char; UTSLENGTH],
    pub nodename: [c_char; UTSLENGTH],
    pub release: [c_char; UTSLENGTH],
    pub version: [c_char; UTSLENGTH],
    pub machine: [c_char; UTSLENGTH],
    pub domainname: [c_char; UTSLENGTH],
}
