use core::{mem, ptr};

use types::*;
use *;

const AT_FDCWD: c_int = -100;
const AT_EMPTY_PATH: c_int = 0x1000;
const AT_REMOVEDIR: c_int = 0x200;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

pub const SEEK_SET: c_int = 0;

// Also in sys_utsname. Has to be both because cbindgen
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

fn e(sys: usize) -> usize {
    if (sys as isize) < 0 && (sys as isize) >= -256 {
        unsafe {
            errno = -(sys as isize) as c_int;
        }
        !0
    } else {
        sys
    }
}

pub unsafe fn accept(socket: c_int, address: *mut sockaddr, address_len: *mut socklen_t) -> c_int {
    e(syscall!(ACCEPT, socket, address, address_len)) as c_int
}

pub unsafe fn bind(socket: c_int, address: *const sockaddr, address_len: socklen_t) -> c_int {
    e(syscall!(BIND, socket, address, address_len)) as c_int
}

pub fn brk(addr: *mut c_void) -> *mut c_void {
    unsafe { syscall!(BRK, addr) as *mut c_void }
}

pub fn chdir(path: *const c_char) -> c_int {
    e(unsafe { syscall!(CHDIR, path) }) as c_int
}

pub fn chmod(path: *const c_char, mode: mode_t) -> c_int {
    e(unsafe { syscall!(FCHMODAT, AT_FDCWD, path, mode, 0) }) as c_int
}

pub fn chown(path: *const c_char, owner: uid_t, group: gid_t) -> c_int {
    e(unsafe { syscall!(FCHOWNAT, AT_FDCWD, path, owner as u32, group as u32) }) as c_int
}

pub fn close(fildes: c_int) -> c_int {
    e(unsafe { syscall!(CLOSE, fildes) }) as c_int
}

pub unsafe fn connect(socket: c_int, address: *const sockaddr, address_len: socklen_t) -> c_int {
    e(syscall!(CONNECT, socket, address, address_len)) as c_int
}

pub fn dup(fildes: c_int) -> c_int {
    e(unsafe { syscall!(DUP, fildes) }) as c_int
}

pub fn dup2(fildes: c_int, fildes2: c_int) -> c_int {
    e(unsafe { syscall!(DUP3, fildes, fildes2, 0) }) as c_int
}

pub fn execve(path: *const c_char, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    e(unsafe { syscall!(EXECVE, path, argv, envp) }) as c_int
}

pub fn exit(status: c_int) -> ! {
    unsafe {
        syscall!(EXIT, status);
    }
    loop {}
}

pub fn fchdir(fildes: c_int) -> c_int {
    e(unsafe { syscall!(FCHDIR, fildes) }) as c_int
}

pub fn fchmod(fildes: c_int, mode: mode_t) -> c_int {
    e(unsafe { syscall!(FCHMOD, fildes, mode) }) as c_int
}

pub fn fchown(fildes: c_int, owner: uid_t, group: gid_t) -> c_int {
    e(unsafe { syscall!(FCHOWN, fildes, owner, group) }) as c_int
}

pub fn fstat(fildes: c_int, buf: *mut stat) -> c_int {
    let empty_cstr: *const c_char = unsafe { ::cstr_from_bytes_with_nul_unchecked(b"\0") };
    e(unsafe { syscall!(NEWFSTATAT, fildes, empty_cstr, buf, AT_EMPTY_PATH) }) as c_int
}

pub fn fcntl(fildes: c_int, cmd: c_int, arg: c_int) -> c_int {
    e(unsafe { syscall!(FCNTL, fildes, cmd, arg) }) as c_int
}

pub fn fork() -> pid_t {
    e(unsafe { syscall!(CLONE, 17, 0) }) as pid_t
}

pub fn fsync(fildes: c_int) -> c_int {
    e(unsafe { syscall!(FSYNC, fildes) }) as c_int
}

pub fn ftruncate(fildes: c_int, length: off_t) -> c_int {
    e(unsafe { syscall!(FTRUNCATE, fildes, length) }) as c_int
}

pub fn getcwd(buf: *mut c_char, size: size_t) -> *mut c_char {
    if e(unsafe { syscall!(GETCWD, buf, size) }) == !0 {
        ptr::null_mut()
    } else {
        buf
    }
}

pub fn getegid() -> gid_t {
    e(unsafe { syscall!(GETEGID) })
}

pub fn geteuid() -> uid_t {
    e(unsafe { syscall!(GETEUID) })
}

pub fn getgid() -> gid_t {
    e(unsafe { syscall!(GETGID) })
}

pub unsafe fn gethostname(mut name: *mut c_char, len: size_t) -> c_int {
    // len only needs to be mutable on linux
    let mut len = len;

    let mut uts = mem::uninitialized();
    let err = uname(&mut uts);
    if err < 0 {
        mem::forget(uts);
        return err;
    }
    for c in uts.nodename.iter() {
        if len == 0 {
            break;
        }
        len -= 1;

        *name = *c;

        if *name == 0 {
            // We do want to copy the zero also, so we check this after the copying.
            break;
        }

        name = name.offset(1);
    }
    0
}

pub unsafe fn getpeername(
    socket: c_int,
    address: *mut sockaddr,
    address_len: *mut socklen_t,
) -> c_int {
    e(syscall!(GETPEERNAME, socket, address, address_len)) as c_int
}

pub fn getpgid(pid: pid_t) -> pid_t {
    e(unsafe { syscall!(GETPGID, pid) })
}

pub fn getpid() -> pid_t {
    e(unsafe { syscall!(GETPID) })
}

pub fn getppid() -> pid_t {
    e(unsafe { syscall!(GETPPID) })
}

pub unsafe fn getsockname(
    socket: c_int,
    address: *mut sockaddr,
    address_len: *mut socklen_t,
) -> c_int {
    e(syscall!(GETSOCKNAME, socket, address, address_len)) as c_int
}

pub fn getsockopt(
    socket: c_int,
    level: c_int,
    option_name: c_int,
    option_value: *mut c_void,
    option_len: *mut socklen_t,
) -> c_int {
    e(unsafe {
        syscall!(
            GETSOCKOPT,
            socket,
            level,
            option_name,
            option_value,
            option_len
        )
    }) as c_int
}

pub fn getuid() -> uid_t {
    e(unsafe { syscall!(GETUID) })
}

pub fn kill(pid: pid_t, sig: c_int) -> c_int {
    e(unsafe { syscall!(KILL, pid, sig) }) as c_int
}

pub fn killpg(pgrp: pid_t, sig: c_int) -> c_int {
    e(unsafe { syscall!(KILL, -(pgrp as isize) as pid_t, sig) }) as c_int
}

pub fn link(path1: *const c_char, path2: *const c_char) -> c_int {
    e(unsafe { syscall!(LINKAT, AT_FDCWD, path1, AT_FDCWD, path2, 0) }) as c_int
}

pub fn listen(socket: c_int, backlog: c_int) -> c_int {
    e(unsafe { syscall!(LISTEN, socket, backlog) }) as c_int
}

pub fn lseek(fildes: c_int, offset: off_t, whence: c_int) -> off_t {
    e(unsafe { syscall!(LSEEK, fildes, offset, whence) }) as off_t
}

pub fn lstat(file: *const c_char, buf: *mut stat) -> c_int {
    e(unsafe { syscall!(NEWFSTATAT, AT_FDCWD, file, buf, AT_SYMLINK_NOFOLLOW) }) as c_int
}

pub fn mkdir(path: *const c_char, mode: mode_t) -> c_int {
    e(unsafe { syscall!(MKDIRAT, AT_FDCWD, path, mode) }) as c_int
}

pub fn mkfifo(path: *const c_char, mode: mode_t) -> c_int {
    e(unsafe { syscall!(MKNODAT, AT_FDCWD, path, mode, 0) }) as c_int
}

pub fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> c_int {
    e(unsafe { syscall!(NANOSLEEP, rqtp, rmtp) }) as c_int
}

pub fn open(path: *const c_char, oflag: c_int, mode: mode_t) -> c_int {
    e(unsafe { syscall!(OPENAT, AT_FDCWD, path, oflag, mode) }) as c_int
}

pub fn pipe(fildes: &mut [c_int]) -> c_int {
    e(unsafe { syscall!(PIPE2, fildes.as_mut_ptr(), 0) }) as c_int
}

pub fn read(fildes: c_int, buf: &mut [u8]) -> ssize_t {
    e(unsafe { syscall!(READ, fildes, buf.as_mut_ptr(), buf.len()) }) as ssize_t
}

pub unsafe fn recvfrom(
    socket: c_int,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
    address: *mut sockaddr,
    address_len: *mut socklen_t,
) -> ssize_t {
    e(syscall!(
        RECVFROM,
        socket,
        buf,
        len,
        flags,
        address,
        address_len
    )) as ssize_t
}

pub fn rename(old: *const c_char, new: *const c_char) -> c_int {
    e(unsafe { syscall!(RENAMEAT, AT_FDCWD, old, AT_FDCWD, new) }) as c_int
}

pub fn rmdir(path: *const c_char) -> c_int {
    e(unsafe { syscall!(UNLINKAT, AT_FDCWD, path, AT_REMOVEDIR) }) as c_int
}

pub unsafe fn sendto(
    socket: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    dest_addr: *const sockaddr,
    dest_len: socklen_t,
) -> ssize_t {
    e(syscall!(
        SENDTO, socket, buf, len, flags, dest_addr, dest_len
    )) as ssize_t
}

pub fn setpgid(pid: pid_t, pgid: pid_t) -> c_int {
    e(unsafe { syscall!(SETPGID, pid, pgid) }) as c_int
}

pub fn setregid(rgid: gid_t, egid: gid_t) -> c_int {
    e(unsafe { syscall!(SETREGID, rgid, egid) }) as c_int
}

pub fn setreuid(ruid: uid_t, euid: uid_t) -> c_int {
    e(unsafe { syscall!(SETREUID, ruid, euid) }) as c_int
}

pub fn setsockopt(
    socket: c_int,
    level: c_int,
    option_name: c_int,
    option_value: *const c_void,
    option_len: socklen_t,
) -> c_int {
    e(unsafe {
        syscall!(
            SETSOCKOPT,
            socket,
            level,
            option_name,
            option_value,
            option_len
        )
    }) as c_int
}

pub fn shutdown(socket: c_int, how: c_int) -> c_int {
    e(unsafe { syscall!(SHUTDOWN, socket, how) }) as c_int
}

pub fn stat(file: *const c_char, buf: *mut stat) -> c_int {
    e(unsafe { syscall!(NEWFSTATAT, AT_FDCWD, file, buf, 0) }) as c_int
}

pub fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int {
    e(unsafe { syscall!(SOCKET, domain, kind, protocol) }) as c_int
}

pub fn socketpair(domain: c_int, kind: c_int, protocol: c_int, socket_vector: *mut c_int) -> c_int {
    e(unsafe { syscall!(SOCKETPAIR, domain, kind, protocol, socket_vector) }) as c_int
}

pub fn uname(utsname: *mut utsname) -> c_int {
    e(unsafe { syscall!(UNAME, utsname, 0) }) as c_int
}

pub fn unlink(path: *const c_char) -> c_int {
    e(unsafe { syscall!(UNLINKAT, AT_FDCWD, path, 0) }) as c_int
}

pub fn waitpid(pid: pid_t, stat_loc: *mut c_int, options: c_int) -> pid_t {
    e(unsafe { syscall!(WAIT4, pid, stat_loc, options, 0) }) as pid_t
}

pub fn write(fildes: c_int, buf: &[u8]) -> ssize_t {
    e(unsafe { syscall!(WRITE, fildes, buf.as_ptr(), buf.len()) }) as ssize_t
}

pub fn clock_gettime(clk_id: clockid_t, tp: *mut timespec) -> c_int {
    e(unsafe { syscall!(CLOCK_GETTIME, clk_id, tp) }) as c_int
}
