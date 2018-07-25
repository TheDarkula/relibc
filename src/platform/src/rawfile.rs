use core::ops::Deref;
use super::{open, dup, close, read, fstat, types::*};
use alloc::Vec;

pub struct RawFile(c_int);

impl RawFile {
    pub fn open(path: *const c_char, oflag: c_int, mode: mode_t) -> Result<RawFile, ()> {
        match open(path, oflag, mode) {
            -1 => Err(()),
            n => Ok(RawFile(n))
        }
    }

    pub fn dup(&self, _buf: &[u8]) -> Result<RawFile, ()> {
        match dup(self.0) {
            -1 => Err(()),
            n => Ok(RawFile(n))
        }
    }

    pub fn as_raw_fd(&self) -> c_int {
        self.0
    }

    pub fn into_raw_fd(self) -> c_int {
        self.0
    }

    pub fn from_raw_fd(fd: c_int) -> Self {
        RawFile(fd)
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

impl Deref for RawFile {
    type Target = c_int;

    fn deref(&self) -> &c_int {
        &self.0
    }
}

pub fn file_read_all<T: AsRef<[u8]>>(path: T) -> Result<Vec<u8>, ()> {
    let fd = RawFile::open(path.as_ref().as_ptr() as *const c_char, 0, 0)?;

    let mut st = stat::default();
    fstat(*fd as i32, &mut st);
    let size = st.st_size as usize;

    let mut buf = Vec::with_capacity(size);
    unsafe { buf.set_len(size) };
    read(*fd as i32, buf.as_mut_slice());

    Ok(buf)
}
