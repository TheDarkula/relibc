use alloc::vec::Vec;
use read;
use types::*;

/// Implements an `Iterator` which returns on either newline or EOF.
#[derive(Clone)]
pub struct RawLineBuffer {
    pub fd: c_int,
    buf: Vec<u8>,
    newline: Option<usize>,
    read: usize
}

pub enum Line<'a> {
    Error,
    EOF,
    Some(&'a [u8])
}

impl RawLineBuffer {
    pub const fn new(fd: c_int) -> Self {
        Self {
            fd: fd,
            buf: Vec::new(),
            newline: None,
            read: 0
        }
    }

    // Can't use iterators because we want to return a reference.
    // See https://stackoverflow.com/a/30422716/5069285
    pub fn next(&mut self) -> Line {
        // Remove last line
        if let Some(newline) = self.newline {
            self.buf.drain(..newline + 1);
        }

        loop {
            // Exit if newline was read already
            self.newline = self.buf.iter().position(|b| *b == b'\n');

            if self.newline.is_some() {
                break;
            }

            let len = self.buf.len();

            if len >= self.buf.capacity() {
                self.buf.reserve(1024);
            }

            // Create buffer of what's left in the vector, uninitialized memory
            unsafe {
                let capacity = self.buf.capacity();
                self.buf.set_len(capacity);
            }

            let read = read(self.fd, &mut self.buf[len..]);

            if read == 0 {
                return Line::EOF;
            }
            if read < 0 {
                return Line::Error;
            }

            // Remove all uninitialized memory that wasn't read
            unsafe {
                self.buf.set_len(len + read as usize);
            }

            self.read += read as usize;
        }

        let newline = self.newline.unwrap(); // safe because it doesn't break the loop otherwise
        Line::Some(&self.buf[..newline])
    }

    /// Return the byte position of the start of the line
    pub fn line_pos(&self) -> usize {
        self.read - self.buf.len()
    }
}
