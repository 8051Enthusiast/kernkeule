use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

/// A buffer that prepends data to the beginning
struct ReverseBuf {
    buf: Vec<u8>,
    pos: usize,
}

impl ReverseBuf {
    fn new() -> Self {
        ReverseBuf {
            buf: vec![0; 16],
            pos: 16,
        }
    }

    fn resize(&mut self, new_size: usize) {
        assert!(new_size >= self.buf.len());
        let mut new_buf = vec![0; new_size];
        let start = new_size - self.buf.len();
        new_buf[start..].copy_from_slice(&self.buf);
        self.pos += start;
        self.buf = new_buf;
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> usize {
        if bytes.len() > self.pos {
            let new_size = (self.buf.len() + bytes.len() - self.pos).next_power_of_two();
            self.resize(new_size);
        }
        let start = self.pos - bytes.len();
        self.buf[start..self.pos].copy_from_slice(bytes);
        self.pos = start;
        self.buf.len() - self.pos
    }

    fn push_str(&mut self, str: &OsStr) -> usize {
        // make sure the string is null-terminated
        self.push_bytes(&[0]);
        self.push_bytes(str.as_bytes())
    }

    fn push_env(&mut self, key: &OsStr, val: &OsStr) -> usize {
        // env is in the form "key=val\0"
        self.push_bytes(&[0]);
        self.push_bytes(val.as_bytes());
        self.push_bytes(&[b'=']);
        self.push_bytes(key.as_bytes())
    }

    #[cfg(test)]
    fn get_bytes(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn get_bytes_aligned(&self) -> &[u8] {
        let start = self.pos & !0xf;
        &self.buf[start..]
    }
}

pub struct AuxVec {
    byte_data: ReverseBuf,
    args: Vec<usize>,
    env: Vec<usize>,
    aux: Vec<(usize, usize)>,
    aux_pointers: Vec<bool>,
}

impl AuxVec {
    pub fn new() -> Self {
        AuxVec {
            byte_data: ReverseBuf::new(),
            args: Vec::new(),
            env: Vec::new(),
            aux: Vec::new(),
            aux_pointers: Vec::new(),
        }
    }

    pub fn push_arg(&mut self, arg: &OsStr) {
        self.args.push(self.byte_data.push_str(arg));
    }

    pub fn push_env(&mut self, key: &OsStr, val: &OsStr) {
        self.env.push(self.byte_data.push_env(key, val));
    }

    pub fn push_aux_val(&mut self, key: u64, val: usize) {
        self.aux.push((key as usize, val));
        self.aux_pointers.push(false);
    }

    pub fn push_aux_str(&mut self, key: u64, val: &OsStr) {
        let pos = self.byte_data.push_str(val);
        self.aux.push((key as usize, pos));
        self.aux_pointers.push(true);
    }

    pub fn push_aux_bytes(&mut self, key: u64, val: &[u8]) {
        let pos = self.byte_data.push_bytes(val);
        self.aux.push((key as usize, pos));
        self.aux_pointers.push(true);
    }

    pub fn build(&self, top_addr: usize) -> Vec<u8> {
        let mut ret = Vec::new();
        let mut push = |val: usize, is_ptr| {
            let val = if is_ptr { top_addr - val } else { val }.to_ne_bytes();
            ret.extend_from_slice(&val);
        };
        push(self.args.len(), false);
        for &arg in self.args.iter() {
            push(arg, true);
        }
        push(0, false);
        for &env in self.env.iter() {
            push(env, true);
        }
        push(0, false);
        for (&(key, val), &is_ptr) in self.aux.iter().zip(self.aux_pointers.iter()) {
            push(key, false);
            push(val, is_ptr);
        }
        push(libc::AT_NULL as usize, false);
        push(0, false);
        let padding_len = ret.len().wrapping_neg() & 0xf;
        ret.extend_from_slice(&[0; 16][..padding_len]);
        ret.extend_from_slice(self.byte_data.get_bytes_aligned());
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_reverse_buf() {
        let mut buf = ReverseBuf::new();
        assert_eq!(buf.push_bytes(&[1, 2, 3]), 3);
        assert_eq!(buf.push_str(OsStr::new("hello")), 9);
        assert_eq!(
            buf.get_bytes(),
            [b'h', b'e', b'l', b'l', b'o', 0, 1, 2, 3].as_slice()
        );
        assert_eq!(buf.push_env(OsStr::new("key"), OsStr::new("val")), 17);
        assert_eq!(
            buf.get_bytes(),
            [
                b'k', b'e', b'y', b'=', b'v', b'a', b'l', 0, b'h', b'e', b'l', b'l', b'o', 0, 1, 2,
                3
            ]
            .as_slice()
        );
    }
}
