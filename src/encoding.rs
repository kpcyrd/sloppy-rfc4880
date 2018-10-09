use errors::*;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Read;

pub trait ReadValue<'a> {
    fn read_string(&mut self) -> Result<&'a [u8]>;
    fn read_mpi(&mut self) -> Result<&'a [u8]>;
}

impl<'a> ReadValue<'a> for &'a [u8] {
    // Not a formal def, mut used many times in the RFC.
    fn read_string(&mut self) -> Result<&'a [u8]> {
        let length = (*self).read_u16::<BigEndian>()? as usize;
        if length <= self.len() {
            let (a, b) = self.split_at(length);
            *self = b;
            Ok(a)
        } else {
            bail!("Index out of bounds")
        }
    }

    // https://tools.ietf.org/html/rfc4880#section-3.2
    fn read_mpi(&mut self) -> Result<&'a [u8]> {
        let length = (*self).read_u16::<BigEndian>()? as usize;
        let length = (length + 7) >> 3;
        if length <= self.len() {
            let (a, b) = self.split_at(length);
            *self = b;
            Ok(a)
        } else {
            bail!("Index out of bounds")
        }
    }
}

pub fn read_length<R: Read>(l0: usize, s: &mut R) -> Result<usize> {
    Ok(if l0 <= 191 {
        l0
    } else if l0 <= 223 {
        let l1 = s.read_u8()? as usize;
        (((l0 - 192) << 8) | l1) + 192
    } else {
        debug_assert!(l0 == 0xff);
        s.read_u32::<BigEndian>()? as usize
    })
}
