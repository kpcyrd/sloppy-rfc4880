use crate::errors::*;
use crate::encoding::read_length;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Read;

// https://tools.ietf.org/html/rfc4880#section-4.3
// sed -e "s/ *\(.*\) = \(.*\),/\2 => Some(Packet::\1),/"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    PublicKeyEncryptedSessionKey = 1,
    Signature = 2,
    SymmetricKeyEncryptedSessionKey = 3,
    OnePassSignature = 4,
    SecretKey = 5,
    PublicKey = 6,
    SecretSubkey = 7,
    CompressedData = 8,
    SymmetricallyEncryptedData = 9,
    Marker = 10,
    LiteralData = 11,
    Trust = 12,
    UserID = 13,
    PublicSubkey = 14,
    UserAttribute = 17,
    SymIntData = 18,
    ModificationDetectionCode = 19,
}

impl Tag {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Tag::PublicKeyEncryptedSessionKey),
            2 => Some(Tag::Signature),
            3 => Some(Tag::SymmetricKeyEncryptedSessionKey),
            4 => Some(Tag::OnePassSignature),
            5 => Some(Tag::SecretKey),
            6 => Some(Tag::PublicKey),
            7 => Some(Tag::SecretSubkey),
            8 => Some(Tag::CompressedData),
            9 => Some(Tag::SymmetricallyEncryptedData),
            10 => Some(Tag::Marker),
            11 => Some(Tag::LiteralData),
            12 => Some(Tag::Trust),
            13 => Some(Tag::UserID),
            14 => Some(Tag::PublicSubkey),
            17 => Some(Tag::UserAttribute),
            18 => Some(Tag::SymIntData),
            19 => Some(Tag::ModificationDetectionCode),
            _ => None,
        }
    }
}

fn ensure_alloc_limit(requested: usize, max_alloc: &Option<usize>) -> Result<()> {
    if let Some(max_alloc) = max_alloc {
        if requested > *max_alloc {
            bail!("Allocation larger than max_alloc");
        }
    }
    Ok(())
}


// TODO: In the next definition, replace Cow with an iterator returning &[u8] (for partial length).
//
// Problem: we can't read the next packet until we've read all the
// partial packets. The `read_packet` function below is correct, but
// allocates a vector which might get big.

pub fn read<B: Read>(reader: &mut B, body: &mut Vec<u8>, max_alloc: &Option<usize>) -> Result<Tag> {

    body.clear();

    let tag = reader.read_u8()?;
    if tag & 0x80 != 0x80 {
        bail!("0x80 must be set in tag");
    }

    let is_new_format = tag & 0x40 == 0x40;
    trace!("New packet format: {:?}", is_new_format);

    let tag = if is_new_format {

        let packet_tag = tag & 0x3f;

        let mut l0 = reader.read_u8()?;
        if l0 >= 224 && l0 < 0xff {
            trace!("Partial body length....");
            while l0 >= 224 && l0 < 0xff {
                // partial length
                let len = 1 << (l0 & 0x1f);
                trace!("Partial read: {:?}", len);

                // read more len bytes
                let i0 = body.len();
                ensure_alloc_limit(i0 + len, max_alloc)?;

                trace!("Resizing buffer to {:?}", i0 + len);
                body.resize(i0 + len, 0);
                trace!("Resize done");
                reader.read_exact(&mut body[i0..])?;
                trace!("Read done");
                l0 = reader.read_u8()?;
                trace!("Next l0: {:?}", l0);
            }
            // Last part of the packet
            let len = read_length(l0 as usize, reader)?;
            trace!("Last part: {:?}", len);
            let i0 = body.len();
            ensure_alloc_limit(i0 + len, max_alloc)?;
            body.resize(i0 + len, 0);
            reader.read_exact(&mut body[i0..])?;

        } else {
            let len = read_length(l0 as usize, reader)?;
            trace!("Packet length: {:?}", len);
            ensure_alloc_limit(len, max_alloc)?;
            body.resize(len, 0);
            reader.read_exact(&mut body[..])?;
        }

        packet_tag

    } else {

        let packet_tag = (tag >> 2) & 0xf;
        trace!("Packet tag: {:?}", Tag::from_byte(packet_tag));
        let length_type = tag & 0x3;
        if length_type == 0 {

            let len = reader.read_u8()? as usize;
            ensure_alloc_limit(len, max_alloc)?;
            body.resize(len, 0);
            reader.read_exact(&mut body[..])?;

        } else if length_type == 1 {

            let len = reader.read_u16::<BigEndian>()? as usize;
            ensure_alloc_limit(len, max_alloc)?;
            body.resize(len, 0);
            reader.read_exact(&mut body[..])?;

        } else if length_type == 2 {

            let len = reader.read_u32::<BigEndian>()? as usize;
            ensure_alloc_limit(len, max_alloc)?;
            body.resize(len, 0);
            reader.read_exact(&mut body[..])?;

        } else {
            // TODO: we can't enforce an allocation limit here
            reader.read_to_end(body)?;
        };
        packet_tag

    };
    if let Some(tag) = Tag::from_byte(tag) {
        Ok(tag)
    } else {
        bail!("Unknown Tag")
    }
}
