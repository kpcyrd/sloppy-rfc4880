use errors::*;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Read;
use encoding::read_length;

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


// TODO: In the next definition, replace Cow with an iterator returning &[u8] (for partial length).
//
// Problem: we can't read the next packet until we've read all the
// partial packets. The `read_packet` function below is correct, but
// allocates a vector which might get big.

pub fn read<B: Read>(reader: &mut B, body: &mut Vec<u8>) -> Result<Tag> {

    body.clear();

    let tag = reader.read_u8()?;
    assert_eq!(tag & 0x80, 0x80);

    let is_new_format = tag & 0x40 == 0x40;
    debug!("new format: {:?}", is_new_format);

    let tag = if is_new_format {

        let packet_tag = tag & 0x3f;

        let mut l0 = reader.read_u8()?;
        if l0 >= 224 && l0 < 0xff {
            debug!("Partial body length");
            while l0 >= 224 && l0 < 0xff {
                // partial length
                let len = 1 << (l0 & 0x1f);

                // read more len bytes
                let i0 = body.len();
                body.resize(i0 + len, 0);
                reader.read_exact(&mut body[i0..])?;
                l0 = reader.read_u8()?
            }
            // Last part of the packet
            let len = read_length(l0 as usize, reader)?;
            let i0 = body.len();
            body.resize(i0 + len, 0);
            reader.read_exact(&mut body[i0..])?;

        } else {
            let len = read_length(l0 as usize, reader)?;
            debug!("len = {:?}", len);
            body.resize(len, 0);
            reader.read_exact(&mut body[..])?;
        }

        packet_tag

    } else {

        let packet_tag = (tag >> 2) & 0xf;
        debug!("packet_tag: {:?}", Tag::from_byte(packet_tag));
        let length_type = tag & 0x3;
        if length_type == 0 {

            let len = reader.read_u8()? as usize;
            body.resize(len, 0);
            reader.read_exact(&mut body[..])?;

        } else if length_type == 1 {

            let len = reader.read_u16::<BigEndian>()? as usize;
            body.resize(len, 0);
            reader.read_exact(&mut body[..])?;

        } else if length_type == 2 {

            let len = reader.read_u32::<BigEndian>()? as usize;
            body.resize(len, 0);
            reader.read_exact(&mut body[..])?;

        } else {
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
