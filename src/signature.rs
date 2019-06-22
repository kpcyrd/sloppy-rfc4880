use byteorder::{BigEndian, ReadBytesExt};
use crate::errors::*;
use crate::encoding::{ReadValue, read_length};
use serde::{Serialize, Deserialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub keyid: Option<String>,
    pub fingerprint: Option<String>,
}

pub fn parse(mut body: &[u8]) -> Result<Signature> {
    let initial_body = body;
    let version = body.read_u8()?;
    let mut keyid = None;
    let mut fingerprint = None;

    debug!("signature version: {:?}", version);
    match version {
        // 3 => TODO
        4 => {
            let _sigtype = body.read_u8()?;
            let _pk_algo = body.read_u8()?;
            let _hash_algo = body.read_u8()?;

            let mut hashed_subpacket = body.read_string()?;
            let initial_len = initial_body.len() - body.len();
            debug!("initial_len: {:?}", initial_len);
            let mut unhashed_subpacket = body.read_string()?;

            while !hashed_subpacket.is_empty() {
                let sub = Subpacket::read(&mut hashed_subpacket)?;
                match sub {
                    Some(Subpacket::Issuer(i)) => keyid = Some(i),
                    Some(Subpacket::IssuerFingerprint(fp)) => fingerprint = Some(fp),
                    _ => (),
                }
            }
            while !unhashed_subpacket.is_empty() {
                let sub = Subpacket::read(&mut unhashed_subpacket)?;
                match sub {
                    Some(Subpacket::Issuer(i)) => keyid = Some(i),
                    Some(Subpacket::IssuerFingerprint(fp)) => fingerprint = Some(fp),
                    _ => (),
                }
            }

            Ok(Signature {
                keyid,
                fingerprint,
            })
        },
        _ => bail!("unsupported signature version: {}", version),
    }
}

pub enum Subpacket {
    Issuer(String),
    IssuerFingerprint(String),
    Unknown,
}

impl Subpacket {
    fn read(packet: &mut &[u8]) -> Result<Option<Subpacket>> {
        let p0 = packet.read_u8()? as usize;
        let len = read_length(p0, packet)?;
        if len <= packet.len() {
            let (mut a, b) = packet.split_at(len);
            *packet = b;

            match a.read_u8()? {
                16 => {
                    let issuer = a.read_u64::<BigEndian>()?;
                    let issuer = format!("{:X}", issuer);
                    Ok(Some(Subpacket::Issuer(issuer)))
                },
                33 => {
                    let _v = a.read_u8()?;
                    let fp = hex::encode_upper(a);
                    Ok(Some(Subpacket::IssuerFingerprint(fp)))
                },
                _ => Ok(None),
            }
        } else {
            bail!("index out of bounds")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signature_issuer() {
        let bytes = b"\x04\x10\x01\x08\0\x1d\x16!\x04\x90;\xabsd\x0e\xb6\xd6U3\xef\xf3F\x8f\x12,\xe8\x16\"\x95\x05\x02[\xdc\xcb\x16\0\n\t\x10F\x8f\x12,\xe8\x16\"\x95dE\x10\0\x9b\xa3\x8f\x05d\xe8c\xffp\xad9\x97\xa9Z\xae\x93\x1a\xb8u\xa7Dm\x1e\xa4\xbd\xfd\xd0X\xfe\x07\x95y-I\x10<\xc8\x03\x8b\x11\xf3\x9eU\xf8s\xdf\xdc\xab\x1d\x9a\xf8\x03\x17\xd0{q\x1fG\xedp\xef\xae!\xd0:\x82\xcc\xbc\xd9Yl\0W:\xa0n\xd5I\x8a~\xa7\xa3z\xb8\xe11\xbc\xbb\x1f\x9d;\x01\x97\x85\x8e%\x02\x18\x14H*\xf0\x9a\xb1_\xc0\x01r\xe4p!\xcf\xd2\xb4\xb0\x06[/v\xeab`\xf3\xdc\xa8\xf0\xd9h\xa5\xc1h\xd1z\xee\x0c*,\xc0\"\xfd\x8f\x1c\xe5\xc1\x12\xb6\xcd\x03\x060\xbd0S\t\x85\x92\x8eN.\xac\xad\x05\x8e\x80\xea\xd2\xfb\xd9\\\xddA\xc0\xc7Q#3I\xb8;\x81\\\x80\x0fm\xd8zO\xb8\xdb\x9a\x18(\xee<hY\xdb\x1a@P\xa4^\x15W\xd3\x91\rq\xd4\xbf\x17\xb4\x88\xed\x85\xe6G\x8f\xdbU\x92\xef\xd4\x9f\x9dbC\x98\xd2\x8f.\xf4\x07\xa6\x94y\xe4P\xca\xbc#\x87)Q\xcb\xc2\xcf\xfd&\xc7\xe2\xced\xa5q\xeey\xc2/pbB\x07\x92\xf0Y?c=\xe5\x97\x9f\xa9\x8e\xb3;\x0c\xb8+\xb5\x01\xd5!\xaeL\xad\xb4y\x15\x1b\xc1\xbcy\xe4J\x05b\x1dI7\xcd\xc7\tW\xf0\x96\xceQs\xa2b\xafm0\xfe\x9f\xd8\xc7\xd03ku]\xb6[\xa7R`\xcf/C\xf7\xf5\x91\x14W\xbd\xd39\x1a\x08\x08\x9c\0\xcf\x05L\xa6O\xb9Z\x13\x99-\xe7d!\xfeW,\x16%\x9e\x0b\xfd\x90\x9cz\x02\xa0\xb3#\x1e\xb3\x19&\n\xedx\xd0\x9c\xdcf\x85\xf4\x9d\xed\"\xf5\xaf/%\xb6\x11\x9a\xb5\x80\x9b\xa2\xf9\xfe\xaa\xb3\xf9\x88\x1a\xca\xbaL[\xae\xf2 \x1b\x04\x99V\xcc\xb8\x1epJ\x1e\xcd\x16\xcd\xfc;&\xdb\x02\x1e\x97f\x18|8,\xd6+d,\xb7\xe9\xfd\x0f&\x1a\xfe\xb6[\xb03\xe0%Wka\xaal\x97\xda\xf3J&\xa6\x16~o1\xdf/\xda\xf7\xc6\x10\xd3\x96\xcdkw\xcb\xf3\x9b\x0c\x8a9\xac /\xda^\x98y\xde\x8d\xac\xb6\x82a\xcaL\xfaI<\x90E\xb8\xfc\xe6\x1f\x15";
        let sig = parse(bytes).expect("parse");

        assert_eq!(sig, Signature {
            keyid: Some(String::from("468F122CE8162295")),
            fingerprint: Some(String::from("903BAB73640EB6D65533EFF3468F122CE8162295")),
        });
    }
}
