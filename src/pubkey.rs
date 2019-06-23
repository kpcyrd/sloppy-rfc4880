use sha1::{Sha1, Digest};

pub fn fingerprint(pubkey: &[u8]) -> String {
    let mut h = Sha1::new();
    h.input(b"\x99");
    let len = pubkey.len() as u16;
    h.input(len.to_be_bytes());
    h.input(pubkey);
    let fp = h.result();
    hex::encode_upper(fp)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculate_fingerprint() {
        let pubkey = b"\x04[\xba\xab\xdd\x01\x08\0\xe0\x0f\xb4=h~z\xf3|\xad\xee\x1c\xcf\x92\xd0\xe4\x01C@d\x91\xf0b\x15\r{!\x8a\xe3w\xeb? \xd1Y\t\xaa7\xea\x17M\xf8\x98X\xb4\r\xf9\xde\xca4\x14\xe7\x17\xdb\xb0\xc8\x17Z,\xce\xd2\x1f\x8e%,\xd6(\xf1m=\x99S6x\xaf\xb0\xb7_n\x7f\x91\xd86\0\x04\xf2V\xb8\xe5\x02\xe8\xfd\xc7\xbd\t\x05^\xd5\xae(\\\xd5\xaa\xea]\x059\x8e\xcc\xfb\x02\xde\xf8m\xb03\x0c\xfcEq\xa0\xc1\xdf\xeaB\x9e?<\x1eX\xa5Hq\x9c\t\xf3\n\\o\xc3)\xab/\xa0P^\xc4\\)#\x12\x0f\x96\xc8\xcc\x8b\xfd\xe6}t\xe4+\xd6\xe4z\xa5\xec\x94}\xce\x03\x91\xfa\x01\xeaT\xe1\xfc\x1c\x15\x1cg\x13.\x9a\xb4\xcc\xe9\xa2\x8b\x80\x08`3\xc4\xa7\xdf\xa8\x02\x14\xe7\xe3\x94m[\xd4\xe1Kf\x15-\x82\xba?\x9eq\x0e\x98\x0b\xabF\xc0\x99\xcb\xc39\x87\xc4\x0c\x16\x96B\x84\x81\xfc\x92\x01\xec\xf7A\x7f\x08+\xc6\x8c\xca\xb7\xaa\xf5\x9c\x1f\xc6l=H\xb3\0\x11\x01\0\x01";
        let fp = fingerprint(pubkey);
        assert_eq!(fp.as_str(), "CB378ED5E1306C1D3785CA81334D08A1D19D963F");
    }
}
