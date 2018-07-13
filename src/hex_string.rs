use rustc_serialize::hex::{FromHexError, FromHex};

use std::fmt::{Display, Formatter, Result as FmtResult};

pub struct HexString(pub String);

impl HexString {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_ref(&self) -> &str {
        self.0.as_ref()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl FromHex for HexString {
    fn from_hex(&self) -> Result<Vec<u8>, FromHexError> {
        self.0.from_hex()
    }
}

impl<'a> From<&'a [u8]> for HexString {
    fn from(input: &'a[u8]) -> HexString {
        let strs: Vec<String> = input.iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        HexString(strs.join(""))
    }
}

impl From<Vec<u8>> for HexString {
    fn from(input: Vec<u8>) -> HexString {
        HexString::from(input.as_ref())
    }
}

impl Display for HexString {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        self.0.fmt(f)
    }
}
