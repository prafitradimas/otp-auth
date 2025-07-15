use crate::encoding::{self, base32::DecodeBase32Error};

#[derive(Default, Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn from_base32(secret: &str) -> Result<Self, DecodeBase32Error> {
        encoding::base32::decode(secret).map(Self)
    }

    pub fn into_base32(&self) -> String {
        encoding::base32::encode(self.0.as_slice())
    }

    pub fn into_hex(&self) -> String {
        encoding::hex::encode(self.0.as_slice())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
impl Eq for Secret {}

#[cfg(test)]
impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

#[cfg(test)]
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(hex[\"{}\"])", self.into_hex())
    }
}

// #[cfg(not(test))]
// impl std::fmt::Debug for Secret {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.write_str("Secret([REDACTED])")
//     }
// }
