pub mod generate;
pub mod verify;

pub enum Version {
    V3,
}

impl Version {
    pub fn number(version: Version) -> u64 {
        match version {
            Version::V3 => 2,
        }
    }
}
