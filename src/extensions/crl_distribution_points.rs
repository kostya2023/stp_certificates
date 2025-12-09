// extensions/crl_distribution_points.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;

pub struct CRLDistributionPoints {
    uri: String,
}

impl CRLDistributionPoints {
    pub fn new(uri: &str) -> Self {
        Self { uri: uri.to_string() }
    }

    pub fn uri(&self) -> String {
        self.uri.clone()
    }
}

