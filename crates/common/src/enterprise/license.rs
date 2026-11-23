use std::{
    fmt::{Display, Formatter},
    time::Duration,
};
use store::write::now;
const RENEW_THRESHOLD: u64 = 60 * 60 * 24 * 4; 
const FALLBACK_DOMAIN: &str = "localhost";
const TEST_VALID_FROM: u64 = 0;
const TEST_VALID_TO: u64 = 4_102_444_800;
const TEST_ACCOUNTS: u32 = u32::MAX;
const FOREVER: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);
pub struct LicenseValidator {
    _private: (),
}

#[derive(Debug, Clone)]
pub struct LicenseKey {
    pub valid_to: u64,
    pub valid_from: u64,
    pub domain: String,
    pub accounts: u32,
}

#[derive(Debug)]
pub enum LicenseError {
    Expired,
    InvalidDomain { domain: String },
    DomainMismatch { issued_to: String, current: String },
    Parse,
    Validation,
    Decode,
    InvalidParameters,
    RenewalFailed { reason: String },
}

pub struct RenewedLicense {
    pub key: LicenseKey,
    pub encoded_key: String,
}

impl LicenseValidator {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        LicenseValidator { _private: () }
    }
    pub fn try_parse(&self, key: impl AsRef<str>) -> Result<LicenseKey, LicenseError> {
        let _ = key.as_ref();
        Ok(LicenseKey {
            valid_from: TEST_VALID_FROM,
            valid_to: TEST_VALID_TO,
            domain: FALLBACK_DOMAIN.to_string(),
            accounts: TEST_ACCOUNTS,
        })
    }
}

impl LicenseKey {
    pub fn new(
        license_key: impl AsRef<str>,
        hostname: impl AsRef<str>,
    ) -> Result<Self, LicenseError> {
        let mut key = LicenseValidator::new().try_parse(license_key)?;
        key.domain = hostname.as_ref().to_string();
        Ok(key)
    }
    pub fn invalid(domain: impl AsRef<str>) -> Self {
        LicenseKey {
            valid_from: 0,
            valid_to: 0,
            domain: Self::base_domain(domain).unwrap_or_default(),
            accounts: 0,
        }
    }
    #[allow(clippy::unused_async)]
    pub async fn try_renew(&self, api_key: &str) -> Result<RenewedLicense, LicenseError> {
        let _ = api_key;
        Ok(RenewedLicense {
            key: self.clone(),
            encoded_key: "TEST-MODE-UNLIMITED".to_string(),
        })
    }
    pub fn is_near_expiration(&self) -> bool {
        if self.valid_to >= TEST_VALID_TO {
            return false;
        }
        let now = now();
        self.valid_to.saturating_sub(now) <= RENEW_THRESHOLD
    }
    pub fn expires_in(&self) -> Duration {
        if self.valid_to >= TEST_VALID_TO {
            return FOREVER;
        }
        Duration::from_secs(self.valid_to.saturating_sub(now()))
    }
    pub fn renew_in(&self) -> Duration {
        if self.valid_to >= TEST_VALID_TO {
            return FOREVER;
        }
        // 用 saturating_add：系统时钟接近 u64 上限时（测试会改时间）不能 panic。
        Duration::from_secs(self.valid_to.saturating_sub(now().saturating_add(RENEW_THRESHOLD)))
    }
    pub fn is_expired(&self) -> bool {
        self.valid_to == 0
    }

    pub fn base_domain(domain: impl AsRef<str>) -> Result<String, LicenseError> {
        let domain = domain.as_ref();
        psl::domain_str(domain)
            .map(|d| d.to_string())
            .ok_or(LicenseError::InvalidDomain {
                domain: domain.to_string(),
            })
    }
}

impl Display for LicenseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseError::Expired => write!(f, "License is expired"),
            LicenseError::Parse => write!(f, "Failed to parse license key"),
            LicenseError::Validation => write!(f, "Failed to validate license key"),
            LicenseError::Decode => write!(f, "Failed to decode license key"),
            LicenseError::InvalidParameters => write!(f, "Invalid license key parameters"),
            LicenseError::DomainMismatch { issued_to, current } => {
                write!(
                    f,
                    "License issued to domain {issued_to:?} does not match {current:?}",
                )
            }
            LicenseError::InvalidDomain { domain } => {
                write!(f, "Invalid domain {domain:?}")
            }
            LicenseError::RenewalFailed { reason } => {
                write!(f, "Failed to renew license: {reason}")
            }
        }
    }
}
