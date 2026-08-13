// SPDX-License-Identifier: Apache-2.0
use std::{fmt, str::FromStr};

use anyhow::{Context as _, anyhow, bail};
use hmac::{Hmac, KeyInit as KeyInit013, Mac as Mac013};
use hmac012::Mac as Mac012;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// HMAC instances per RFC 6238: SHA-1 uses the sha1 0.10 / hmac 0.12
/// (digest 0.10) stack; SHA-256 and SHA-512 use sha2 0.11 / hmac 0.13
/// (digest 0.11).
type HmacSha1 = hmac012::Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Magic prefix of the encrypted TOTP entry payload.
const TOTP_MAGIC: &[u8] = b"cybercuris-totp-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Sha1 => 0,
            Self::Sha256 => 1,
            Self::Sha512 => 2,
        }
    }

    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Sha1),
            1 => Some(Self::Sha256),
            2 => Some(Self::Sha512),
            _ => None,
        }
    }
}

impl fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TotpAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => bail!(
                "unsupported TOTP algorithm: {s} (expected sha1, sha256, or \
                 sha512)"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpParams {
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
}

impl TotpParams {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(6..=8).contains(&self.digits) {
            bail!("TOTP digits must be between 6 and 8, got {}", self.digits);
        }
        if self.period == 0 {
            bail!("TOTP period must be positive");
        }
        if self.period > 3600 {
            bail!("TOTP period must be at most 3600 seconds");
        }
        Ok(())
    }
}

/// Serialize an encrypted-entry payload:
/// `magic(17) || algorithm(1) || digits(1) || period-le(4) || secret`.
pub fn encode_entry(
    params: &TotpParams,
    secret: &[u8],
) -> anyhow::Result<Vec<u8>> {
    params.validate()?;
    if secret.is_empty() {
        bail!("TOTP secret cannot be empty");
    }

    let mut out = Vec::with_capacity(TOTP_MAGIC.len() + 6 + secret.len());
    out.extend_from_slice(TOTP_MAGIC);
    out.push(params.algorithm.to_byte());
    out.push(params.digits);
    out.extend_from_slice(&params.period.to_le_bytes());
    out.extend_from_slice(secret);
    Ok(out)
}

pub fn decode_entry(plain: &[u8]) -> anyhow::Result<(TotpParams, &[u8])> {
    let rest = plain
        .strip_prefix(TOTP_MAGIC)
        .ok_or_else(|| anyhow!("not a CyberCuris TOTP entry"))?;
    if rest.len() < 6 {
        bail!("TOTP entry payload too short");
    }
    let algorithm = TotpAlgorithm::from_byte(rest[0])
        .ok_or_else(|| anyhow!("unknown TOTP algorithm byte {}", rest[0]))?;
    let digits = rest[1];
    let period = u32::from_le_bytes(
        rest[2..6]
            .try_into()
            .map_err(|_| anyhow!("corrupt TOTP period"))?,
    );
    let params = TotpParams {
        algorithm,
        digits,
        period,
    };
    params.validate()?;

    let secret = &rest[6..];
    if secret.is_empty() {
        bail!("TOTP entry has an empty secret");
    }
    Ok((params, secret))
}

/// Generate the TOTP value for `timestamp` (Unix seconds) per RFC 6238.
pub fn generate_totp(
    secret: &[u8],
    params: &TotpParams,
    timestamp: u64,
) -> anyhow::Result<String> {
    params.validate()?;
    if secret.is_empty() {
        bail!("TOTP secret cannot be empty");
    }

    let counter = timestamp / u64::from(params.period);
    let mut msg = [0u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());

    let hash = match params.algorithm {
        TotpAlgorithm::Sha1 => hmac_sha1(secret, &msg)?,
        TotpAlgorithm::Sha256 => hmac_sha256(secret, &msg)?,
        TotpAlgorithm::Sha512 => hmac_sha512(secret, &msg)?,
    };

    // Dynamic truncation (RFC 4226 section 5.3).
    let offset = usize::from(hash[hash.len() - 1] & 0x0f);
    let binary = (u32::from(hash[offset]) & 0x7f) << 24
        | u32::from(hash[offset + 1]) << 16
        | u32::from(hash[offset + 2]) << 8
        | u32::from(hash[offset + 3]);
    let modulus = 10u32.pow(u32::from(params.digits));
    let code = binary % modulus;

    Ok(format!("{code:0width$}", width = params.digits as usize))
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut mac = <HmacSha1 as Mac012>::new_from_slice(key)
        .context("invalid TOTP key")?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut mac = <HmacSha256 as KeyInit013>::new_from_slice(key)
        .context("invalid TOTP key")?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut mac = <HmacSha512 as KeyInit013>::new_from_slice(key)
        .context("invalid TOTP key")?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Decode the CLI-provided secret.  By default this tries RFC 4648 base32
/// (what TOTP provisioning URLs and authenticator apps use); if the input
/// clearly cannot be base32 it is treated as raw bytes.  `force_raw` skips
/// base32 for inputs that happen to look like base32.
pub fn decode_secret(input: &str, force_raw: bool) -> anyhow::Result<Vec<u8>> {
    if force_raw {
        return Ok(input.as_bytes().to_vec());
    }
    if looks_like_base32(input) {
        decode_base32(input)
    } else {
        Ok(input.as_bytes().to_vec())
    }
}

fn looks_like_base32(input: &str) -> bool {
    let mut has_data = false;
    input.chars().all(|c| {
        if c.is_ascii_whitespace() {
            return true;
        }
        has_data = true;
        c == '='
            || matches!(
                c.to_ascii_uppercase(),
                'A'..='Z' | '2'..='7'
            )
    }) && has_data
}

/// RFC 4648 base32 decoding.  Whitespace is ignored and lowercase is
/// accepted; `=` padding may be omitted.
pub fn decode_base32(input: &str) -> anyhow::Result<Vec<u8>> {
    let normalized: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let chars = normalized.as_bytes();
    if chars.is_empty() {
        bail!("base32 secret is empty");
    }

    let pad_start =
        chars.iter().position(|c| *c == b'=').unwrap_or(chars.len());
    if chars[pad_start..].iter().any(|c| *c != b'=') {
        bail!("invalid base32 padding");
    }
    let data = &chars[..pad_start];
    if data.is_empty() {
        bail!("base32 secret has no data");
    }
    if matches!(data.len() % 8, 1 | 3 | 6) {
        bail!("invalid base32 length {}", data.len());
    }

    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in data {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => bail!("invalid base32 character {:?}", c as char),
        };
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 && (acc & ((1u32 << bits) - 1)) != 0 {
        bail!("non-canonical base32 encoding");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_SECRET: &[u8] = b"12345678901234567890";
    const SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SECRET: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    struct Vector {
        time: u64,
        sha1: &'static str,
        sha256: &'static str,
        sha512: &'static str,
    }

    // RFC 6238 Appendix B, with the RFC's 8-digit outputs.
    const VECTORS: &[Vector] = &[
        Vector {
            time: 59,
            sha1: "94287082",
            sha256: "46119246",
            sha512: "90693936",
        },
        Vector {
            time: 1_111_111_109,
            sha1: "07081804",
            sha256: "68084774",
            sha512: "25091201",
        },
        Vector {
            time: 1_111_111_111,
            sha1: "14050471",
            sha256: "67062674",
            sha512: "99943326",
        },
        Vector {
            time: 1_234_567_890,
            sha1: "89005924",
            sha256: "91819424",
            sha512: "93441116",
        },
        Vector {
            time: 2_000_000_000,
            sha1: "69279037",
            sha256: "90698825",
            sha512: "38618901",
        },
        Vector {
            time: 20_000_000_000,
            sha1: "65353130",
            sha256: "77737706",
            sha512: "47863826",
        },
    ];

    #[test]
    fn test_rfc6238_vectors() {
        for v in VECTORS {
            let params = TotpParams {
                algorithm: TotpAlgorithm::Sha1,
                digits: 8,
                period: 30,
            };
            assert_eq!(
                generate_totp(SHA1_SECRET, &params, v.time).unwrap(),
                v.sha1
            );

            let params = TotpParams {
                algorithm: TotpAlgorithm::Sha256,
                digits: 8,
                period: 30,
            };
            assert_eq!(
                generate_totp(SHA256_SECRET, &params, v.time).unwrap(),
                v.sha256
            );

            let params = TotpParams {
                algorithm: TotpAlgorithm::Sha512,
                digits: 8,
                period: 30,
            };
            assert_eq!(
                generate_totp(SHA512_SECRET, &params, v.time).unwrap(),
                v.sha512
            );
        }
    }

    #[test]
    fn test_default_six_digits() {
        let params = TotpParams {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        };
        // Known 6-digit SHA-1 value for the RFC secret at time 59.
        assert_eq!(generate_totp(SHA1_SECRET, &params, 59).unwrap(), "287082");
    }

    #[test]
    fn test_base32_decode() {
        assert_eq!(decode_base32("JBSWY3DPEE").unwrap(), b"Hello!");
        assert_eq!(decode_base32("jbswy3dpee").unwrap(), b"Hello!");
        assert_eq!(decode_base32("JBSWY3D PEE").unwrap(), b"Hello!");
        assert_eq!(
            decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
    }

    #[test]
    fn test_base32_invalid() {
        assert!(decode_base32("").is_err());
        assert!(decode_base32("A").is_err());
        assert!(decode_base32("ABC").is_err());
        assert!(decode_base32("A=======").is_err());
        assert!(decode_base32("A!B").is_err());
    }

    #[test]
    fn test_decode_secret_fallback_and_raw() {
        // Base32 input decodes.
        assert_eq!(decode_secret("JBSWY3DPEE", false).unwrap(), b"Hello!");
        // Non-base32 input falls back to raw bytes.
        assert_eq!(
            decode_secret("12345678901234567890", false).unwrap(),
            b"12345678901234567890"
        );
        // Base32-looking input with a typo errors instead of being stored
        // as raw bytes.
        assert!(decode_secret("ABC", false).is_err());
        // --raw forces raw bytes even for valid base32.
        assert_eq!(decode_secret("JBSWY3DPEE", true).unwrap(), b"JBSWY3DPEE");
    }

    #[test]
    fn test_entry_roundtrip() {
        let params = TotpParams {
            algorithm: TotpAlgorithm::Sha512,
            digits: 7,
            period: 60,
        };
        let encoded = encode_entry(&params, b"secret").unwrap();
        let (decoded, secret) = decode_entry(&encoded).unwrap();
        assert_eq!(decoded, params);
        assert_eq!(secret, b"secret");
    }
}
