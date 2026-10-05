//! WebAuthn / FIDO2 (YubiKey and other security keys) — ES256 only, pure Rust.

use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ciborium::value::{Integer, Value};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ES256_ALG: i32 = -7;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: String,
    pub name: String,
    /// Uncompressed SEC1 (0x04 || x || y), standard base64.
    pub public_key: String,
    pub sign_count: u32,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialPublic {
    pub id: String,
    pub name: String,
    pub created_at: u64,
}

impl StoredCredential {
    pub fn to_public(&self) -> CredentialPublic {
        CredentialPublic {
            id: self.id.clone(),
            name: self.name.clone(),
            created_at: self.created_at,
        }
    }
}

pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim();
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| {
            let mut padded = s.replace('-', "+").replace('_', "/");
            while padded.len() % 4 != 0 {
                padded.push('=');
            }
            STANDARD.decode(padded)
        })
        .map_err(|e| anyhow!("invalid base64url: {e}"))
}

pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

fn integer_i128(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => i128::try_from(*i).ok(),
        _ => None,
    }
}

fn map_get<'a>(map: &'a [(Value, Value)], key: i128) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| {
        if integer_i128(k) == Some(key) {
            Some(v)
        } else {
            None
        }
    })
}

fn bytes_of(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b.as_slice()),
        _ => None,
    }
}

/// Parse COSE_Key EC2 P-256 into uncompressed SEC1 bytes (65).
pub fn cose_ec2_p256_to_sec1(cose: &[u8]) -> anyhow::Result<Vec<u8>> {
    let val: Value = ciborium::from_reader(cose).context("COSE CBOR")?;
    let Value::Map(map) = val else {
        bail!("COSE key is not a map");
    };
    let kty = map_get(&map, 1).and_then(integer_i128);
    if kty != Some(2) {
        bail!("unsupported COSE kty (need EC2)");
    }
    if let Some(alg) = map_get(&map, 3).and_then(integer_i128) {
        if alg != i128::from(ES256_ALG) {
            bail!("unsupported COSE alg (need ES256)");
        }
    }
    let crv = map_get(&map, -1).and_then(integer_i128);
    if crv != Some(1) {
        bail!("unsupported COSE curve (need P-256)");
    }
    let x = map_get(&map, -2)
        .and_then(bytes_of)
        .ok_or_else(|| anyhow!("missing COSE x"))?;
    let y = map_get(&map, -3)
        .and_then(bytes_of)
        .ok_or_else(|| anyhow!("missing COSE y"))?;
    if x.len() != 32 || y.len() != 32 {
        bail!("invalid P-256 coordinate length");
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    Ok(sec1)
}

pub fn encode_cose_ec2_p256(x: &[u8], y: &[u8]) -> anyhow::Result<Vec<u8>> {
    if x.len() != 32 || y.len() != 32 {
        bail!("P-256 coordinates must be 32 bytes");
    }
    let map = vec![
        (Value::Integer(Integer::from(1)), Value::Integer(Integer::from(2))),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(ES256_ALG)),
        ),
        (Value::Integer(Integer::from(-1)), Value::Integer(Integer::from(1))),
        (Value::Integer(Integer::from(-2)), Value::Bytes(x.to_vec())),
        (Value::Integer(Integer::from(-3)), Value::Bytes(y.to_vec())),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out)?;
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct ClientData {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: String,
}

pub fn parse_client_data(json_bytes: &[u8]) -> anyhow::Result<ClientData> {
    serde_json::from_slice(json_bytes).context("clientDataJSON")
}

pub fn verify_client_data(
    data: &ClientData,
    expected_type: &str,
    challenge: &[u8],
    origin: &str,
) -> anyhow::Result<()> {
    if data.type_ != expected_type {
        bail!("unexpected webauthn type");
    }
    let got = b64url_decode(&data.challenge)?;
    if got != challenge {
        bail!("webauthn challenge mismatch");
    }
    if data.origin.trim_end_matches('/') != origin.trim_end_matches('/') {
        bail!("webauthn origin mismatch");
    }
    Ok(())
}

#[derive(Debug)]
pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub credential_id: Option<Vec<u8>>,
    pub public_key_sec1: Option<Vec<u8>>,
}

pub fn parse_auth_data(raw: &[u8], expect_attested: bool) -> anyhow::Result<AuthData> {
    if raw.len() < 37 {
        bail!("authenticatorData too short");
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&raw[0..32]);
    let flags = raw[32];
    let sign_count = u32::from_be_bytes(raw[33..37].try_into().unwrap());
    let attested = flags & 0x40 != 0;
    if expect_attested && !attested {
        bail!("attested credential data missing");
    }
    if !attested {
        return Ok(AuthData {
            rp_id_hash,
            flags,
            sign_count,
            credential_id: None,
            public_key_sec1: None,
        });
    }
    if raw.len() < 55 {
        bail!("attested authenticatorData too short");
    }
    let cred_len = u16::from_be_bytes(raw[53..55].try_into().unwrap()) as usize;
    let cred_start: usize = 55;
    let cred_end = cred_start
        .checked_add(cred_len)
        .ok_or_else(|| anyhow!("credential id overflow"))?;
    if raw.len() < cred_end {
        bail!("credential id truncated");
    }
    let credential_id = raw[cred_start..cred_end].to_vec();
    let cose = &raw[cred_end..];
    let public_key_sec1 = cose_ec2_p256_to_sec1(cose)?;
    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id: Some(credential_id),
        public_key_sec1: Some(public_key_sec1),
    })
}

pub fn parse_attestation_auth_data(attestation_object: &[u8]) -> anyhow::Result<Vec<u8>> {
    let val: Value = ciborium::from_reader(attestation_object).context("attestationObject")?;
    let Value::Map(map) = val else {
        bail!("attestationObject is not a map");
    };
    let auth = map.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == "authData" => bytes_of(v).map(|b| b.to_vec()),
        _ => None,
    });
    auth.ok_or_else(|| anyhow!("attestationObject missing authData"))
}

pub fn verify_rp_id(auth: &AuthData, rp_id: &str) -> anyhow::Result<()> {
    if auth.rp_id_hash != rp_id_hash(rp_id) {
        bail!("rpIdHash mismatch");
    }
    if auth.flags & 0x01 == 0 {
        bail!("user presence bit not set");
    }
    Ok(())
}

pub fn verify_assertion(
    public_key_sec1: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    let point = EncodedPoint::from_bytes(public_key_sec1).map_err(|_| anyhow!("invalid public key"))?;
    let key = VerifyingKey::from_encoded_point(&point).map_err(|_| anyhow!("invalid P-256 key"))?;
    let sig = Signature::from_der(signature)
        .or_else(|_| Signature::from_slice(signature))
        .map_err(|_| anyhow!("invalid assertion signature"))?;
    let client_hash = Sha256::digest(client_data_json);
    let mut msg = Vec::with_capacity(authenticator_data.len() + 32);
    msg.extend_from_slice(authenticator_data);
    msg.extend_from_slice(&client_hash);
    key.verify(&msg, &sig)
        .map_err(|_| anyhow!("security key signature invalid"))?;
    Ok(())
}

pub fn check_sign_count(stored: u32, observed: u32) -> anyhow::Result<u32> {
    if stored == 0 && observed == 0 {
        return Ok(0);
    }
    if observed <= stored {
        bail!("security key sign count did not increase");
    }
    Ok(observed)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebauthnRpConfig {
    /// Full origin the browser will send, e.g. `https://console.example`.
    #[serde(default)]
    pub origin: Option<String>,
    /// Relying-party ID (hostname). Defaults to the hostname of `origin`.
    #[serde(default)]
    pub rp_id: Option<String>,
}

impl WebauthnRpConfig {
    pub fn sanitized(self) -> Self {
        Self {
            origin: optional_trimmed(self.origin.as_deref()),
            rp_id: optional_trimmed(self.rp_id.as_deref()),
        }
    }
}

fn optional_trimmed(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .map(|s| s.trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn config_path() -> std::path::PathBuf {
    std::path::PathBuf::from(".dev/webauthn.json")
}

pub fn load_config() -> WebauthnRpConfig {
    let path = config_path();
    if path.is_file() {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<WebauthnRpConfig>(&raw) {
                return cfg.sanitized();
            }
        }
    }
    WebauthnRpConfig::default()
}

pub fn save_config(cfg: &WebauthnRpConfig) {
    let path = config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(raw) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(path, raw);
    }
}

/// Derive RP ID + origin from the browser Origin/Host headers, with optional server overrides.
pub fn rp_from_request(
    origin_header: Option<&str>,
    host: Option<&str>,
    forwarded_proto: Option<&str>,
    override_cfg: &WebauthnRpConfig,
) -> anyhow::Result<(String, String)> {
    if let Some(forced_origin) = override_cfg.origin.as_deref() {
        let origin = forced_origin.trim().trim_end_matches('/').to_string();
        let rp = override_cfg
            .rp_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| rp_id_from_origin(&origin));
        return Ok((rp, origin));
    }
    let origin = if let Some(o) = origin_header.filter(|s| !s.is_empty()) {
        o.trim().trim_end_matches('/').to_string()
    } else {
        let host = host.ok_or_else(|| anyhow!("missing Host/Origin for WebAuthn"))?;
        let proto = forwarded_proto
            .unwrap_or("https")
            .split(',')
            .next()
            .unwrap_or("https")
            .trim();
        format!("{proto}://{host}")
    };
    let rp = override_cfg
        .rp_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| rp_id_from_origin(&origin));
    Ok((rp, origin))
}

pub fn rp_id_from_origin(origin: &str) -> String {
    let rest = origin
        .split("://")
        .nth(1)
        .unwrap_or(origin);
    rest.split(':').next().unwrap_or(rest).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn cose_roundtrip() {
        let x = [1u8; 32];
        let y = [2u8; 32];
        let cose = encode_cose_ec2_p256(&x, &y).unwrap();
        let sec1 = cose_ec2_p256_to_sec1(&cose).unwrap();
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &x);
        assert_eq!(&sec1[33..], &y);
    }

    #[test]
    fn assertion_roundtrip() {
        let signing = SigningKey::random(&mut OsRng);
        let verifying = VerifyingKey::from(&signing);
        let sec1 = verifying.to_encoded_point(false).as_bytes().to_vec();
        let auth_data = vec![0u8; 37];
        let client = br#"{"type":"webauthn.get","challenge":"abc","origin":"https://localhost"}"#;
        let client_hash = Sha256::digest(client);
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&client_hash);
        let sig: Signature = signing.sign(&msg);
        verify_assertion(&sec1, &auth_data, client, &sig.to_der().as_bytes().to_vec()).unwrap();
        assert!(verify_assertion(&sec1, &auth_data, client, &[0u8; 64]).is_err());
    }

    #[test]
    fn origin_parse() {
        let (rp, origin) = rp_from_request(
            Some("https://console.example:8443"),
            None,
            None,
            &WebauthnRpConfig::default(),
        )
        .unwrap();
        assert_eq!(rp, "console.example");
        assert_eq!(origin, "https://console.example:8443");
        assert_eq!(rp_id_from_origin("https://127.0.0.1:18080"), "127.0.0.1");
    }

    #[test]
    fn origin_override_from_settings() {
        let cfg = WebauthnRpConfig {
            origin: Some("https://ids.example".into()),
            rp_id: Some("ids.example".into()),
        };
        let (rp, origin) = rp_from_request(Some("https://127.0.0.1:18080"), None, None, &cfg).unwrap();
        assert_eq!(rp, "ids.example");
        assert_eq!(origin, "https://ids.example");
    }
}
