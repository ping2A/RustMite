//! Operator console authentication (Mobipwn-style).
//!
//! File-backed users + hashed sessions + per-user TOTP / WebAuthn MFA.
//! Auth is **required by default** (`RUSTMITE_REQUIRE_AUTH`, default on).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::webauthn::{self, StoredCredential};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::engine::general_purpose::STANDARD as STANDARD_B64;
use base64::Engine;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use totp_lite::{totp_custom, Sha1};
use tracing::info;
use uuid::Uuid;

const SESSION_TTL_SECS: u64 = 7 * 24 * 3600;
const MFA_CHALLENGE_TTL_SECS: u64 = 5 * 60;
const WEBAUTHN_TIMEOUT_MS: u32 = 120_000;
const ISSUER: &str = "RustMite";
pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Analyst,
    Viewer,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Analyst => "analyst",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "admin" => Some(Self::Admin),
            "analyst" => Some(Self::Analyst),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UserRecord {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub totp_enabled: bool,
    pub webauthn_enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub webauthn_credentials: Vec<webauthn::CredentialPublic>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UserRow {
    id: Uuid,
    username: String,
    password_hash: String,
    role: String,
    #[serde(default)]
    totp_secret: Option<String>,
    #[serde(default)]
    totp_enabled: bool,
    #[serde(default)]
    webauthn_credentials: Vec<StoredCredential>,
    created_at: u64,
    #[serde(default)]
    last_login_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionRow {
    user_id: Uuid,
    token_hash: String,
    mfa_verified: bool,
    expires_at: u64,
    #[serde(default)]
    last_seen_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MfaChallenge {
    id: Uuid,
    user_id: Uuid,
    expires_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AuthFile {
    users: Vec<UserRow>,
    #[serde(default)]
    sessions: Vec<SessionRow>,
    #[serde(default)]
    mfa_challenges: Vec<MfaChallenge>,
}

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user_id: Uuid,
    pub username: String,
    pub role: Role,
}

#[derive(Clone, Debug)]
struct PendingWebauthn {
    user_id: Uuid,
    challenge: Vec<u8>,
    origin: String,
    rp_id: String,
    register: bool,
    expires_at: u64,
}

#[derive(Clone)]
pub struct OperatorAuth {
    inner: Arc<RwLock<AuthFile>>,
    pending_webauthn: Arc<RwLock<HashMap<Uuid, PendingWebauthn>>>,
    path: PathBuf,
    pub require_auth: bool,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    format!("{:x}", h.finalize())
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .and_then(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .ok()
        })
        .is_some()
}

/// Self-service / admin-set password rules (bootstrap `admin`/`admin` is exempt).
pub fn password_policy(username: &str, password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    if password.chars().any(|c| c.is_control()) {
        return Err("password must not contain control characters".into());
    }
    if password.eq_ignore_ascii_case(username.trim()) {
        return Err("password must not match username".into());
    }
    let lower = password.to_ascii_lowercase();
    const BANNED: &[&str] = &[
        "password",
        "password1234",
        "admin",
        "adminadmin12",
        "rustmite",
        "changemechangeme",
        "123456789012",
        "qwertyuiopas",
    ];
    if BANNED.contains(&lower.as_str()) {
        return Err("password is too common".into());
    }
    Ok(())
}

fn generate_totp_secret() -> String {
    let bytes: [u8; 20] = rand::random();
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}

fn decode_totp_secret(secret: &str) -> Option<Vec<u8>> {
    let normalized = secret.trim().replace(' ', "").to_uppercase();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &normalized))
}

pub fn verify_totp(secret: &str, code: &str) -> bool {
    let Some(key) = decode_totp_secret(secret) else {
        return false;
    };
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let now = now_secs() as i64;
    for step in -1_i64..=1 {
        let ts = (now + step * 30).max(0) as u64;
        let expected = totp_custom::<Sha1>(30, 6, &key, ts);
        if expected == trimmed {
            return true;
        }
    }
    false
}

pub fn totp_uri(secret: &str, username: &str) -> String {
    let label = urlencoding::encode(&format!("{ISSUER}:{username}")).into_owned();
    let issuer_q = urlencoding::encode(ISSUER).into_owned();
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer_q}&algorithm=SHA1&digits=6&period=30"
    )
}

fn user_to_record(u: &UserRow) -> UserRecord {
    UserRecord {
        id: u.id,
        username: u.username.clone(),
        role: u.role.clone(),
        totp_enabled: u.totp_enabled,
        webauthn_enabled: !u.webauthn_credentials.is_empty(),
        webauthn_credentials: u.webauthn_credentials.iter().map(|c| c.to_public()).collect(),
        created_at: u.created_at,
    }
}

impl OperatorAuth {
    pub fn open(path: impl Into<PathBuf>, require_auth: bool) -> anyhow::Result<Self> {
        let path = path.into();
        let file = if path.is_file() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            AuthFile::default()
        };
        Ok(Self {
            inner: Arc::new(RwLock::new(file)),
            pending_webauthn: Arc::new(RwLock::new(HashMap::new())),
            path,
            require_auth,
        })
    }

    pub fn default_path() -> PathBuf {
        std::env::var_os("RUSTMITE_AUTH_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".dev/auth.json"))
    }

    async fn persist(&self, file: &AuthFile) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(file)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub async fn ensure_bootstrap_admin(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        let mut guard = self.inner.write().await;
        if !guard.users.is_empty() {
            return Ok(());
        }
        let hash = hash_password(password)?;
        let now = now_secs();
        guard.users.push(UserRow {
            id: Uuid::now_v7(),
            username: username.trim().to_string(),
            password_hash: hash,
            role: Role::Admin.as_str().into(),
            totp_secret: None,
            totp_enabled: false,
            webauthn_credentials: Vec::new(),
            created_at: now,
            last_login_at: None,
        });
        self.persist(&guard).await?;
        info!(username, "bootstrap admin user created");
        Ok(())
    }

    fn gc(file: &mut AuthFile) {
        let now = now_secs();
        file.sessions.retain(|s| s.expires_at > now);
        file.mfa_challenges.retain(|c| c.expires_at > now);
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Option<UserRowPublic>> {
        let guard = self.inner.read().await;
        let Some(user) = guard
            .users
            .iter()
            .find(|u| u.username.eq_ignore_ascii_case(username.trim()))
        else {
            return Ok(None);
        };
        if !verify_password(password, &user.password_hash) {
            return Ok(None);
        }
        Ok(Some(UserRowPublic::from_row(user)))
    }

    pub fn user_needs_mfa(user: &UserRowPublic) -> bool {
        user.totp_enabled || !user.webauthn_credentials.is_empty()
    }

    pub fn user_mfa_methods(user: &UserRowPublic) -> Vec<&'static str> {
        let mut m = Vec::new();
        if user.totp_enabled {
            m.push("totp");
        }
        if !user.webauthn_credentials.is_empty() {
            m.push("webauthn");
        }
        m
    }

    pub async fn create_mfa_challenge(&self, user_id: Uuid) -> anyhow::Result<Uuid> {
        let mut guard = self.inner.write().await;
        Self::gc(&mut guard);
        let id = Uuid::now_v7();
        guard.mfa_challenges.push(MfaChallenge {
            id,
            user_id,
            expires_at: now_secs() + MFA_CHALLENGE_TTL_SECS,
        });
        self.persist(&guard).await?;
        Ok(id)
    }

    pub async fn consume_mfa_challenge(
        &self,
        challenge_id: Uuid,
    ) -> anyhow::Result<Option<UserRowPublic>> {
        let mut guard = self.inner.write().await;
        Self::gc(&mut guard);
        let idx = guard
            .mfa_challenges
            .iter()
            .position(|c| c.id == challenge_id && c.expires_at > now_secs());
        let Some(idx) = idx else {
            return Ok(None);
        };
        let ch = guard.mfa_challenges.remove(idx);
        let user = guard.users.iter().find(|u| u.id == ch.user_id).cloned();
        self.persist(&guard).await?;
        Ok(user.map(|u| UserRowPublic::from_row(&u)))
    }

    pub async fn create_session(
        &self,
        user: &UserRowPublic,
        mfa_verified: bool,
    ) -> anyhow::Result<String> {
        let token = format!("{:x}{:x}", rand::random::<u128>(), rand::random::<u128>());
        let token_hash = hash_token(&token);
        let mut guard = self.inner.write().await;
        Self::gc(&mut guard);
        let now = now_secs();
        guard.sessions.push(SessionRow {
            user_id: user.id,
            token_hash,
            mfa_verified,
            expires_at: now + SESSION_TTL_SECS,
            last_seen_at: now,
        });
        if let Some(u) = guard.users.iter_mut().find(|u| u.id == user.id) {
            u.last_login_at = Some(now);
        }
        self.persist(&guard).await?;
        Ok(token)
    }

    pub async fn verify_session(&self, token: &str) -> anyhow::Result<Option<AuthContext>> {
        let token_hash = hash_token(token);
        let mut guard = self.inner.write().await;
        Self::gc(&mut guard);
        let now = now_secs();
        let session_user = {
            let Some(session) = guard
                .sessions
                .iter_mut()
                .find(|s| s.token_hash == token_hash && s.expires_at > now)
            else {
                return Ok(None);
            };
            if !session.mfa_verified {
                return Ok(None);
            }
            session.last_seen_at = now;
            session.user_id
        };
        let Some(user) = guard.users.iter().find(|u| u.id == session_user).cloned() else {
            return Ok(None);
        };
        let role = Role::parse(&user.role).unwrap_or(Role::Viewer);
        let _ = self.persist(&guard).await;
        Ok(Some(AuthContext {
            user_id: user.id,
            username: user.username,
            role,
        }))
    }

    pub async fn delete_session(&self, token: &str) -> anyhow::Result<()> {
        let token_hash = hash_token(token);
        let mut guard = self.inner.write().await;
        guard.sessions.retain(|s| s.token_hash != token_hash);
        self.persist(&guard).await?;
        Ok(())
    }

    pub async fn get_user(&self, id: Uuid) -> Option<UserRecord> {
        let guard = self.inner.read().await;
        guard.users.iter().find(|u| u.id == id).map(user_to_record)
    }

    pub async fn list_users(&self) -> Vec<UserRecord> {
        let guard = self.inner.read().await;
        let mut out: Vec<_> = guard.users.iter().map(user_to_record).collect();
        out.sort_by(|a, b| a.username.cmp(&b.username));
        out
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
    ) -> anyhow::Result<UserRecord> {
        let username = username.trim();
        if username.is_empty() {
            anyhow::bail!("username required");
        }
        password_policy(username, password).map_err(|e| anyhow::anyhow!("{e}"))?;
        let role = Role::parse(role).ok_or_else(|| anyhow::anyhow!("role must be admin, analyst, or viewer"))?;
        let mut guard = self.inner.write().await;
        if guard
            .users
            .iter()
            .any(|u| u.username.eq_ignore_ascii_case(username))
        {
            anyhow::bail!("username already taken");
        }
        let hash = hash_password(password)?;
        let row = UserRow {
            id: Uuid::now_v7(),
            username: username.to_string(),
            password_hash: hash,
            role: role.as_str().into(),
            totp_secret: None,
            totp_enabled: false,
            webauthn_credentials: Vec::new(),
            created_at: now_secs(),
            last_login_at: None,
        };
        let rec = user_to_record(&row);
        guard.users.push(row);
        self.persist(&guard).await?;
        Ok(rec)
    }

    pub async fn update_user(
        &self,
        id: Uuid,
        role: Option<&str>,
        password: Option<&str>,
    ) -> anyhow::Result<Option<UserRecord>> {
        let mut guard = self.inner.write().await;
        let Some(idx) = guard.users.iter().position(|u| u.id == id) else {
            return Ok(None);
        };
        if let Some(r) = role {
            let next = Role::parse(r).ok_or_else(|| anyhow::anyhow!("invalid role"))?;
            if guard.users[idx].role == "admin" && next != Role::Admin {
                let admins = guard.users.iter().filter(|u| u.role == "admin").count();
                if admins <= 1 {
                    anyhow::bail!("cannot demote the last admin");
                }
            }
            guard.users[idx].role = next.as_str().into();
        }
        if let Some(pw) = password {
            password_policy(&guard.users[idx].username, pw).map_err(|e| anyhow::anyhow!("{e}"))?;
            guard.users[idx].password_hash = hash_password(pw)?;
            guard.sessions.retain(|s| s.user_id != id);
        }
        let rec = user_to_record(&guard.users[idx]);
        self.persist(&guard).await?;
        Ok(Some(rec))
    }

    pub async fn delete_user(&self, id: Uuid) -> anyhow::Result<bool> {
        let mut guard = self.inner.write().await;
        let Some(idx) = guard.users.iter().position(|u| u.id == id) else {
            return Ok(false);
        };
        if guard.users[idx].role == "admin" {
            let admins = guard.users.iter().filter(|u| u.role == "admin").count();
            if admins <= 1 {
                anyhow::bail!("cannot delete the last admin");
            }
        }
        guard.users.remove(idx);
        guard.sessions.retain(|s| s.user_id != id);
        guard.mfa_challenges.retain(|c| c.user_id != id);
        self.persist(&guard).await?;
        Ok(true)
    }

    /// Change own password: current password required; other sessions dropped.
    pub async fn change_password(
        &self,
        user_id: Uuid,
        current: &str,
        new: &str,
        keep_session_token: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut guard = self.inner.write().await;
        let Some(idx) = guard.users.iter().position(|u| u.id == user_id) else {
            anyhow::bail!("user not found");
        };
        if !verify_password(current, &guard.users[idx].password_hash) {
            anyhow::bail!("current password is incorrect");
        }
        if current == new {
            anyhow::bail!("new password must be different from the current password");
        }
        password_policy(&guard.users[idx].username, new).map_err(|e| anyhow::anyhow!("{e}"))?;
        guard.users[idx].password_hash = hash_password(new)?;
        let keep = keep_session_token.map(hash_token);
        guard.sessions.retain(|s| {
            if s.user_id != user_id {
                return true;
            }
            keep.as_ref().map(|h| s.token_hash == *h).unwrap_or(false)
        });
        self.persist(&guard).await?;
        Ok(())
    }

    pub async fn peek_mfa_challenge(&self, challenge_id: Uuid) -> Option<Uuid> {
        let mut pending = self.pending_webauthn.write().await;
        Self::gc_pending(&mut pending);
        drop(pending);
        let mut guard = self.inner.write().await;
        Self::gc(&mut guard);
        let now = now_secs();
        guard
            .mfa_challenges
            .iter()
            .find(|c| c.id == challenge_id && c.expires_at > now)
            .map(|c| c.user_id)
    }

    /// Verify TOTP without consuming the challenge until the code is valid.
    pub async fn verify_mfa_totp(
        &self,
        challenge_id: Uuid,
        code: &str,
    ) -> anyhow::Result<Option<UserRowPublic>> {
        let mut guard = self.inner.write().await;
        Self::gc(&mut guard);
        let now = now_secs();
        let Some(pos) = guard
            .mfa_challenges
            .iter()
            .position(|c| c.id == challenge_id && c.expires_at > now)
        else {
            return Ok(None);
        };
        let user_id = guard.mfa_challenges[pos].user_id;
        let Some(user) = guard.users.iter().find(|u| u.id == user_id).cloned() else {
            return Ok(None);
        };
        if !user.totp_enabled {
            anyhow::bail!("authenticator app is not enabled for this account");
        }
        let Some(secret) = user.totp_secret.as_deref() else {
            return Ok(None);
        };
        if !verify_totp(secret, code) {
            anyhow::bail!("invalid code");
        }
        guard.mfa_challenges.remove(pos);
        self.persist(&guard).await?;
        Ok(Some(UserRowPublic::from_row(&user)))
    }

    fn gc_pending(map: &mut HashMap<Uuid, PendingWebauthn>) {
        let now = now_secs();
        map.retain(|_, p| p.expires_at > now);
    }

    fn new_webauthn_challenge() -> Vec<u8> {
        let a = rand::random::<u128>().to_be_bytes();
        let b = rand::random::<u128>().to_be_bytes();
        let mut v = Vec::with_capacity(32);
        v.extend_from_slice(&a);
        v.extend_from_slice(&b);
        v
    }

    pub async fn webauthn_register_begin(
        &self,
        user_id: Uuid,
        rp_id: &str,
        origin: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let guard = self.inner.read().await;
        let user = guard
            .users
            .iter()
            .find(|u| u.id == user_id)
            .ok_or_else(|| anyhow::anyhow!("user not found"))?;
        let exclude: Vec<serde_json::Value> = user
            .webauthn_credentials
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type": "public-key",
                    "id": c.id,
                    "transports": ["usb", "nfc", "ble", "hybrid"]
                })
            })
            .collect();
        let challenge = Self::new_webauthn_challenge();
        let user_handle = user.id.as_bytes().to_vec();
        let opts = serde_json::json!({
            "publicKey": {
                "rp": { "name": ISSUER, "id": rp_id },
                "user": {
                    "id": webauthn::b64url_encode(&user_handle),
                    "name": user.username,
                    "displayName": user.username,
                },
                "challenge": webauthn::b64url_encode(&challenge),
                "pubKeyCredParams": [{ "type": "public-key", "alg": webauthn::ES256_ALG }],
                "timeout": WEBAUTHN_TIMEOUT_MS,
                "attestation": "none",
                "authenticatorSelection": {
                    "residentKey": "preferred",
                    "userVerification": "preferred",
                    "authenticatorAttachment": "cross-platform"
                },
                "hints": ["security-key"],
                "excludeCredentials": exclude,
            }
        });
        drop(guard);
        let mut pending = self.pending_webauthn.write().await;
        Self::gc_pending(&mut pending);
        pending.insert(
            user_id,
            PendingWebauthn {
                user_id,
                challenge,
                origin: origin.to_string(),
                rp_id: rp_id.to_string(),
                register: true,
                expires_at: now_secs() + MFA_CHALLENGE_TTL_SECS,
            },
        );
        Ok(opts)
    }

    pub async fn webauthn_register_finish(
        &self,
        user_id: Uuid,
        attestation_object_b64: &str,
        client_data_json_b64: &str,
        raw_id_b64: &str,
        name: Option<&str>,
    ) -> anyhow::Result<UserRecord> {
        let pending = {
            let mut map = self.pending_webauthn.write().await;
            Self::gc_pending(&mut map);
            map.remove(&user_id)
                .ok_or_else(|| anyhow::anyhow!("registration challenge expired — try again"))?
        };
        if !pending.register || pending.user_id != user_id {
            anyhow::bail!("registration challenge expired — try again");
        }
        let client_raw = webauthn::b64url_decode(client_data_json_b64)?;
        let client = webauthn::parse_client_data(&client_raw)?;
        webauthn::verify_client_data(&client, "webauthn.create", &pending.challenge, &pending.origin)?;
        let att = webauthn::b64url_decode(attestation_object_b64)?;
        let auth_raw = webauthn::parse_attestation_auth_data(&att)?;
        let auth = webauthn::parse_auth_data(&auth_raw, true)?;
        webauthn::verify_rp_id(&auth, &pending.rp_id)?;
        let cred_id = auth
            .credential_id
            .ok_or_else(|| anyhow::anyhow!("missing credential id"))?;
        let pk = auth
            .public_key_sec1
            .ok_or_else(|| anyhow::anyhow!("missing public key"))?;
        let sent_id = webauthn::b64url_decode(raw_id_b64)?;
        if sent_id != cred_id {
            anyhow::bail!("credential id mismatch");
        }
        let id_str = webauthn::b64url_encode(&cred_id);
        let label = name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("YubiKey")
            .chars()
            .take(64)
            .collect::<String>();
        let mut guard = self.inner.write().await;
        let user = guard
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or_else(|| anyhow::anyhow!("user not found"))?;
        if user.webauthn_credentials.iter().any(|c| c.id == id_str) {
            anyhow::bail!("this security key is already registered");
        }
        user.webauthn_credentials.push(StoredCredential {
            id: id_str,
            name: label,
            public_key: STANDARD_B64.encode(&pk),
            sign_count: auth.sign_count,
            created_at: now_secs(),
        });
        let rec = user_to_record(user);
        self.persist(&guard).await?;
        Ok(rec)
    }

    pub async fn webauthn_login_begin(
        &self,
        mfa_challenge_id: Uuid,
        rp_id: &str,
        origin: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let user_id = self
            .peek_mfa_challenge(mfa_challenge_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("challenge expired"))?;
        let guard = self.inner.read().await;
        let user = guard
            .users
            .iter()
            .find(|u| u.id == user_id)
            .ok_or_else(|| anyhow::anyhow!("user not found"))?;
        if user.webauthn_credentials.is_empty() {
            anyhow::bail!("no security key registered");
        }
        let allow: Vec<serde_json::Value> = user
            .webauthn_credentials
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type": "public-key",
                    "id": c.id,
                    "transports": ["usb", "nfc", "ble", "hybrid"]
                })
            })
            .collect();
        let challenge = Self::new_webauthn_challenge();
        let opts = serde_json::json!({
            "publicKey": {
                "challenge": webauthn::b64url_encode(&challenge),
                "timeout": WEBAUTHN_TIMEOUT_MS,
                "rpId": rp_id,
                "allowCredentials": allow,
                "userVerification": "preferred",
                "hints": ["security-key"],
            }
        });
        drop(guard);
        let mut pending = self.pending_webauthn.write().await;
        Self::gc_pending(&mut pending);
        pending.insert(
            mfa_challenge_id,
            PendingWebauthn {
                user_id,
                challenge,
                origin: origin.to_string(),
                rp_id: rp_id.to_string(),
                register: false,
                expires_at: now_secs() + MFA_CHALLENGE_TTL_SECS,
            },
        );
        Ok(opts)
    }

    pub async fn webauthn_login_finish(
        &self,
        mfa_challenge_id: Uuid,
        raw_id_b64: &str,
        authenticator_data_b64: &str,
        client_data_json_b64: &str,
        signature_b64: &str,
    ) -> anyhow::Result<UserRowPublic> {
        let pending = {
            let mut map = self.pending_webauthn.write().await;
            Self::gc_pending(&mut map);
            map.remove(&mfa_challenge_id)
                .ok_or_else(|| anyhow::anyhow!("security key challenge expired"))?
        };
        if pending.register {
            anyhow::bail!("security key challenge expired");
        }
        let client_raw = webauthn::b64url_decode(client_data_json_b64)?;
        let client = webauthn::parse_client_data(&client_raw)?;
        webauthn::verify_client_data(&client, "webauthn.get", &pending.challenge, &pending.origin)?;
        let auth_raw = webauthn::b64url_decode(authenticator_data_b64)?;
        let auth = webauthn::parse_auth_data(&auth_raw, false)?;
        webauthn::verify_rp_id(&auth, &pending.rp_id)?;
        let cred_id = webauthn::b64url_decode(raw_id_b64)?;
        let id_str = webauthn::b64url_encode(&cred_id);
        let sig = webauthn::b64url_decode(signature_b64)?;
        let mut guard = self.inner.write().await;
        Self::gc(&mut guard);
        let now = now_secs();
        let Some(ch_pos) = guard
            .mfa_challenges
            .iter()
            .position(|c| c.id == mfa_challenge_id && c.expires_at > now && c.user_id == pending.user_id)
        else {
            anyhow::bail!("challenge expired");
        };
        let Some(user_idx) = guard.users.iter().position(|u| u.id == pending.user_id) else {
            anyhow::bail!("user not found");
        };
        let cred_idx = guard.users[user_idx]
            .webauthn_credentials
            .iter()
            .position(|c| c.id == id_str)
            .ok_or_else(|| anyhow::anyhow!("unknown security key"))?;
        let pk = STANDARD_B64
            .decode(&guard.users[user_idx].webauthn_credentials[cred_idx].public_key)
            .map_err(|_| anyhow::anyhow!("corrupt stored public key"))?;
        webauthn::verify_assertion(&pk, &auth_raw, &client_raw, &sig)?;
        let stored_count = guard.users[user_idx].webauthn_credentials[cred_idx].sign_count;
        let next = webauthn::check_sign_count(stored_count, auth.sign_count)?;
        guard.users[user_idx].webauthn_credentials[cred_idx].sign_count = next;
        guard.mfa_challenges.remove(ch_pos);
        let rec = UserRowPublic::from_row(&guard.users[user_idx]);
        self.persist(&guard).await?;
        Ok(rec)
    }

    pub async fn delete_webauthn_credential(
        &self,
        user_id: Uuid,
        cred_id: &str,
    ) -> anyhow::Result<bool> {
        let mut guard = self.inner.write().await;
        let Some(user) = guard.users.iter_mut().find(|u| u.id == user_id) else {
            return Ok(false);
        };
        let before = user.webauthn_credentials.len();
        user.webauthn_credentials.retain(|c| c.id != cred_id);
        let ok = user.webauthn_credentials.len() != before;
        self.persist(&guard).await?;
        Ok(ok)
    }

    pub async fn setup_totp(&self, user_id: Uuid) -> anyhow::Result<(String, String)> {
        let mut guard = self.inner.write().await;
        let user = guard
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or_else(|| anyhow::anyhow!("user not found"))?;
        let secret = generate_totp_secret();
        user.totp_secret = Some(secret.clone());
        user.totp_enabled = false;
        let uri = totp_uri(&secret, &user.username);
        self.persist(&guard).await?;
        Ok((secret, uri))
    }

    pub async fn enable_totp(&self, user_id: Uuid, code: &str) -> anyhow::Result<bool> {
        let mut guard = self.inner.write().await;
        let user = guard
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or_else(|| anyhow::anyhow!("user not found"))?;
        let Some(secret) = user.totp_secret.clone() else {
            return Ok(false);
        };
        if !verify_totp(&secret, code) {
            return Ok(false);
        }
        user.totp_enabled = true;
        self.persist(&guard).await?;
        Ok(true)
    }

    pub async fn disable_totp(&self, user_id: Uuid) -> anyhow::Result<()> {
        let mut guard = self.inner.write().await;
        if let Some(user) = guard.users.iter_mut().find(|u| u.id == user_id) {
            user.totp_enabled = false;
            user.totp_secret = None;
        }
        self.persist(&guard).await?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Public view of a user row used across auth handlers (includes TOTP secret for verify).
#[derive(Clone, Debug)]
pub struct UserRowPublic {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub totp_enabled: bool,
    pub totp_secret: Option<String>,
    pub webauthn_credentials: Vec<StoredCredential>,
    pub created_at: u64,
}

impl UserRowPublic {
    fn from_row(u: &UserRow) -> Self {
        Self {
            id: u.id,
            username: u.username.clone(),
            role: u.role.clone(),
            totp_enabled: u.totp_enabled,
            totp_secret: u.totp_secret.clone(),
            webauthn_credentials: u.webauthn_credentials.clone(),
            created_at: u.created_at,
        }
    }

    pub fn to_record(&self) -> UserRecord {
        UserRecord {
            id: self.id,
            username: self.username.clone(),
            role: self.role.clone(),
            totp_enabled: self.totp_enabled,
            webauthn_enabled: !self.webauthn_credentials.is_empty(),
            webauthn_credentials: self.webauthn_credentials.iter().map(|c| c.to_public()).collect(),
            created_at: self.created_at,
        }
    }

    pub fn verify_totp(&self, code: &str) -> bool {
        self.totp_secret
            .as_deref()
            .map(|s| verify_totp(s, code))
            .unwrap_or(false)
    }
}

/// Env helper: auth required unless explicitly disabled.
pub fn require_auth_from_env() -> bool {
    match std::env::var("RUSTMITE_REQUIRE_AUTH") {
        Ok(v) => {
            let v = v.trim();
            !(v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("no"))
        }
        Err(_) => true,
    }
}

pub fn bootstrap_admin_from_env() -> (String, String) {
    let user = std::env::var("RUSTMITE_ADMIN_USER").unwrap_or_else(|_| "admin".into());
    let pass = std::env::var("RUSTMITE_ADMIN_PASSWORD").unwrap_or_else(|_| "admin".into());
    (user, pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn login_mfa_and_session_roundtrip() {
        let path = std::env::temp_dir().join(format!("rustmite-auth-test-{}.json", Uuid::new_v4()));
        let _ = std::fs::remove_file(&path);
        let auth = OperatorAuth::open(&path, true).unwrap();
        auth.ensure_bootstrap_admin("admin", "admin").await.unwrap();

        let user = auth.authenticate("admin", "admin").await.unwrap().unwrap();
        assert!(!user.totp_enabled);
        let token = auth.create_session(&user, true).await.unwrap();
        let ctx = auth.verify_session(&token).await.unwrap().unwrap();
        assert_eq!(ctx.username, "admin");
        assert!(ctx.role.is_admin());

        let (secret, uri) = auth.setup_totp(user.id).await.unwrap();
        assert!(uri.contains("otpauth://totp/"));
        let code = {
            let key = decode_totp_secret(&secret).unwrap();
            totp_custom::<Sha1>(30, 6, &key, now_secs())
        };
        assert!(auth.enable_totp(user.id, &code).await.unwrap());

        let user2 = auth.authenticate("admin", "admin").await.unwrap().unwrap();
        assert!(user2.totp_enabled);
        let challenge = auth.create_mfa_challenge(user2.id).await.unwrap();
        let challenged = auth.consume_mfa_challenge(challenge).await.unwrap().unwrap();
        let code_now = {
            let key = decode_totp_secret(&secret).unwrap();
            totp_custom::<Sha1>(30, 6, &key, now_secs())
        };
        assert!(challenged.verify_totp(&code_now));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn password_hash_is_argon2() {
        let h = hash_password("secret").unwrap();
        assert!(h.starts_with("$argon2"));
        assert!(verify_password("secret", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn role_parse() {
        assert!(matches!(Role::parse("Admin"), Some(Role::Admin)));
        assert!(Role::parse("nope").is_none());
    }

    #[test]
    fn password_policy_rejects_short_and_common() {
        assert!(password_policy("alice", "short").is_err());
        assert!(password_policy("longusername", "longusername").is_err());
        assert!(password_policy("alice", "password1234").is_err());
        assert!(password_policy("alice", "correct-horse-battery").is_ok());
    }

    #[tokio::test]
    async fn change_password_requires_current_and_drops_other_sessions() {
        let path = std::env::temp_dir().join(format!("rustmite-pw-{}.json", Uuid::new_v4()));
        let _ = std::fs::remove_file(&path);
        let auth = OperatorAuth::open(&path, true).unwrap();
        auth.ensure_bootstrap_admin("admin", "admin").await.unwrap();
        let user = auth.authenticate("admin", "admin").await.unwrap().unwrap();
        let token_a = auth.create_session(&user, true).await.unwrap();
        let token_b = auth.create_session(&user, true).await.unwrap();
        auth.change_password(
            user.id,
            "admin",
            "correct-horse-battery",
            Some(&token_a),
        )
        .await
        .unwrap();
        assert!(auth.authenticate("admin", "admin").await.unwrap().is_none());
        assert!(auth
            .authenticate("admin", "correct-horse-battery")
            .await
            .unwrap()
            .is_some());
        assert!(auth.verify_session(&token_a).await.unwrap().is_some());
        assert!(auth.verify_session(&token_b).await.unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }
}
