//! Noise XX handshake helpers for node ↔ control-plane identity.
//!
//! Pattern: Noise_XX_25519_ChaChaPoly_BLAKE2s — mutual authentication so each
//! client (node) presents a static key the server can fingerprint and pin.

use snow::{Builder, HandshakeState, TransportState};
use thiserror::Error;
use zeroize::Zeroize;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("noise: {0}")]
    Snow(String),
    #[error("noise handshake incomplete")]
    Incomplete,
    #[error("noise identity missing")]
    MissingIdentity,
}

#[derive(Clone)]
pub struct NoiseKeypair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl NoiseKeypair {
    pub fn generate() -> Result<Self, NoiseError> {
        let kp = Builder::new(NOISE_PATTERN.parse().map_err(|e| NoiseError::Snow(format!("{e}")))?)
            .generate_keypair()
            .map_err(|e| NoiseError::Snow(e.to_string()))?;
        let mut private = [0u8; 32];
        private.copy_from_slice(&kp.private);
        let mut public = [0u8; 32];
        public.copy_from_slice(&kp.public);
        Ok(Self { public, private })
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }
}

impl Drop for NoiseKeypair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

/// Server-side XX responder (control plane).
pub struct NoiseServerHandshake {
    state: HandshakeState,
}

impl NoiseServerHandshake {
    pub fn new(local: &NoiseKeypair) -> Result<Self, NoiseError> {
        let state = Builder::new(NOISE_PATTERN.parse().map_err(|e| NoiseError::Snow(format!("{e}")))?)
            .local_private_key(&local.private)
            .build_responder()
            .map_err(|e| NoiseError::Snow(e.to_string()))?;
        Ok(Self { state })
    }

    pub fn read_message(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
        self.state
            .read_message(input, output)
            .map_err(|e| NoiseError::Snow(e.to_string()))
    }

    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
        self.state
            .write_message(payload, output)
            .map_err(|e| NoiseError::Snow(e.to_string()))
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn into_transport(self) -> Result<(TransportState, [u8; 32]), NoiseError> {
        let remote = self
            .state
            .get_remote_static()
            .ok_or(NoiseError::MissingIdentity)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(remote);
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| NoiseError::Snow(e.to_string()))?;
        Ok((transport, id))
    }
}

/// Client-side XX initiator (node / probe relay).
pub struct NoiseClientHandshake {
    state: HandshakeState,
}

impl NoiseClientHandshake {
    pub fn new(local: &NoiseKeypair) -> Result<Self, NoiseError> {
        let state = Builder::new(NOISE_PATTERN.parse().map_err(|e| NoiseError::Snow(format!("{e}")))?)
            .local_private_key(&local.private)
            .build_initiator()
            .map_err(|e| NoiseError::Snow(e.to_string()))?;
        Ok(Self { state })
    }

    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
        self.state
            .write_message(payload, output)
            .map_err(|e| NoiseError::Snow(e.to_string()))
    }

    pub fn read_message(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, NoiseError> {
        self.state
            .read_message(input, output)
            .map_err(|e| NoiseError::Snow(e.to_string()))
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn into_transport(self) -> Result<(TransportState, [u8; 32]), NoiseError> {
        let remote = self
            .state
            .get_remote_static()
            .ok_or(NoiseError::MissingIdentity)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(remote);
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| NoiseError::Snow(e.to_string()))?;
        Ok((transport, id))
    }
}

/// Fingerprint used in settings / node registration (stable hex id).
pub fn identity_fingerprint(public: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let dig = Sha256::digest(public);
    format!("noise-xx:{}", hex::encode(&dig[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xx_handshake_exchanges_identities() {
        let server_kp = NoiseKeypair::generate().unwrap();
        let client_kp = NoiseKeypair::generate().unwrap();
        let mut server = NoiseServerHandshake::new(&server_kp).unwrap();
        let mut client = NoiseClientHandshake::new(&client_kp).unwrap();

        let mut buf_a = [0u8; 1024];
        let mut buf_b = [0u8; 1024];
        let mut buf_c = [0u8; 1024];

        // -> e
        let n = client.write_message(&[], &mut buf_a).unwrap();
        server.read_message(&buf_a[..n], &mut buf_b).unwrap();
        // <- e, ee, s, es
        let n = server.write_message(&[], &mut buf_b).unwrap();
        client.read_message(&buf_b[..n], &mut buf_c).unwrap();
        // -> s, se
        let n = client.write_message(&[], &mut buf_a).unwrap();
        server.read_message(&buf_a[..n], &mut buf_b).unwrap();

        assert!(client.is_handshake_finished());
        assert!(server.is_handshake_finished());
        let (_ct, server_sees_client) = server.into_transport().unwrap();
        let (_st, client_sees_server) = client.into_transport().unwrap();
        assert_eq!(server_sees_client, client_kp.public);
        assert_eq!(client_sees_server, server_kp.public);
    }
}
