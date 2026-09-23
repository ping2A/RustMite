use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyRecord {
    pub key_type: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Default)]
pub struct HostKeyPolicy {
    pub pinned: Vec<HostKeyRecord>,
    pub allow_tofu: bool,
}

impl HostKeyPolicy {
    pub fn check(&self, presented: &HostKeyRecord) -> Result<HostKeyAction, HostKeyReject> {
        if self.pinned.is_empty() {
            if self.allow_tofu {
                return Ok(HostKeyAction::PinNew(presented.clone()));
            }
            return Err(HostKeyReject::NoPin);
        }
        if self
            .pinned
            .iter()
            .any(|p| p.fingerprint == presented.fingerprint && p.key_type == presented.key_type)
        {
            return Ok(HostKeyAction::Accept);
        }
        Err(HostKeyReject::Changed {
            expected: self
                .pinned
                .first()
                .map(|p| p.fingerprint.clone())
                .unwrap_or_default(),
            got: presented.fingerprint.clone(),
        })
    }
}

#[derive(Clone, Debug)]
pub enum HostKeyAction {
    Accept,
    PinNew(HostKeyRecord),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyReject {
    NoPin,
    Changed { expected: String, got: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_changed_key() {
        let policy = HostKeyPolicy {
            pinned: vec![HostKeyRecord {
                key_type: "ssh-ed25519".into(),
                fingerprint: "AA".into(),
            }],
            allow_tofu: false,
        };
        let got = policy.check(&HostKeyRecord {
            key_type: "ssh-ed25519".into(),
            fingerprint: "BB".into(),
        });
        assert!(matches!(got, Err(HostKeyReject::Changed { .. })));
    }
}
