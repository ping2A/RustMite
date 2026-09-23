use rustmite_proto::DeliveryMethod;

#[derive(Clone, Debug)]
pub struct DeliveryPlan {
    pub method: DeliveryMethod,
    pub encoder: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DeliveryOutcome {
    pub method: DeliveryMethod,
    pub encoder: Option<String>,
    pub bytes_transferred: u64,
    pub cleanup_ok: bool,
    pub fallback_reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct HostCapabilities {
    pub memfd_create: bool,
    pub exec_tmpfs: bool,
    pub sftp: bool,
    pub has_base64: bool,
    pub kernel_ok_for_memfd: bool,
    /// Writable + executable directory for Method B / stage-0 bootstrap.
    pub staging_dir: Option<String>,
}

impl HostCapabilities {
    /// Construct from fingerprint-probe tokens (used by tests + scan.rs).
    pub fn from_flags(
        memfd: bool,
        exec_tmpfs: bool,
        has_base64: bool,
        sftp: bool,
    ) -> Self {
        Self {
            memfd_create: memfd,
            kernel_ok_for_memfd: memfd,
            exec_tmpfs,
            has_base64,
            sftp,
            staging_dir: if exec_tmpfs {
                Some("/dev/shm".into())
            } else {
                None
            },
        }
    }
}

pub fn select_delivery_method(caps: &HostCapabilities) -> DeliveryPlan {
    if caps.memfd_create && caps.kernel_ok_for_memfd {
        return DeliveryPlan {
            method: DeliveryMethod::Memfd,
            encoder: Some(if caps.has_base64 {
                "base64".into()
            } else {
                "raw-ssh-channel".into()
            }),
        };
    }
    if caps.exec_tmpfs {
        return DeliveryPlan {
            method: DeliveryMethod::Tmpfs,
            encoder: Some("base64".into()),
        };
    }
    if caps.sftp {
        return DeliveryPlan {
            method: DeliveryMethod::Sftp,
            encoder: None,
        };
    }
    DeliveryPlan {
        method: DeliveryMethod::PureCommand,
        encoder: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_memfd() {
        let caps = HostCapabilities {
            memfd_create: true,
            kernel_ok_for_memfd: true,
            has_base64: true,
            ..HostCapabilities::default()
        };
        assert!(matches!(
            select_delivery_method(&caps).method,
            DeliveryMethod::Memfd
        ));
    }

    #[test]
    fn degrades_to_pure_command() {
        let caps = HostCapabilities::default();
        assert!(matches!(
            select_delivery_method(&caps).method,
            DeliveryMethod::PureCommand
        ));
    }
}
