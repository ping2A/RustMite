//! SSH transport, probe delivery framing, and bounded NDJSON ingest.
#![forbid(unsafe_code)]

pub mod delivery;
pub mod error;
pub mod fingerprint;
pub mod framing;
pub mod hostkey;
pub mod ingest;
pub mod noise_xx;
pub mod probe;
pub mod probes;
pub mod timeouts;
pub mod throttle;

#[cfg(feature = "ssh")]
pub mod pure_command;
#[cfg(feature = "ssh")]
pub mod scan;
#[cfg(feature = "ssh")]
pub mod ssh;

pub use delivery::{select_delivery_method, DeliveryOutcome, DeliveryPlan, HostCapabilities};
pub use error::TransportError;
pub use fingerprint::{parse_os_release, parse_uname_hint, HostFingerprint, HostSystemInfo};
pub use framing::{encode_probe_frame, read_ndjson_bounded, FrameLimits};
pub use hostkey::{HostKeyAction, HostKeyPolicy, HostKeyRecord, HostKeyReject};
pub use ingest::{normalise_stream, NormalisedResult};
pub use noise_xx::{
    identity_fingerprint, NoiseClientHandshake, NoiseError, NoiseKeypair, NoiseServerHandshake,
    NOISE_PATTERN,
};
pub use probe::{
    probe_tcp_ssh_banner, test_host_connectivity, ConnectivityReport, ConnectivityStage,
    ConnectivityTestOpts,
};
pub use probes::{
    default_search_roots, AgentlessTarget, ProbeArtifact, ProbeCatalog, DEFAULT_LINUX_TARGETS,
};
pub use timeouts::SshTimeouts;

#[cfg(feature = "ssh")]
pub use scan::{remote_scan, RemoteScanOpts, RemoteScanResult, SudoEscalation};
#[cfg(feature = "ssh")]
pub use ssh::{ConnectOpts, SshCredential, SshSession};
