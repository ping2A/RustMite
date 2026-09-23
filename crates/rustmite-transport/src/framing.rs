//! Length-prefixed frames and bounded NDJSON reader.

use rustmite_proto::Envelope;

use crate::error::TransportError;

#[derive(Clone, Debug)]
pub struct FrameLimits {
    pub max_total_bytes: u64,
    pub max_line_bytes: usize,
    pub max_lines: u32,
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: 64 * 1024 * 1024,
            max_line_bytes: 256 * 1024,
            max_lines: 2_000_000,
        }
    }
}

/// Compress probe ELF with lz4 size-prepended and wrap as LE u32 length frame.
pub fn encode_probe_frame(probe_elf: &[u8]) -> Vec<u8> {
    let compressed = lz4_flex::compress_prepend_size(probe_elf);
    let mut out = Vec::with_capacity(4 + compressed.len());
    out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    out.extend_from_slice(&compressed);
    out
}

/// Parse NDJSON envelopes with hard caps (hostile input).
pub fn read_ndjson_bounded(
    input: &str,
    limits: &FrameLimits,
) -> Result<Vec<Envelope>, TransportError> {
    let mut total = 0u64;
    let mut lines = 0u32;
    let mut out = Vec::new();
    for line in input.split('\n') {
        if line.is_empty() {
            continue;
        }
        lines = lines.saturating_add(1);
        if lines > limits.max_lines {
            return Err(TransportError::Ingest("max lines exceeded".into()));
        }
        if line.len() > limits.max_line_bytes {
            return Err(TransportError::Ingest("line too long".into()));
        }
        total = total.saturating_add(line.len() as u64);
        if total > limits.max_total_bytes {
            return Err(TransportError::Ingest("max bytes exceeded".into()));
        }
        let env: Envelope = serde_json::from_str(line)
            .map_err(|e| TransportError::Ingest(format!("json: {e}")))?;
        out.push(env);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{Arch, CapabilitySet, Envelope, Hello, SCHEMA_VERSION};

    #[test]
    fn frame_roundtrip_len() {
        let elf = b"\x7fELFfake";
        let frame = encode_probe_frame(elf);
        assert_eq!(
            u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        let body = &frame[4..];
        let dec = lz4_flex::decompress_size_prepended(body).unwrap();
        assert_eq!(dec, elf);
    }

    #[test]
    fn rejects_overlong_line() {
        let big = format!("{{\"kind\":\"error\",\"code\":\"x\",\"msg\":\"{}\"}}", "a".repeat(300_000));
        let limits = FrameLimits {
            max_line_bytes: 1000,
            ..FrameLimits::default()
        };
        assert!(read_ndjson_bounded(&big, &limits).is_err());
    }

    #[test]
    fn parses_hello() {
        let h = Envelope::Hello(Hello {
            schema: SCHEMA_VERSION,
            probe_version: "0.1.0".into(),
            arch: Arch::X86_64,
            kernel: "6.1".into(),
            boot_id: "abc".into(),
            euid: 0,
            pid: 1,
            nonce: "00".into(),
            caps: CapabilitySet::default(),
        });
        let line = serde_json::to_string(&h).unwrap();
        let v = read_ndjson_bounded(&line, &FrameLimits::default()).unwrap();
        assert_eq!(v.len(), 1);
    }
}
