//! Observation sink trait + VecSink / NdjsonSink.

use std::io::{self, Write};

use rustmite_proto::{Envelope, Observation};

use crate::CollectError;

pub trait ObservationSink {
    fn emit(&mut self, obs: Observation) -> Result<(), CollectError>;
}

/// Collects observations into a `Vec` (tests / offline).
#[derive(Default, Debug)]
pub struct VecSink {
    pub observations: Vec<Observation>,
}

impl VecSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }
}

impl ObservationSink for VecSink {
    fn emit(&mut self, obs: Observation) -> Result<(), CollectError> {
        self.observations.push(obs);
        Ok(())
    }
}

/// Writes `Envelope::Obs` lines to a writer (probe stdout).
pub struct NdjsonSink<W: Write> {
    writer: W,
    collector: String,
    seq: u32,
    bytes_out: u64,
}

impl NdjsonSink<io::Stdout> {
    /// Sink writing NDJSON envelopes to stdout.
    pub fn new() -> Self {
        Self::with_writer(io::stdout())
    }
}

impl Default for NdjsonSink<io::Stdout> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: Write> NdjsonSink<W> {
    pub fn with_writer(writer: W) -> Self {
        Self {
            writer,
            collector: String::new(),
            seq: 0,
            bytes_out: 0,
        }
    }

    pub fn set_collector(&mut self, id: impl Into<String>) {
        self.collector = id.into();
    }

    pub fn bytes_out(&self) -> u64 {
        self.bytes_out
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }
}

impl<W: Write> ObservationSink for NdjsonSink<W> {
    fn emit(&mut self, obs: Observation) -> Result<(), CollectError> {
        let env = Envelope::Obs {
            c: self.collector.clone(),
            n: self.seq,
            d: obs,
        };
        self.seq = self.seq.saturating_add(1);
        let mut line = serde_json::to_vec(&env).map_err(|e| CollectError::msg(e.to_string()))?;
        line.push(b'\n');
        self.bytes_out = self.bytes_out.saturating_add(line.len() as u64);
        self.writer
            .write_all(&line)
            .map_err(|e| CollectError::msg(e.to_string()))?;
        Ok(())
    }
}
