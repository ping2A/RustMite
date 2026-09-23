//! Transfer-rate shaping for probe delivery over SSH.

use std::time::Duration;

/// Sleep so that transferring `bytes` averages at most `max_bps` (0 = unlimited).
pub async fn pace_transfer(bytes: usize, max_bps: u64) {
    if max_bps == 0 || bytes == 0 {
        return;
    }
    let nanos = (bytes as u128)
        .saturating_mul(1_000_000_000)
        .checked_div(max_bps as u128)
        .unwrap_or(0);
    if nanos > 0 {
        tokio::time::sleep(Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)).await;
    }
}

/// Synchronous estimate used by unit tests (no sleep).
pub fn pace_delay_ms(bytes: usize, max_bps: u64) -> u64 {
    if max_bps == 0 || bytes == 0 {
        return 0;
    }
    ((bytes as u128) * 1000 / max_bps as u128).min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_is_instant() {
        assert_eq!(pace_delay_ms(10_000_000, 0), 0);
        assert_eq!(pace_delay_ms(0, 1024), 0);
    }

    #[test]
    fn one_mib_at_one_mib_per_sec_is_about_one_second() {
        let ms = pace_delay_ms(1024 * 1024, 1024 * 1024);
        assert!((900..=1100).contains(&ms), "got {ms}ms");
    }

    #[test]
    fn slower_cap_takes_longer() {
        let fast = pace_delay_ms(100_000, 100_000);
        let slow = pace_delay_ms(100_000, 10_000);
        assert!(slow > fast * 5);
    }

    #[tokio::test]
    async fn pace_transfer_respects_cap() {
        let start = std::time::Instant::now();
        // 50 KiB at 100 KiB/s ≈ 500ms
        pace_transfer(50 * 1024, 100 * 1024).await;
        let elapsed = start.elapsed().as_millis();
        assert!(
            elapsed >= 400,
            "expected ~500ms pacing, got {elapsed}ms"
        );
    }
}
