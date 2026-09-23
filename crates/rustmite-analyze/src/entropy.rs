//! Shannon entropy and sliding-window max.

/// Byte-frequency Shannon entropy on a 0.0–8.0 scale.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        if let Some(c) = counts.get_mut(usize::from(b)) {
            *c = c.saturating_add(1);
        }
    }
    let len = data.len() as f64;
    let mut h = 0.0_f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / len;
        h -= p * p.log2();
    }
    h
}

/// Sliding-window Shannon entropy; returns `(max_entropy, offset)`.
///
/// If `window` is 0 or larger than `data`, returns whole-buffer entropy at offset 0.
pub fn sliding_window_max(data: &[u8], window: usize) -> (f64, usize) {
    if data.is_empty() {
        return (0.0, 0);
    }
    if window == 0 || window >= data.len() {
        return (shannon_entropy(data), 0);
    }
    let mut best_h = 0.0_f64;
    let mut best_off = 0usize;
    let last = data.len().saturating_sub(window);
    let mut off = 0usize;
    while off <= last {
        let end = off.saturating_add(window);
        if let Some(slice) = data.get(off..end) {
            let h = shannon_entropy(slice);
            if h > best_h {
                best_h = h;
                best_off = off;
            }
        }
        off = off.saturating_add(1);
    }
    (best_h, best_off)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_same_is_zero() {
        let data = [0x41u8; 1024];
        let h = shannon_entropy(&data);
        assert!(h.abs() < 1e-9, "entropy={h}");
    }

    #[test]
    fn uniform_is_high() {
        let mut data = [0u8; 256];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let h = shannon_entropy(&data);
        assert!(h > 7.9, "entropy={h}");
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn sliding_window_finds_packed_region() {
        let mut data = vec![0x41u8; 512];
        for i in 0..256 {
            if let Some(b) = data.get_mut(200 + i) {
                *b = i as u8;
            }
        }
        let (h, off) = sliding_window_max(&data, 256);
        assert!(h > 7.5, "max={h}");
        assert!(off >= 150 && off <= 250, "offset={off}");
    }
}
