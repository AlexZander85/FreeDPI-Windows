use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// Минимальный режим: outbound TLS ClientHello, outbound QUIC Initial, outbound DNS request.
    Strict,
    /// Нормальный режим: разрешает включённые production techniques, но не весь UDP:443.
    Balanced,
    /// Временный диагностический режим: шире Strict, но должен иметь dwell и warning metrics.
    SafeFallback,
}

#[derive(Debug, Clone)]
pub struct CaptureBudgetConfig {
    pub max_capture_pps: u64,
    pub max_drop_ratio_ppm: u64,
    pub max_worker_queue_depth: usize,
    pub max_other_udp443_pps: u64,
    pub min_mode_dwell: Duration,
}

impl Default for CaptureBudgetConfig {
    fn default() -> Self {
        Self {
            max_capture_pps: 150_000,
            max_drop_ratio_ppm: 1_000, // 0.1%
            max_worker_queue_depth: 4096,
            max_other_udp443_pps: 100,
            min_mode_dwell: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CapturePressure {
    pub rx_pps: u64,
    pub drop_ratio_ppm: u64,
    pub max_worker_queue_depth: usize,
    pub other_udp443_pps: u64,
}

#[derive(Debug)]
pub struct CaptureBudgetGovernor {
    cfg: CaptureBudgetConfig,
    mode: CaptureMode,
    last_switch: Instant,
    last_rx: AtomicU64,
    last_drop: AtomicU64,
    last_other_udp443: AtomicU64,
}

impl CaptureBudgetGovernor {
    pub fn new(cfg: CaptureBudgetConfig) -> Self {
        Self {
            cfg,
            mode: CaptureMode::Strict,
            last_switch: Instant::now(),
            last_rx: AtomicU64::new(0),
            last_drop: AtomicU64::new(0),
            last_other_udp443: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn mode(&self) -> CaptureMode {
        self.mode
    }

    pub fn observe_window(
        &mut self,
        total_received: u64,
        total_dropped: u64,
        total_other_udp443: u64,
        window: Duration,
        max_worker_queue_depth: usize,
    ) -> (Option<CaptureMode>, CapturePressure) {
        let prev_rx = self.last_rx.swap(total_received, Ordering::Relaxed);
        let prev_drop = self.last_drop.swap(total_dropped, Ordering::Relaxed);
        let prev_other = self
            .last_other_udp443
            .swap(total_other_udp443, Ordering::Relaxed);

        let rx_delta = total_received.saturating_sub(prev_rx);
        let drop_delta = total_dropped.saturating_sub(prev_drop);
        let other_delta = total_other_udp443.saturating_sub(prev_other);
        let secs = window.as_secs().max(1);

        let pressure = CapturePressure {
            rx_pps: rx_delta / secs,
            drop_ratio_ppm: if rx_delta == 0 {
                0
            } else {
                drop_delta.saturating_mul(1_000_000) / rx_delta
            },
            max_worker_queue_depth,
            other_udp443_pps: other_delta / secs,
        };

        if self.last_switch.elapsed() < self.cfg.min_mode_dwell {
            return (None, pressure);
        }

        let next = self.decide(pressure);
        if next != self.mode {
            self.mode = next;
            self.last_switch = Instant::now();
            (Some(next), pressure)
        } else {
            (None, pressure)
        }
    }

    fn decide(&self, p: CapturePressure) -> CaptureMode {
        let overloaded = p.rx_pps > self.cfg.max_capture_pps
            || p.drop_ratio_ppm > self.cfg.max_drop_ratio_ppm
            || p.max_worker_queue_depth > self.cfg.max_worker_queue_depth
            || p.other_udp443_pps > self.cfg.max_other_udp443_pps;

        match (self.mode, overloaded) {
            (_, true) => CaptureMode::Strict,
            (CaptureMode::Strict, false) => CaptureMode::Balanced,
            (CaptureMode::Balanced, false) => CaptureMode::Balanced,
            (CaptureMode::SafeFallback, false) => CaptureMode::Balanced,
        }
    }
}

pub fn build_filter(mode: CaptureMode, enable_dns: bool, enable_quic: bool) -> String {
    let mut terms: Vec<String> = Vec::with_capacity(4);

    terms.push(
        "(tcp.DstPort == 443 && tcp.PayloadLength > 5 \
          && tcp.Payload[0] == 0x16 && tcp.Payload[1] == 0x03 \
          && tcp.Payload[5] == 0x01)"
            .to_string(),
    );

    if enable_quic {
        terms.push(
            "(udp.DstPort == 443 && udp.PayloadLength >= 1200 \
              && (udp.Payload[0] & 0xC0) == 0xC0 \
              && (udp.Payload[0] & 0x30) == 0x00)"
                .to_string(),
        );
    }

    if enable_dns {
        terms.push("udp.DstPort == 53".to_string());
    }

    match mode {
        CaptureMode::Strict | CaptureMode::Balanced => {
            format!("(ip or ipv6) && outbound && ({})", terms.join(" or "))
        }
        CaptureMode::SafeFallback => "(ip or ipv6) && outbound && \
             ((tcp.DstPort == 443 && tcp.PayloadLength > 0) \
             or (udp.DstPort == 443 && udp.PayloadLength > 0) \
             or udp.DstPort == 53)"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_budget_governor_transitions() {
        let cfg = CaptureBudgetConfig::default();
        let mut gov = CaptureBudgetGovernor::new(cfg);
        gov.last_switch = Instant::now() - Duration::from_secs(60); // Bypass min dwell check

        // 1. Initial mode is Strict
        assert_eq!(gov.mode(), CaptureMode::Strict);

        // 2. Under normal traffic load, switch to Balanced
        let (res, _) = gov.observe_window(100, 0, 0, Duration::from_secs(1), 0);
        assert_eq!(res, Some(CaptureMode::Balanced));
        assert_eq!(gov.mode(), CaptureMode::Balanced);

        // 3. Bypass dwell again for tests
        gov.last_switch = Instant::now() - Duration::from_secs(60);

        // 4. Overload trigger: high pps -> Strict
        let (res2, _) = gov.observe_window(100 + 200_000, 0, 0, Duration::from_secs(1), 0);
        assert_eq!(res2, Some(CaptureMode::Strict));
        assert_eq!(gov.mode(), CaptureMode::Strict);
    }

    #[test]
    fn test_build_filter_syntax() {
        let f1 = build_filter(CaptureMode::Strict, true, true);
        assert!(f1.contains("tcp.DstPort == 443"));
        assert!(f1.contains("udp.DstPort == 53"));
        assert!(f1.contains("udp.DstPort == 443"));

        let f2 = build_filter(CaptureMode::SafeFallback, true, true);
        assert!(f2.contains("PayloadLength > 0"));
    }
}
