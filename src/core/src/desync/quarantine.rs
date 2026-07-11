//! Quarantine module — intended desync helpers/techniques that are currently
//! quarantined/deprecated/no-op due to complexity or performance issues.

/// Checks if a desync helper/technique is explicitly quarantined.
/// Intended techniques/helpers that are currently not reachable/implemented
/// in the strategy pipeline are listed here with explanation.
pub fn is_explicitly_quarantined(name: &str) -> bool {
    match name {
        "entropy_padding" => {
            // Quarantined: Requires flow entropy profiling, which is too slow
            // for the hot packet loop in user-mode WinDivert.
            true
        }
        "ip_ppxor" => {
            // Quarantined: IP payload XOR obfuscation is incompatible with
            // standard L4 TCP/UDP state tracking of client OS.
            true
        }
        "poisson_delay_fast" => {
            // Quarantined: Poisson delay requires async execution queues
            // which have a high scheduler overhead on multi-gigabit traffic.
            true
        }
        "h2_hpack_aware" => {
            // Quarantined: HTTP/2 HPACK parsing requires maintaining state
            // for HPACK dynamic tables, which is too memory-heavy for a stateless/conntrack proxy.
            true
        }
        "host_obfuscation" => {
            // Quarantined: Host header obfuscation is handled by FakeSni
            // and HTTP-specific splits, standalone host obfuscation is deprecated.
            true
        }
        "hpack_bomber" => {
            // Quarantined: HPACK compression bomb requires dynamic frame insertion
            // which is prone to breaking HTTP/2 stream synchronization.
            true
        }
        _ => false,
    }
}
