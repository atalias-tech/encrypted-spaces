//! Dependency-free concurrent-connection limiter: per-IP and global caps.
//! A `ConnPermit` decrements both counters on drop, so counts self-correct
//! on disconnect/panic. Per-IP caps are meaningful for direct exposure;
//! behind a reverse proxy the peer is the proxy and the global cap governs.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

struct Counts {
    per_ip: HashMap<IpAddr, u32>,
    total: usize,
}

#[derive(Clone)]
pub struct ConnLimiter {
    counts: Arc<Mutex<Counts>>,
    max_per_ip: u32,
    max_global: usize,
}

pub struct ConnPermit {
    ip: IpAddr,
    counts: Arc<Mutex<Counts>>,
}

impl ConnLimiter {
    pub fn new(max_per_ip: u32, max_global: usize) -> Self {
        Self {
            counts: Arc::new(Mutex::new(Counts {
                per_ip: HashMap::new(),
                total: 0,
            })),
            max_per_ip,
            max_global,
        }
    }

    /// Returns a permit if both caps allow another connection from `ip`,
    /// else `None` (caller must drop the socket).
    ///
    /// A cap value of `0` means "unlimited" for that dimension (operator
    /// opt-out rather than accidental total-lockout on a typo).
    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnPermit> {
        let mut c = self.counts.lock().unwrap();
        if self.max_global != 0 && c.total >= self.max_global {
            return None;
        }
        let entry = c.per_ip.entry(ip).or_insert(0);
        if self.max_per_ip != 0 && *entry >= self.max_per_ip {
            return None;
        }
        *entry += 1;
        c.total += 1;
        Some(ConnPermit {
            ip,
            counts: Arc::clone(&self.counts),
        })
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        let c = self.counts.lock().unwrap();
        c.per_ip.is_empty() && c.total == 0
    }
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut c = self.counts.lock().unwrap();
        c.total = c.total.saturating_sub(1);
        if let Some(n) = c.per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.per_ip.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn per_ip_cap_enforced_and_released() {
        let l = ConnLimiter::new(2, 100);
        let a = l.try_acquire(ip(1)).unwrap();
        let _b = l.try_acquire(ip(1)).unwrap();
        assert!(l.try_acquire(ip(1)).is_none(), "3rd from same IP rejected");
        assert!(l.try_acquire(ip(2)).is_some(), "other IP unaffected");
        drop(a);
        assert!(
            l.try_acquire(ip(1)).is_some(),
            "permit release frees a slot"
        );
    }

    #[test]
    fn global_cap_enforced() {
        let l = ConnLimiter::new(100, 2);
        let _a = l.try_acquire(ip(1)).unwrap();
        let _b = l.try_acquire(ip(2)).unwrap();
        assert!(
            l.try_acquire(ip(3)).is_none(),
            "global cap rejects regardless of IP"
        );
    }

    #[test]
    fn empty_ip_entry_cleaned_up() {
        let l = ConnLimiter::new(2, 100);
        {
            let _p = l.try_acquire(ip(1)).unwrap();
        }
        assert!(l.is_empty(), "IP map entry removed when count hits 0");
    }

    #[test]
    fn zero_cap_means_unlimited() {
        // Both caps set to 0: every acquire must succeed (no cap applied).
        let l = ConnLimiter::new(0, 0);
        let mut permits = Vec::new();
        for _ in 0..20 {
            permits.push(l.try_acquire(ip(1)).expect("0-cap must be unlimited"));
        }
    }
}
