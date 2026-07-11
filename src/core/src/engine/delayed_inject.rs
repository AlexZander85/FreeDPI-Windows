use crate::packet_engine::{PacketBufferPool, PacketEngine};
use bytes::Bytes;
use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windivert::prelude::{NetworkLayer, WinDivertAddress};

#[derive(Debug)]
struct ScheduledPacket {
    at: Instant,
    data: Bytes,
    addr: WinDivertAddress<NetworkLayer>,
}

impl PartialEq for ScheduledPacket {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}

impl Eq for ScheduledPacket {}

impl PartialOrd for ScheduledPacket {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledPacket {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        other.at.cmp(&self.at)
    }
}

#[derive(Debug)]
pub struct DelayedInject {
    tx: crossbeam::channel::Sender<ScheduledPacket>,
    dropped: AtomicU64,
    sent: AtomicU64,
}

impl DelayedInject {
    pub fn start(
        engine: Arc<PacketEngine>,
        pool: Arc<PacketBufferPool>,
        capacity: usize,
    ) -> Arc<Self> {
        let (tx, rx) = crossbeam::channel::bounded::<ScheduledPacket>(capacity);
        let this = Arc::new(Self {
            tx,
            dropped: AtomicU64::new(0),
            sent: AtomicU64::new(0),
        });
        let worker_self = Arc::clone(&this);
        std::thread::Builder::new()
            .name("fp-delayed-inject".into())
            .spawn(move || worker_self.run(engine, pool, rx))
            .expect("spawn delayed inject worker");
        this
    }

    fn run(
        self: Arc<Self>,
        engine: Arc<PacketEngine>,
        pool: Arc<PacketBufferPool>,
        rx: crossbeam::channel::Receiver<ScheduledPacket>,
    ) {
        let mut heap = BinaryHeap::<ScheduledPacket>::new();
        loop {
            let now = Instant::now();
            while heap.peek().is_some_and(|pkt| pkt.at <= now) {
                let pkt = heap.pop().expect("peeked Some");
                if engine
                    .inject_batch_via_divert(&[(pkt.data.clone(), pkt.addr)])
                    .is_ok()
                {
                    self.sent.fetch_add(1, Ordering::Relaxed);
                }
                pool.release_bytes(pkt.data);
            }

            let timeout = heap
                .peek()
                .map(|pkt| pkt.at.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|| Duration::from_millis(10));

            match rx.recv_timeout(timeout) {
                Ok(pkt) => heap.push(pkt),
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    #[inline]
    pub fn try_schedule(
        &self,
        delay_us: u32,
        data: Bytes,
        addr: WinDivertAddress<NetworkLayer>,
    ) -> bool {
        let pkt = ScheduledPacket {
            at: Instant::now() + Duration::from_micros(delay_us as u64),
            data,
            addr,
        };
        match self.tx.try_send(pkt) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}
