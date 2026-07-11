use bytes::Bytes;
use crossbeam::channel::Sender;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct AwgAsyncWriter {
    tx: Sender<Bytes>,
    dropped: AtomicU64,
}

impl AwgAsyncWriter {
    pub fn start(awg: Arc<crate::proxy::awg_tunnel::AwgTunnel>, capacity: usize) -> Arc<Self> {
        let (tx, rx) = crossbeam::channel::bounded::<Bytes>(capacity);
        let this = Arc::new(Self {
            tx,
            dropped: AtomicU64::new(0),
        });

        crate::Runtime::global().io.spawn(async move {
            while let Ok(data) = rx.recv() {
                if let Err(e) = awg.send_ip_packet(data).await {
                    tracing::error!("AWG async send failed: {}", e);
                }
            }
        });

        this
    }

    #[inline]
    pub fn try_send(&self, data: Bytes) -> bool {
        match self.tx.try_send(data) {
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
}
