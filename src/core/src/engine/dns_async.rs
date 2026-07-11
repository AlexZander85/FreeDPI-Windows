use crate::packet_engine::PacketEngine;
use bytes::Bytes;
use crossbeam::channel::Sender;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use windivert::prelude::{NetworkLayer, WinDivertAddress};

pub struct DnsAsyncBridge {
    tx: Sender<(Bytes, WinDivertAddress<NetworkLayer>)>,
    dropped: AtomicU64,
}

impl DnsAsyncBridge {
    pub fn start(
        engine: Arc<PacketEngine>,
        dns_proxy: Arc<crate::dns::dns_proxy::DnsProxyEngine>,
        capacity: usize,
    ) -> Arc<Self> {
        let (tx, rx) =
            crossbeam::channel::bounded::<(Bytes, WinDivertAddress<NetworkLayer>)>(capacity);
        let this = Arc::new(Self {
            tx,
            dropped: AtomicU64::new(0),
        });

        let worker_proxy = Arc::clone(&dns_proxy);
        let worker_engine = Arc::clone(&engine);
        crate::Runtime::global().io.spawn(async move {
            while let Ok((data, addr)) = rx.recv() {
                if let Some(resp) = worker_proxy.handle_dns_query(&data).await {
                    let _ =
                        worker_engine.inject_batch_via_divert(&[(bytes::Bytes::from(resp), addr)]);
                }
            }
        });

        this
    }

    #[inline]
    pub fn try_offload(&self, data: Bytes, addr: WinDivertAddress<NetworkLayer>) -> bool {
        match self.tx.try_send((data, addr)) {
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
