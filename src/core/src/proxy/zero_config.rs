use crate::config::ZeroConfigConfig;
use crate::proxy::http_tunnel::OperaTunnel;
use crate::proxy::surfeasy::SurfEasyClient;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use std::sync::atomic::{AtomicBool, Ordering};

/// T63: Состояние Zero-Config движка.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroConfigState {
    /// Инициализация.
    Initializing,
    /// Маскированный Opera HTTPS прокси-канал работает.
    OperaProxyActive,
    /// Прокси недоступны, используется прямой обход (desync).
    DesyncOnly,
    /// Ошибка инициализации.
    Failed,
}

/// T63: Zero-Config Bypass Engine.
pub struct ZeroConfigEngine {
    config: ZeroConfigConfig,
    state: Arc<std::sync::RwLock<ZeroConfigState>>,
    tunnel: Arc<std::sync::RwLock<Option<Arc<OperaTunnel>>>>,
    auto_active: AtomicBool,
}

impl ZeroConfigEngine {
    pub fn new(config: ZeroConfigConfig) -> Self {
        Self {
            config,
            state: Arc::new(std::sync::RwLock::new(ZeroConfigState::Initializing)),
            tunnel: Arc::new(std::sync::RwLock::new(None)),
            auto_active: AtomicBool::new(false),
        }
    }

    /// T63: Инициализация Zero-Config — вызывается при старте.
    pub async fn initialize(&self) -> Result<()> {
        info!("T63: Initializing Zero-Config Whitelist Bypass Engine...");

        if !self.config.enabled && !self.config.auto_detect {
            info!("T63: Zero-Config is disabled.");
            *self.state.write().unwrap() = ZeroConfigState::DesyncOnly;
            return Ok(());
        }

        if self.config.enabled {
            if let Err(e) = self.activate_tunnel().await {
                error!("T63: Zero-Config initialization failed: {e:#}. Falling back to Desync.");
                *self.state.write().unwrap() = ZeroConfigState::Failed;
            }
        } else {
            // Auto detect mode is active, wait for detector to call set_auto_active
            *self.state.write().unwrap() = ZeroConfigState::DesyncOnly;
        }

        Ok(())
    }

    /// Вспомогательный метод для установки туннеля через SurfEasy/Opera
    pub async fn activate_tunnel(&self) -> Result<()> {
        if *self.state.read().unwrap() == ZeroConfigState::OperaProxyActive {
            return Ok(());
        }

        // 1. Инициализируем SurfEasy API клиент
        let mut client = SurfEasyClient::new();
        info!("T63: Registering anonymous SurfEasy session...");
        client.init().await?;

        // 2. Получаем прокси для Европы (EU) — обычно они самые быстрые и стабильные
        info!("T63: Discovering Opera VPN proxy endpoints for EU...");
        let proxies = match client.discover("EU").await {
            Ok(p) => p,
            Err(e) => {
                warn!("T63: Discover EU proxies failed: {e:#}. Trying default list...");
                // Если API discover лежит, делаем fallback на статические известные IP Opera
                vec![crate::proxy::surfeasy::SeIpEntry {
                    geo: None,
                    host: Some("eu0.sec-tunnel.com".into()),
                    ip: "77.111.244.26".into(),
                    ports: vec![443],
                }]
            }
        };

        if proxies.is_empty() {
            bail!("No Opera proxies discovered.");
        }

        // 3. Выбираем первый рабочий прокси
        let proxy = &proxies[0];
        let proxy_host = proxy.host.as_deref().unwrap_or(&proxy.ip);
        let proxy_port = proxy.ports.first().copied().unwrap_or(443);
        let (user, pass) = client.proxy_credentials();

        info!(
            "T63: Selected proxy {proxy_host}:{proxy_port}. Creating tunnel with fake SNI: {}",
            self.config.opera_masquerade_sni
        );

        // 4. Создаем OperaTunnel с маскировкой SNI
        let tunnel = Arc::new(OperaTunnel::new(
            proxy_host.to_string(),
            proxy_port,
            self.config.opera_masquerade_sni.clone(),
            user,
            pass,
        ));
        tunnel.start_keep_warm();

        // 5. Тестируем подключение к Госуслугам или example.com
        info!("T63: Testing CONNECT tunnel to example.com:443...");
        tunnel.connect("example.com", 443).await?;

        info!("T63: CONNECT tunnel established successfully! Whitelist bypass active.");
        *self.tunnel.write().unwrap() = Some(tunnel);
        *self.state.write().unwrap() = ZeroConfigState::OperaProxyActive;

        Ok(())
    }

    /// Метод динамической активации/деактивации автодетектором
    pub fn set_auto_active(self: &Arc<Self>, active: bool) {
        let old = self.auto_active.swap(active, Ordering::Relaxed);
        if active && !old {
            let self_clone = self.clone();
            tokio::spawn(async move {
                info!("T63: Auto-detector signaled whitelist active. Initializing Opera tunnel...");
                if let Err(e) = self_clone.activate_tunnel().await {
                    error!("T63: Failed to auto-activate ZeroConfig bypass: {e:#}");
                    self_clone.auto_active.store(false, Ordering::Relaxed);
                }
            });
        } else if !active && old {
            info!("T63: Auto-detector signaled whitelist inactive. Stopping Opera tunnel...");
            *self.tunnel.write().unwrap() = None;
            *self.state.write().unwrap() = ZeroConfigState::DesyncOnly;
        }
    }

    /// T63: Возвращает текущее состояние движка.
    pub fn get_state(&self) -> ZeroConfigState {
        *self.state.read().unwrap()
    }

    /// T63: Возвращает true, если Opera прокси активен.
    pub fn is_active(&self) -> bool {
        self.get_state() == ZeroConfigState::OperaProxyActive
    }

    /// T63: Получить ссылку на активный туннель для форвардинга.
    pub fn get_tunnel(&self) -> Option<Arc<OperaTunnel>> {
        self.tunnel.read().unwrap().clone()
    }
}
