//! Named Pipes — защищённый IPC для AI агента.
//!
//! Использует Windows Named Pipes (`\\.\pipe\FreeDPI_agent`)
//! вместо HTTP REST API для взаимодействия с AI агентом.
//!
//! Преимущества над HTTP:
//! - Нет TCP port open (нет MITM вектора)
//! - Только локальные процессы могут подключиться
//! - Windows ACL контролирует доступ
//!
//! ## Статус
//! Интерфейс полностью определён. Полная реализация через Windows API
//! требует точных signatures для CreateNamedPipeW/ConnectNamedPipe
//! (windows crate v0.62 имеет отличия от v0.48).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Имя pipe для AI агента.
pub const PIPE_NAME: &str = "\\\\.\\pipe\\FreeDPI_agent";

/// Сообщение от AI агента.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PipeMessage {
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "get_status")]
    GetStatus,
    #[serde(rename = "get_stats")]
    GetStats,
    #[serde(rename = "test_strategy")]
    TestStrategy { domain: String, technique: String },
}

/// Ответ на сообщение агента.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeResponse {
    pub success: bool,
    pub data: serde_json::Value,
}

/// Обработчик сообщений от AI агента.
pub trait PipeHandler: Send + Sync {
    fn handle(&self, msg: &PipeMessage) -> PipeResponse;
}

/// Сервер Named Pipe.
///
/// ## Реализация
/// Полная реализация требует точных WinAPI signatures:
/// - CreateNamedPipeW (pipe creation)
/// - ConnectNamedPipe (wait for client)
/// - ReadFile / WriteFile (communication)
/// - DisconnectNamedPipe (cleanup)
///
/// Текущая версия логирует попытку запуска.
/// Используйте HTTP API (`api/` crate) как fallback.
pub struct PipeServer {
    pipe_path: String,
}

impl PipeServer {
    pub fn new() -> Self {
        Self {
            pipe_path: PIPE_NAME.to_string(),
        }
    }

    pub fn pipe_path(&self) -> &str {
        &self.pipe_path
    }

    pub fn run<H: PipeHandler + Send + Sync + 'static>(self, handler: H) -> Result<()> {
        use windows::core::w;
        use windows::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
        use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
        };

        info!("Starting Named Pipe server at {}", self.pipe_path);
        let handler = std::sync::Arc::new(handler);

        std::thread::spawn(move || {
            let pipe_name = w!("\\\\.\\pipe\\FreeDPI_agent");
            loop {
                // dwOpenMode: PIPE_ACCESS_DUPLEX (3)
                // dwPipeMode: PIPE_TYPE_BYTE (0) | PIPE_READMODE_BYTE (0) | PIPE_WAIT (0) => 0
                // nMaxInstances: PIPE_UNLIMITED_INSTANCES (255)
                let pipe_handle = unsafe {
                    CreateNamedPipeW(
                        pipe_name,
                        windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(3),
                        windows::Win32::System::Pipes::NAMED_PIPE_MODE(0),
                        255,
                        1024,
                        1024,
                        0,
                        None,
                    )
                };

                if pipe_handle.is_invalid() || pipe_handle == INVALID_HANDLE_VALUE {
                    tracing::error!("CreateNamedPipeW failed: {:?}", unsafe { GetLastError() });
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    continue;
                }

                // Wait for a client to connect
                let connected = unsafe { ConnectNamedPipe(pipe_handle, None) };
                if connected.is_ok()
                    || unsafe { GetLastError() } == windows::Win32::Foundation::ERROR_PIPE_CONNECTED
                {
                    let mut buffer = [0u8; 1024];
                    let mut bytes_read = 0u32;
                    let success = unsafe {
                        ReadFile(pipe_handle, Some(&mut buffer), Some(&mut bytes_read), None)
                    };

                    if success.is_ok() && bytes_read > 0 {
                        let request_bytes = &buffer[..bytes_read as usize];
                        if let Ok(msg) = serde_json::from_slice::<PipeMessage>(request_bytes) {
                            let resp = handler.handle(&msg);
                            if let Ok(resp_bytes) = serde_json::to_vec(&resp) {
                                let mut bytes_written = 0u32;
                                let _ = unsafe {
                                    WriteFile(
                                        pipe_handle,
                                        Some(&resp_bytes),
                                        Some(&mut bytes_written),
                                        None,
                                    )
                                };
                            }
                        }
                    }
                }

                unsafe {
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                }
            }
        });

        Ok(())
    }
}

impl Default for PipeServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHandler;
    impl PipeHandler for TestHandler {
        fn handle(&self, msg: &PipeMessage) -> PipeResponse {
            match msg {
                PipeMessage::Ping => PipeResponse {
                    success: true,
                    data: serde_json::json!({"pong": true}),
                },
                PipeMessage::GetStatus => PipeResponse {
                    success: true,
                    data: serde_json::json!({"status": "running"}),
                },
                PipeMessage::GetStats => PipeResponse {
                    success: true,
                    data: serde_json::json!({"packets": 0}),
                },
                PipeMessage::TestStrategy { domain, .. } => PipeResponse {
                    success: true,
                    data: serde_json::json!({"domain": domain}),
                },
            }
        }
    }

    #[test]
    fn test_pipe_message_serialization() {
        let msg = PipeMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ping"));

        let msg = PipeMessage::TestStrategy {
            domain: "example.com".into(),
            technique: "FakeSni".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("example.com"));
    }

    #[test]
    fn test_pipe_handler() {
        let handler = TestHandler;
        let resp = handler.handle(&PipeMessage::Ping);
        assert!(resp.success);
        assert_eq!(resp.data["pong"], true);
    }
}
