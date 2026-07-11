# Testlab local servers

Use `tools/synthetic_dpi_server.py` for deterministic local block symptoms. It is not a real ISP DPI and must not be used to claim provider effectiveness.

Recommended bindings:

- HTTP: `127.0.0.1:18080`
- TLS-like TCP symptom server: `127.0.0.1:18443`
- DNS UDP: `127.0.0.1:1053`
- QUIC-like UDP: `127.0.0.1:1443`
