<div align="center">

# NetMon

**Agentless Network Discovery, Inventory & Operations Platform**

Python + FastAPI based network management project focused on truthful asset visibility, diagnostics, inventory and operational security signals.

[![CI](https://github.com/AtakanTas-io/NetMon/actions/workflows/ci.yml/badge.svg)](https://github.com/AtakanTas-io/NetMon/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10--3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)
![Tests](https://img.shields.io/badge/tests-105%20passed-brightgreen?logo=pytest)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

## Overview

NetMon is a network-management project built to make local and enterprise network assets easier to discover, inspect and manage without requiring an agent on every endpoint.

The project combines network discovery, diagnostics, normalized inventory, IP address management, switch-port evidence, configuration backup/diff, security-oriented alerts and a FastAPI/WebSocket backend behind a desktop/web interface.

A core design rule is **not to fabricate data**. When a device, protocol or operating-system permission does not expose a value, NetMon reports it as unavailable instead of inventing hardware, traffic or vulnerability information.

## Verified capabilities

The capabilities below are implemented in the current repository and covered by code and/or automated tests.

| Area | Capability |
| --- | --- |
| Discovery | Local-network discovery with cross-platform discovery paths, Nmap-aware service discovery and device classification evidence |
| Diagnostics | Ping, DNS, traceroute/path diagnostics and network-engineering command helpers |
| Inventory | Normalized asset inventory with MAC-based deduplication, IP-change handling, metadata and online/offline state |
| Windows inventory | Credentialed WMI / WinRM inventory paths with explicit access-denied and unavailable states |
| Network devices | SNMP identity collection and BRIDGE-MIB `dot1dTpFdbPort` MAC-to-switch-port association when SNMP is available |
| IPAM | CIDR-aware subnet capacity, address observations and IP-conflict detection without invented DNS/DHCP data |
| NCM | SSH-backed network configuration backup and line-by-line diff; unavailable when credentials/configuration are missing |
| DHCP security | UDP/68 BOOTREPLY monitoring and rogue-DHCP alerts when an authorized DHCP list is configured |
| Exposure monitoring | Open-port/service observations and change/anomaly logic without claiming that an exposed port is automatically a vulnerability |
| Traffic visibility | Measured local-interface Tx/Rx rates plus real active socket/session data; no fabricated per-device byte counts |
| Security | Random initial admin password, forced password change, session validation, RBAC, audit-oriented controls and protected management secrets |
| UI / API | FastAPI REST API, WebSocket updates, browser UI and PyWebView desktop shell |

## What NetMon does not claim

NetMon is intentionally explicit about technical limits:

- Agentless discovery cannot retrieve hardware/software details that a target does not expose through an authorized protocol.
- WMI and WinRM inventory require valid credentials and suitable target-side permissions/firewall configuration.
- SNMP switch-port mapping requires reachable SNMP and suitable community/configuration on the network device.
- Rogue-DHCP monitoring depends on UDP/68 access and a configured authorized-server list.
- Local interface counters and OS socket tables do **not** provide packet-capture-quality per-device traffic accounting.
- An open port or unusual observation is evidence for investigation, not proof of a vulnerability or compromise.

## Architecture

```text
NetMon/
├── backend/
│   ├── server.py              # FastAPI API, WebSocket, persistence and orchestration
│   ├── netdiag_core.py        # Discovery and diagnostic engines
│   ├── deep_discovery.py      # Deeper protocol/device discovery helpers
│   ├── wmi_scanner.py         # WMI / WinRM inventory
│   ├── snmp_switch_mapper.py  # BRIDGE-MIB MAC-to-port mapping
│   ├── dhcp_monitor.py        # UDP/68 DHCP monitoring
│   └── desktop_app.py         # PyWebView desktop shell
├── frontend/
│   ├── index.html
│   └── app.js
├── tests/                     # Automated pytest suite
├── scripts/                   # Windows and utility scripts
├── docs/                      # Technical notes and reports
└── .github/workflows/ci.yml   # Windows CI matrix for Python 3.10-3.13
```

## Quality assurance

The GitHub Actions workflow runs the test suite on **Windows** with Python **3.10, 3.11, 3.12 and 3.13**.

At commit `5cdcce7`, the CI matrix completed successfully on all four Python versions. The Python 3.12 job collected **105 tests and passed all 105**.

Representative coverage includes:

- authentication, session expiry and RBAC boundaries
- forced first-login password change
- protected management secrets
- WMI/WinRM failure states
- normalized inventory and MAC deduplication
- Nmap service parsing and timeout behavior
- IPAM subnet/conflict behavior
- real-vs-unavailable operational readiness contracts
- NCM backup/diff behavior
- traffic/socket contracts that prevent fabricated traffic values
- analyst/exposure logic that avoids unsupported vulnerability claims

Run locally:

```bash
python -m pytest tests/ -v
```

## Installation

### Requirements

- Python 3.10-3.13
- Windows is the primary desktop/CI platform
- Some discovery paths also support non-Windows environments
- Optional capabilities depend on the relevant protocols/tools being available (for example Nmap, SNMP, WMI/WinRM or SSH)

### Windows quick start

```cmd
calistir.bat
```

### Manual start

```bash
python -m venv .venv
```

Windows:

```cmd
.venv\Scripts\activate
pip install -r requirements.txt
python backend/desktop_app.py
```

Linux/macOS web-oriented environments:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

> The first administrator password is generated at runtime rather than hard-coded. The application forces a password change on first login.

## Tech stack

- **Backend:** Python, FastAPI, Uvicorn, SQLite
- **Networking:** ICMP/DNS/traceroute helpers, Nmap integration paths, SNMP, WMI/WinRM, SSH
- **Desktop:** PyWebView
- **Frontend:** HTML, JavaScript, Chart.js
- **Testing:** pytest, pytest-asyncio, HTTPX
- **CI:** GitHub Actions, Windows matrix, Python 3.10-3.13

## Project status

NetMon is under active development. Current work is focused on improving operational reliability, protocol-specific evidence, documentation and making the distinction between **measured**, **discovered**, **configured** and **unavailable** data obvious in the UI.

See [ROADMAP.md](ROADMAP.md) for planned work and [CHANGELOG.md](CHANGELOG.md) for repository-level changes.

## Security and responsible use

Use NetMon only on systems and networks you own or are explicitly authorized to assess. Some discovery and inventory operations can require elevated privileges or administrative credentials.

See [SECURITY.md](SECURITY.md) for the project security policy.

## Contributing

Contributions, bug reports and reproducible test cases are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE).
