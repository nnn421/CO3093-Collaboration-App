# Distributed & Streaming-Based Client-Server Collaboration App

**CO3093 — Network Application Development — Assignment 1**

A Python-based real-time collaboration application built from scratch
using only raw sockets. No frameworks. Custom UDP streaming protocol
with reliable delivery, sliding window, and AES-GCM encryption.

---

## Prerequisites

- Python 3.10 or later
- pip

## Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd <repo-folder>

# 2. Create a virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

## Running the Server

```bash
python server/main.py
```

Expected output:

```
HH:MM:SS  INFO      server — Server starting...
HH:MM:SS  INFO      server — TCP  → port 9000
HH:MM:SS  INFO      server — UDP  → port 9001
HH:MM:SS  INFO      server — HTTP → port 8080
HH:MM:SS  INFO      server — Press Ctrl+C to stop.
```

## Running the Client

```bash
python -m client.cli
```

## Running Tests

```bash
pytest tests/ -v
```

## Opening the Web UI

After the server and client agent are running:

```
http://localhost:8080
```

---

## Project Structure

```
.
├── shared/          — Shared config and utilities (all team members)
├── transport/       — Custom UDP transport protocol (Person A)
├── server/          — Collaboration server (Person B)
├── client/          — Client agent and CLI (Person C)
├── ui/              — Raw-socket HTTP server + Web UI (Person C)
├── docs/            — Protocol spec, architecture, state diagrams
├── tests/           — pytest test suite (Person C)
└── downloads/       — Received files stored here
```

## Team

| Role | Responsibility |
|------|---------------|
| Person A | Transport layer: UDP, reliable delivery, sliding window, congestion control |
| Person B | Server: asyncio, authentication, user registry, encryption, routing |
| Person C | Client, Web UI, network simulator, testing, documentation |

## Technical Constraints

- **Raw sockets only** — `import socket`, no Flask/Django/WebSocket
- TCP port 9000 — control channel (auth, messaging)
- UDP port 9001 — custom streaming protocol
- HTTP port 8080 — web UI (hand-rolled HTTP/1.1)

## Deadline

08/11/2026 — 23:59
