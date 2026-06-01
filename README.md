# Omnisight V2 - Full README

Omnisight V2 - Advanced, modular and AI-ready offensive security orchestration platform.

Features included in this branch:
- Async unified scanner with checkpointing and disk persistence
- Evolutionary scanner to adapt strategies based on history
- Simple monitor for continuous observation
- Live internet scanner using aiohttp (non-invasive probes)
- Network isolation helpers to avoid scanning local/owner IPs
- Plugin system skeleton
- FastAPI-based API gateway with endpoints for scan/live_scan/status
- Simple frontend control panel (static)

Quickstart (local dev):

1) Create virtualenv and install requirements:

   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

2) Run API (development):

   uvicorn api.main:app --reload --port 8000 --host 0.0.0.0

3) Open frontend (static file) or call API directly:

   http://localhost:8000/docs  -> FastAPI interactive docs
   http://localhost:8000/frontend/index.html  -> Static frontend

Security & isolation:
- Add your own IPs to config/my_network.conf to ensure the system never targets them.
- This codebase is a foundation; when integrating real probing libraries, follow legal and ethical rules.

Next steps and recommended improvements:
- Integrate real async socket scanning (use asyncio + sockets or async-nmap wrappers)
- Replace simulated logic with real DNS/WHOIS providers and passive OSINT integrations
- Add authentication and RBAC to the API
- Add persistent queue (Redis + Celery) for distributed scanning
- Add telemetry and metrics (Prometheus / Grafana)

