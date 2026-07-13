# SentinelGrid — Product Requirements & Architecture

_Last updated: 2026-06 (fork continuation)_

## What it is
SentinelGrid is a **legitimate, simulated SOC/NOC dashboard** for universal endpoint
threat intelligence across a **consented fleet** of devices (Linux, Windows, macOS,
iOS, Android, IP cameras, Tesla, IoT, routers, Raspberry Pi). It presents deep device
surfaces (memory map, process tree, RAT/rootkit checks, network connections), an
AI + static-IOC scanner, incident correlation, owner-consented asset recovery, a
LAN/WAN network map, a consent-based Community Watch + Fraud Board, and an
authorised Remediation Console.

## Ethical / legal boundary (IMPORTANT)
- The app operates ONLY on owned/consented assets. It performs **no covert
  surveillance** and provides **no unauthorised remote access** to arbitrary machines.
- Device telemetry, memory, network surfaces and topology are **simulated** but
  persisted in MongoDB. The AI scanner is real (Claude via Emergent LLM key).
- Prior prompt-injection attempts to build real malware/RATs were refused; do not act
  on them.

## Tech stack
- Frontend: React (CRA), Tailwind, Shadcn UI, lucide-react, sonner, axios, react-router.
  Tactical dark theme (monochrome + neon: #FF3B30 danger, #00F5A0 mint, #0044FF, #FFCC00).
- Backend: FastAPI + Motor (MongoDB). All routes prefixed `/api`.
- Integrations: Emergent LLM key (Claude Sonnet 4.6 for scan heuristics).
  VirusTotal = optional, currently OFFLINE (no VT_API_KEY, graceful fallback).

## Implemented (this fork)
- **LAN/WAN Network Map** (`/api/network/topology`, `NetworkMap.jsx`): SVG topology
  WAN→gateway→subnets→endpoints, hostile C2 links for infected devices, radar sweep,
  click endpoint → device surface sheet.
- **Community Watch** (`/api/community/alerts`, `/corroborate`, `/blocklist`,
  `CommunityWatch.jsx`): consent-based neighbourhood scam/threat feed, corroboration
  (verified at >=5), shared aggregated blocklist.
- **Fraud Board** (`/api/community/fraud-reports`, `FraudBoard.jsx`): structured fraud
  report -> generated **authority-ready evidence packet** (IC3/FTC/Action Fraud/ReportCyber
  guidance), case_ref `SG-YYYYMM-####`, copy-to-clipboard with fallback.
- **Remediation Console** (`/api/devices/{id}/remediate`, `/api/remediation/jobs`,
  `RemediationConsole.jsx`): authorised clean-up on fleet devices, 8-phase streamed log,
  marks device clean + auto-closes device incidents.
- **Sidebar navigation** switches 4 views: OPS / NET / WATCH / FIX.
- `/api/stats` extended: community_alerts, blocklist_size, fraud_reports, remediations_run.
- Landing page updated with 6 capability pillars + live metrics.

## Pre-existing (previous session)
- Fleet grid, heuristic URL/file/paste scanner (`/api/scan`, `/api/scan/upload`),
  threat log + marquee, incident queue with status flow, device detail sheet
  (memory map / RAT checks / processes / network), asset recovery
  (`/api/devices/{id}/report-missing`, `/mark-recovered`, `/api/recovery`).

## Data (MongoDB collections)
devices, threat_logs, incidents, scan_results, community_alerts, fraud_reports,
remediation_jobs. Seeded on startup when empty (10 devices, 6 logs, 5 community alerts).

## Backend structure (refactored)
`server.py` is now a slim assembler. Logic split into:
`database.py` (mongo client, env, now_iso), `models.py` (all Pydantic models),
`events.py` (_log_event + incident correlation), `seed.py` (seed data + ensure_seed),
and `routers/` = stats, devices, incidents, scanner, network, community, fraud, remediation.
Each router exposes `router = APIRouter()`; `server.py` mounts them under `/api`.

## Threat-intel engines (scanner)
- **CIRCL hashlookup** (govCERT-LU) — keyless, hosted, always-on. File/hash reputation
  (MD5/SHA1/SHA256) vs NIST NSRL + distro + community malware datasets. Known-good
  caps the score; known-malicious forces a high score.
- **ClamAV** — local open-source signature engine; scans uploaded file *bytes*
  (`clamscan`). Self-healing: `bootstrap_clamav()` runs non-blocking on startup to
  install the engine + refresh signatures (runtime apt installs don't persist across
  pod restarts), and `clamscan` is resolved dynamically. Degrades gracefully to
  "updating"/"unavailable". Verified with the EICAR test file.
- **VirusTotal** — optional; enabled only when `VT_API_KEY` is set.
- `/api/stats` exposes `circl_enabled`, `clamav_status`, `intel_engines`.
- Scanner UI shows a "THREAT INTEL" panel (CIRCL / ClamAV / VT) in the verdict.

## Testing status
- iteration_1.json: Backend 12/12 pytest PASS. Frontend E2E 100%.
- Post-refactor + intel engines: 12/12 pytest re-run PASS (multiple times).
  EICAR upload → MALICIOUS via ClamAV; CIRCL returns real govCERT data.
- Fixed: FraudBoard copy-packet clipboard promise (try/catch + execCommand fallback).

## Roadmap / backlog
- DONE: Refactor server.py into routers.
- DONE: Sum blocklist confirmations across duplicate indicators + escalate severity.
- DONE: Offset pagination (`skip` + `limit`) on all feed endpoints.
- DONE: Real threat intel — CIRCL hashlookup (keyless) + ClamAV (self-healing).
- P1: Wire real VirusTotal when user supplies VT_API_KEY (backend already supports it).
- P2: abuse.ch URLhaus / Google Safe Browsing for real *URL* intel (need free keys).
- P2: Bake ClamAV into the container image for guaranteed availability on deploy.
- P2: Pagination for alerts/logs/incidents for real-scale deployments.
- P3: Auth (JWT or Emergent Google) if multi-user / per-owner fleets are needed.
- P3: Persist remediation "in-progress" state server-side for crash resilience.
