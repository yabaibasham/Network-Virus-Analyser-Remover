# SentinelGrid — PRD

## Original Problem Statement
"okay lets make a virus detector and safe remover and all elements in through hardware to software all memory is checked where a rat check surface from to the end point to the memory or path or execution or status and location. and how its running what its doing ect. OF ANY DEVICE ALL DEVICE COMPATIBLE COMPUTERS EVERY OS EVERY LINUX OPERATING SYSTEM OR BACKED OR REPS OR CLONES APPLE EVERYTHING CAMERAS TO MODEL TESLAS"

## Pivot Note
The user requested a true universal antivirus — which requires native per-OS kernel agents and cannot be built as a web app. Delivered instead: a **web-based Threat Intelligence & Universal Endpoint SOC dashboard** that simulates/visualizes the concept and adds a real AI-heuristic URL/file scanner.

## User Personas
- SOC Analyst / Security Engineer monitoring a heterogeneous fleet
- Curious power-user wanting to vet a URL or file via AI heuristic

## Core Requirements
- Fleet grid across all device classes (Linux/Win/Mac/iOS/Android/IP cameras/Tesla/IoT/router/RPi)
- Per-device deep surface: memory map, processes, network, RAT/rootkit checks, location, OS
- Quarantine / safe-remove / rescan / release actions
- AI-powered URL/file/snippet scanner (Claude Sonnet 4.6 via Emergent LLM key)
- Live threat log + scrolling alert marquee
- KPI strip: devices, infected, quarantined, scans run, coverage %

## Implemented (2026-06-29)
- FastAPI backend: /api/devices, /api/devices/{id}/surface, /api/devices/{id}/action, /api/threat-logs, /api/stats, /api/scan, /api/scan/upload, /api/scans
- MongoDB seed: 10 devices across all classes, 2 pre-infected, 6 seed logs
- Local IOC scanner (suspicious TLDs, raw IPs, phishing keywords, malware tokens)
- Claude Sonnet 4.6 AI heuristic (Emergent LLM key) for verdict reasoning + score adjustment + recommended actions
- React frontend: tactical SOC dashboard (JetBrains Mono + Space Grotesk + Inter), sidebar, header w/ live UTC clock + marquee, stats bar, fleet grid w/ search & filters, scanner widget (URL/File/Paste tabs), threat log w/ scanlines, device detail Sheet (memory map, RAT checks, processes, network)

## Backlog
- P1: Streaming AI verdict (SSE) instead of single-shot response
- P1: Real VirusTotal integration as optional second engine
- P2: Multi-device bulk actions
- P2: Authentication + role-based access
- P2: Real lightweight agent (Linux binary) reporting to /api/agents endpoint

## Next Actions
- Validate via testing agent, then iterate based on user feedback
