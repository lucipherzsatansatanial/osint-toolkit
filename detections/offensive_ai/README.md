# Offensive AI-agent detection pack

Detection rules and hunting queries for attack frameworks driven by AI agents:
ARTEX / AntiFox, Cairn, PentAGI, HexStrike AI, CyberStrikeAI, Strix, Hermes Agent, Agent Zero.

| Rule | Behaviour | Files |
|---|---|---|
| OAI-001 | AI agent CLI started with approvals disabled, then attack tools on the same host | 01 (KQL), 11 (SPL), 21 (Sigma) |
| OAI-002 | Server calls an external AI model API; Chinese providers raised to high | 02 (KQL), 12 (SPL), 22 (Sigma) |
| OAI-003 | ≥4 different attack tools (or ≥30 runs) from one source within 2 minutes | 03 (KQL), 11 (SPL) |
| OAI-004 | ≥20 probe-like IPs (≤5 requests each, ≥60% errors) against one site in 5 minutes | 04 (KQL), 13 (SPL) |
| OAI-005 | ≥3 of recon / scan / exploit / post on one entity within 15 minutes | 05 (KQL) |
| OAI-006 | Framework indicators (user agents, strings, files, images, IPs, domains) | 06 (KQL), 23 (Sigma) |
| OAI-007 | Out-of-band (OAST) callback domains | 05 (KQL), 24 (Sigma) |
| OAI-008 | Web/API recon burst from one source IP | 07 (KQL) |
| OAI-009 | Lateral movement fan-out (admin ports / network logons) | 08 (KQL), 14 (SPL) |
| OAI-010/011 | Database dump / bulk read, then exfiltration | — (DB audit schemas vary; use the ingest API) |
| OAI-012 | Several AI agent CLIs with approvals off on one host (CAIRN-style swarm) | 09 (KQL) |
| OAI-013 | Security tools launched by an MCP server (HexStrike = critical) | 09 (KQL) |
| OAI-014 | Download-and-execute / reverse shell / encoded / inline code under an agent (Hermes, Agent Zero) | 09 (KQL) |

Use-case catalogue with priorities: [`../USE_CASES.md`](../USE_CASES.md).

## Status (read before deploying)
- **Sigma**: parsed and converted with pySigma (`sigma convert -t splunk`). Not tested against real logs.
- **KQL / SPL**: written for Microsoft Defender XDR / Sentinel (`DeviceProcessEvents`, `DeviceNetworkEvents`,
  `DeviceInfo`, `W3CIISLog`) and Splunk (Sysmon, `access_combined`). **Not executed** against a live tenant:
  run them in hunting mode first, then tune thresholds and server naming before turning them into alerts.
- Model-API hostnames are a curated list; check each provider's current docs before blocking.
- Behaviour rules matter more than indicators: operators can change user agents, banners and certificates.

## Indicators
Indicators come from [ThreatDefence/agentic-attack-detections](https://github.com/ThreatDefence/agentic-attack-detections)
(MIT licence), `iocs/indicators.csv`. The platform downloads it live (`app/modules/threatintel.py`, feed
`agentic`), drops rows past `review_by`, and does not alert on low-confidence rows (legitimate services) or on
generic browser strings. That project notes its rules are not yet tested against a captured intrusion.
