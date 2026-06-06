# Discovery Session

## Date
2026-03-09T06:45:00+08:00

## Exploration Summary

### What
Security Ronin Katana — a forensic triage tool rebranded from usnjrnl-forensic, now part of the Security Ronin product family alongside Security Ronin General (CISO sidekick). Split into a free community tier (Apache-2.0, public repo) and an enterprise tier (proprietary license, private repo), following the established chatham/chatham-pro two-repo pattern.

### Why
The original usnjrnl-forensic was a single open-source tool. The product has matured enough to justify commercial enterprise features that teams and organizations need — collaboration, collection, multi-device correlation, and additional data source support. The rebrand aligns the forensic tool with the Security Ronin company identity and creates a coherent product family (General = strategic commander, Katana = precision forensic blade).

### Who
- **Primary (Community)**: Solo DFIR consultants — independent practitioners handling 3-5 cases/month who need fast, reliable triage from disk images.
- **Secondary (Enterprise)**: MSSP analysts and enterprise IR teams — 15-30 cases/month, need collaboration, multi-device correlation, collection agents, and integration with existing toolchains (Velociraptor, Binalyze).

### Differentiator
End-to-end USN journal triage with ghost recovery, unallocated carving, path reconstruction, and 12 automated IR questions in 35 seconds. No other tool combines all of these. Enterprise tier adds multi-device correlation, collection agents, and collaborative investigation that competing tools (Velociraptor, Timesketch) each do in isolation but not as an integrated forensic workflow.

### Key Quotes
> "Security Ronin is my company name, and we already have plans for Security Ronin General too"
> "We need two repos because the free one will be public, the other one private, we already have that pattern in chatham/chatham-pro"
> "Moving live triage out of the free tier is ok — we never advertised this feature"

## Strategic Context
- Solo founder building two products in parallel (General + Katana)
- General has a $10K SAFE and 4-month self-sustaining timeline
- Chatham/chatham-pro provides the proven two-repo open-core template
- Existing codebase at v0.6.0 with working pipeline, 12 triage questions, HTML reports

## Enterprise Feature Phasing (agreed)
- **Phase 1** (revenue gates): RBAC, multi-device examination, Velociraptor/Binalyze import, live triage
- **Phase 2** (expansion): PCAP/NetFlow, collaborative investigation
- **Phase 3** (platform): Targeted collection agent

## Open Questions
- Enterprise pricing model (carry forward $99/month or adjust for expanded feature set?)
- CLI command name: `katana`, `srk`, `ronin-katana`, or keep `usnjrnl-forensic` as the binary?
- How much of General's architecture (auth, multi-tenancy) can be shared with Katana enterprise?
- Conference circuit timing — debut as Katana or wait for enterprise features?
