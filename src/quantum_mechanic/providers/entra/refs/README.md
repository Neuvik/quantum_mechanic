# Entra ID Reference Data

> **`🔓 PUBLIC`**

This directory holds vendored reference data about Microsoft Entra ID
first-party applications — the client IDs, FOCI-family membership,
pre-consented Graph permissions, and display names that QM's detectors
consult during analysis.

**We did not build this data.** It was reverse-engineered and painstakingly
curated by the community researchers named below. QM vendors it so
`check-ca-bypasses` and related detectors work fully offline during
engagements — but credit belongs to the upstream maintainers.

If you find this data useful, **please star the upstream repos and use the
interactive browsers linked below** — they're maintained on volunteer
time and their maintainers deserve visibility.

---

## Attribution

### `GraphPreConsent.yaml`

- **Source**: [`zh54321/GraphPreConsentExplorer`](https://github.com/zh54321/GraphPreConsentExplorer)
- **Author**: zh54321
- **License**: MIT
- **Content**: ~1,664 Microsoft first-party clients with per-app `foci`,
  `broci`, `graph_api_permissions`, `auth_code`, `device_code`, and reply
  addresses.
- **Interactive browser**: bundled `GraphPreConsentExplorer.html` in the
  upstream repo — clone locally to explore.
- **Why it matters here**: this file is the source of truth for QM's
  FOCI-family list. Without it, `detect_foci_exclusion_blast` under-reports
  by roughly 7× (we'd only know about 7 of ~49 FOCI apps).

### `MicrosoftApps.json`

- **Source**: [`merill/microsoft-info`](https://github.com/merill/microsoft-info)
- **Author**: [Merill Fernando](https://merill.net/)
- **License**: MIT
- **Content**: ~4,395 Microsoft first-party apps with `AppId`,
  `AppDisplayName`, `AppOwnerOrganizationId`, `Source`. Refreshed daily
  by upstream automation.
- **Interactive browser**: [graphpermissions.merill.net](https://graphpermissions.merill.net/)
  — the go-to reference for Graph permission metadata.
- **Why it matters here**: QM uses this to resolve unknown app-ID GUIDs
  to human-readable names in detector output (so operators see
  "Microsoft Edge" instead of `e9c51622-460d-4d3d-952d-966a5b1da34c`).

### Related upstream work worth pointing at

- **[entrascopes.com](https://entrascopes.com/)** — Fabian Bader
  ([@fabian_bader](https://github.com/fabian-bader)) and Dirk-jan Mollema
  ([@dirkjanm](https://github.com/dirkjanm)) — polished web browser of
  first-party apps with filtering by FOCI status, CA bypass capability,
  and pre-consented scopes. Use this for exploratory research.
- **[dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools)** — the
  tool this ecosystem grew from. The `roadtx` command has
  `getscope`/`findscope` that will locate a first-party client with a
  specific Graph permission.
- **Dirk-jan Mollema, "Finding Entra ID CA bypasses the structured way"**
  ([slides](https://dirkjanm.io/assets/raw/Finding%20Entra%20ID%20CA%20Bypasses%20-%20the%20structured%20way.pdf))
  — the research talk many of QM's CA-bypass detectors are grounded in.

---

## Why we vendor (instead of live-fetching)

`check-ca-bypasses` and related analyses run against locally-collected
evidence and are meant to work in three environments where live fetching
is a liability:

1. **Air-gapped or OPSEC-strict engagements** — no unauthorized outbound
   calls from the operator's machine.
2. **Reliability during a live engagement** — an upstream repo being
   temporarily unavailable must not silently degrade detection.
3. **Auditability** — every version bump of this data lands as a git diff
   that a reviewer can inspect, not an invisible network artifact.

The tradeoff: this data drifts. Microsoft adds new first-party clients;
zh54321 and the community catalog them. Refresh on your own schedule.

---

## Updating the vendored data

Refresh these files from the private maintenance repository or another
maintained source-of-truth for Entra reference data. The public repository
ships the vendored results for offline use; it does not document the
internal refresh workflow here.

---

## License notes

Both upstream data files are MIT-licensed. Copies of the upstream
`LICENSE` files are included at:

- `LICENSE-GraphPreConsentExplorer.txt`
- `LICENSE-microsoft-info.txt`

If you redistribute QM in any form, preserve these attributions.

## Change log

| Rev | Date       | Change |
|-----|------------|--------|
| 1.0 | 2026-07-16 | Initial vendoring — GraphPreConsent (~1664 clients, 49 FOCI), MicrosoftApps (~4395 apps) |
