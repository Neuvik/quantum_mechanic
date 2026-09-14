# Report

| | |
|---|---|
| **Version** | v1.0.0 |
| **Issued** | 2026-09-14 |
| **Last reviewed** | 2026-09-14 |
| **Status** | Active |

The `report` command renders the full engagement narrative inline in the terminal.

```
qm[acme-assessment][aws:1]> report
```

---

## What the Report Shows

### Credential Chain

A provenance tree showing how each credential was obtained:

```
Credentials
├── #1 AWS svc-deploy (access key import)
│   └── #2 AWS BackupAdminRole ← assumed from #1 via sts:AssumeRole
│       └── #4 AWS AdminRole ← assumed from #2 via trust policy
└── #3 Azure j.smith@acme.com (device code)
```

Color coding: `green` = active · `yellow` = expiring · `red` = expired

### Technique Timeline

Chronological log of every technique run in this engagement:

```
#   Timestamp        Technique                Provider  Principal
1   2026-03-09 14:02 discovery/whoami         AWS       svc-deploy
2   2026-03-09 14:03 discovery/enum_iam       AWS       svc-deploy
3   2026-03-09 14:08 escalation/assume_role_chain AWS    BackupAdminRole
```

### Findings

All findings sorted by severity:

```
ID    Severity         Finding                                 Provider  Technique
F001  🔴 CRITICAL      AdminRole attachable via PassRole       AWS       escalation/...
F002  🟠 HIGH          S3 bucket allows public GetObject       AWS       discovery/...
F003  🟡 MEDIUM        IAM user with console access + no MFA  AWS       discovery/...
```

Severity levels: `critical` · `high` · `medium` · `low` · `info`

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0.0 | 2026-09-14 | General availability release. |
| v1.0-rc3 | 2026-08-07 | Corrected the technique ID in the timeline example. |
| v1.0-rc2 | 2026-08-04 | Public report guide aligned to the shipped inline engagement narrative |
