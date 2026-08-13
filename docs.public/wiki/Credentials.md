# Credentials

| | |
|---|---|
| **Version** | v1.0-rc3 |
| **Issued** | 2026-08-07 |
| **Last reviewed** | 2026-08-07 |
| **Status** | Active |

---

## Importing Credentials

### AWS

```
qm[ws]> import aws --profile default
qm[ws]> import aws --profile prod-readonly
```

### Azure

```
qm[ws]> import azure --default                               # Azure CLI session
qm[ws]> import azure --client-id <id> --client-secret <s> --tenant-id <tenant-id>
```

### GCP

```
qm[ws]> import gcp --default                                 # application default credentials
qm[ws]> import gcp --key-file /path/to/service-account.json
```

### OCI

```
qm[ws]> import oci --default                                 # ~/.oci/config DEFAULT profile
qm[ws]> import oci --profile PROD
```

---

## Managing Credentials

### List all credentials
```
qm[ws]> creds
  #1  aws   ACTIVE    BackupAdminRole (assumed from #2)   expires: 47 min
  #2  aws   ACTIVE    svc-deploy (access key import)
  #3  azure EXPIRING  j.smith@acme.com (Azure CLI)        expires: 3 min
```

**Status values:** `active`, `expiring` (< 5 min), `expired`, `revoked`

### List active only
```
qm[ws]> creds --active
```

### Switch active credential
```
qm[ws]> use 2
✓ Active credential: #2 (aws)
qm[ws][aws:2]>
```

### Delete a credential
```
qm[ws]> creds delete 3
✓ Credential #3 deleted
```

---

## Inspecting Credentials

### Human-friendly view (default)
```
qm[ws]> creds
  #1  AWS Assumed Role — BackupAdminRole
      How: assumed from #2 via sts:AssumeRole
      Expires: 47 minutes
```

### Raw JSON view
```
qm[ws]> raw 1
  AccessKeyId:     ASIA3PZ...
  SecretAccessKey: [REDACTED]
  SessionToken:    FwoGZX...
  Expiration:      2026-03-09T18:47:00Z
```

> **Note:** Secret material is encrypted at rest. `raw` shows the structure
> without revealing the secret.

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0-rc3 | 2026-08-07 | Corrected the Azure service-principal tenant flag. |
| v1.0-rc2 | 2026-08-04 | Public credential guide aligned to the shipped AWS, Azure, Entra, GCP, and OCI command set |
