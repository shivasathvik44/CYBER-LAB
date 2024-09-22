# Incident Response Reports

This directory houses formal post-incident documentation, root cause analysis (RCA) records, and triage logs following security events simulated or detected within the homelab.

---

## Directory Structure

```text
incident-reports/
├── README.md
├── templates/
│   └── incident-report-template.md   # Standard NIST SP 800-61 / SANS aligned template
└── IR-2026-*.md                      # Completed incident reports (added after exercises)
```

---

## Incident Reporting Lifecycle

Reports documented in this directory follow the **NIST SP 800-61 Rev. 2** Incident Handling Lifecycle:

```text
  +------------------+      +------------------------+
  | 1. Preparation   | ---> | 2. Detection & Analysis|
  +------------------+      +------------------------+
                                        |
                                        v
  +------------------+      +------------------------+
  | 4. Post-Incident | <--- | 3. Containment,        |
  |    Activity      |      |    Eradication,        |
  +------------------+      |    Recovery            |
                            +------------------------+
```

---

## How to Document a New Lab Incident

1. Make a copy of `templates/incident-report-template.md`.
2. Name the file using the format: `IR-YYYY-XXXX-<scenario-name>.md` (e.g., `IR-2026-0001-ssh-bruteforce.md`).
3. Fill out all sections: Executive Summary, Evidence Hashes, Timeline, MITRE ATT&CK IDs, and Lessons Learned.
4. Link referenced sample logs or alert exports located in `evidence/`.
