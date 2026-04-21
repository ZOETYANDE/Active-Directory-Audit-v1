# 🛡️ AD Audit Framework v1.0

Enterprise-grade Active Directory security assessment tool. Automates comprehensive AD auditing — from network discovery to CVE detection, BloodHound collection, ADCS analysis, and delegated permissions review — with professional HTML, JSON, and PowerShell remediation reporting.

## 🚀 Key Features in v1.0

- **5 new audit modules**: Shares, SMB Unauth, DNS, Vulnerabilities (CVEs), Hardening
- **20+ new security checks**: PrintNightmare, PetitPotam, ZeroLogon, EternalBlue, noPac, MachineAccountQuota, passwords in descriptions, reversible encryption, DES-only Kerberos, Pre-Windows 2000 group, Protected Users, AD Recycle Bin, functional level, AdminCount orphans
- **enum4linux-ng activated**: Anonymous SMB enumeration now runs automatically
- **Module selector**: `--modules` and `--skip` to run only what you need
- **Progress tracking**: Real-time progress bar with elapsed time
- **3 new output files**: `findings.json` (SIEM), `REMEDIATION.ps1` (PowerShell fixes), `17_DNS/`
- **Bilingual group detection**: Works on both English and French-locale DCs
- **Auto-generated remediation**: PowerShell script with fix commands for each finding

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| 🔍 **Discovery** | Network scan, AD service detection, SMB protocol analysis |
| 🔐 **Authentication** | NetExec/CrackMapExec/LDAP credential validation |
| 👥 **Users & Groups** | Inactive accounts, pwd-never-expires, AS-REP Roasting, Kerberoasting, passwords in descriptions, reversible encryption, DES-only, recently created accounts, bilingual group enumeration, Pre-Windows 2000, Protected Users |
| 🔑 **Password Policy** | Default domain policy, FGPP, lockout thresholds |
| 📋 **GPO** | GPO enumeration, GPP password detection (MS14-025) |
| 📂 **Shares** | SMB share enumeration, writable shares, SYSVOL content scan |
| 🔗 **Delegation** | Unconstrained, constrained, RBCD |
| 🛡️ **ACL** | AdminSDHolder, adminCount analysis |
| 🌐 **Trusts** | Forest/domain trusts, SID filtering |
| 💻 **LAPS** | Schema detection, coverage analysis |
| 📜 **ADCS** | CA enumeration, ESC1-ESC8 vulnerability detection (certipy) |
| 🩸 **BloodHound** | Automated collection with FQDN auto-resolution |
| 🔓 **SMB Unauth** | enum4linux-ng, null session testing, anonymous share access |
| 🌍 **DNS** | Zone transfer test, wildcard detection, SRV enumeration |
| 💥 **Vulnerabilities** | PrintNightmare, PetitPotam, ZeroLogon, noPac, EternalBlue (MS17-010) |
| 🏗️ **Hardening** | MachineAccountQuota, functional level, Recycle Bin, AdminCount orphans |
| 📊 **Reporting** | HTML report, JSON findings, PowerShell remediation, text report, SHA256 checksums |

## 🚀 Quick Start

```bash
# 1. Install dependencies
sudo ./requirements.sh

# 2. Run a full audit
./activeD_Audit.sh -t 192.168.199.10 -d LAB.LOCAL -u john.doe

# 3. Run with config file
./activeD_Audit.sh --config audit.conf -u auditor

# 4. Non-authenticated scan only
./activeD_Audit.sh -t 192.168.199.10 -d LAB.LOCAL --unauth-only

# 5. Run specific modules only
./activeD_Audit.sh -t 192.168.199.10 -d LAB.LOCAL -u admin --modules users,groups,bloodhound

# 6. Skip heavy modules
./activeD_Audit.sh -t 192.168.199.10 -d LAB.LOCAL -u admin --skip bloodhound,adcs

# 7. List available modules
./activeD_Audit.sh --list-modules
```

## 📖 Usage

```
./activeD_Audit.sh [OPTIONS] [username]

TARGET:
  -t, --target <IP>         DC IP address
  -d, --domain <DOMAIN>     AD domain (e.g. CORP.LOCAL)
  -n, --network <CIDR>      Network range (auto-detected if omitted)
  --dc-hostname <NAME>      DC hostname for BloodHound

AUTHENTICATION:
  -u, --user <username>     AD username
  --unauth-only             Non-authenticated tests only

MODULES:
  --modules <list>          Comma-separated modules to run
  --skip <list>             Comma-separated modules to skip
  --list-modules            Show available modules

OPTIONS:
  --config <file>           Load config from file
  --output-dir <path>       Custom output directory
  --ldaps                   Use LDAPS (port 636)
  --encrypt                 GPG-encrypt final archive
  --inactivity-days <N>     Inactive account threshold (default: 90)

DEBUG:
  --debug                   Debug mode (detailed logs)
  --verbose                 Verbose output
  -h, --help                Show help
```

### Available Modules

| Module | Type | Description |
|--------|------|-------------|
| `inventory` | Unauth | Network discovery (nmap) |
| `dc_config` | Unauth | SMBv1, SMB signing, LDAP signing |
| `ldap_unauth` | Unauth | Anonymous LDAP bind test |
| `smb_unauth` | Unauth | enum4linux-ng, null sessions |
| `dns` | Unauth | Zone transfer, wildcard, SRV records |
| `users` | Auth | User accounts, passwords in descriptions, encryption flags |
| `groups` | Auth | Privileged groups (EN/FR), Pre-Win2000, Protected Users |
| `inactive` | Auth | Inactive user accounts |
| `computers` | Auth | Computer objects, obsolete OS |
| `password` | Auth | Password policy, FGPP |
| `gpo` | Auth | GPO enumeration, GPP passwords |
| `shares` | Auth | SMB shares, writable shares, SYSVOL scan |
| `delegation` | Auth | Unconstrained, constrained, RBCD |
| `acl` | Auth | AdminSDHolder, adminCount, DCSync |
| `trusts` | Auth | Trust relationships, SID filtering |
| `laps` | Auth | LAPS schema and coverage |
| `adcs` | Auth | ADCS CA servers, ESC1-ESC8 |
| `vulns` | Auth | PrintNightmare, PetitPotam, ZeroLogon, noPac, EternalBlue |
| `misc` | Auth | MachineAccountQuota, functional level, Recycle Bin |
| `bloodhound` | Auth | BloodHound collection |

## 🏗️ Architecture

```
activeD_Audit.sh                    ← Entry point (400 lines — globals, CLI, main flow)
lib/
├── core.sh                         ← Logging, display, timers, findings, utilities
├── config.sh                       ← Config loading, requirements, environment setup
├── modules/
│   ├── inventory.sh                ← Network discovery (nmap)
│   ├── dc_config.sh                ← SMBv1, SMB signing, LDAP signing
│   ├── ldap_unauth.sh              ← Anonymous LDAP bind test
│   ├── smb_unauth.sh               ← enum4linux-ng, null sessions
│   ├── dns.sh                      ← Zone transfer, wildcard, SRV
│   ├── authenticated.sh            ← Auth orchestrator
│   ├── users.sh                    ← User accounts, passwords, encryption flags
│   ├── groups.sh                   ← Privileged groups (EN/FR bilingual)
│   ├── inactive.sh                 ← Inactive users & computers
│   ├── password_policy.sh          ← Default policy + FGPP
│   ├── gpo.sh                      ← GPO + GPP passwords
│   ├── shares.sh                   ← SMB shares, SYSVOL
│   ├── delegation.sh               ← Unconstrained, constrained, RBCD
│   ├── acl.sh                      ← AdminSDHolder, DCSync
│   ├── trusts.sh                   ← Trust relationships
│   ├── laps.sh                     ← LAPS schema + coverage
│   ├── adcs.sh                     ← CA servers, ESC1-ESC8
│   ├── vulns.sh                    ← PrintNightmare, PetitPotam, ZeroLogon
│   ├── misc.sh                     ← MAQ, functional level, Recycle Bin
│   └── bloodhound.sh               ← BloodHound collection
└── reporting/
    ├── html_report.sh              ← HTML report (dark theme, risk score)
    ├── json_export.sh              ← SIEM-ready JSON findings
    ├── remediation.sh              ← PowerShell remediation script
    └── text_reports.sh             ← Text report, summary, checksums, archive
```

## 📁 Output Structure

```
DOMAIN_Audit_YYYYMMDD_HHMMSS/
├── 00_RESUME_SECURITE.txt         ← Risk summary
├── RAPPORT_AUDIT_AD.html          ← Professional HTML report
├── RAPPORT_AUDIT_AD.txt           ← Text report
├── findings.json                  ← Machine-readable findings (SIEM)     [NEW]
├── REMEDIATION.ps1                ← PowerShell fix commands              [NEW]
├── audit_execution.log            ← Full execution log
├── log_summary.txt                ← Log statistics
├── checksums.sha256               ← Integrity verification
├── 01_Inventaire/                 ← Network discovery
├── 02_Configuration_DC/           ← SMB/LDAP config
├── 03_Comptes_Utilisateurs/       ← User analysis
├── 04_Groupes_Privileges/         ← Group membership (EN/FR)
├── 05_Politique_Mots_de_Passe/    ← Password policies
├── 06_GPO/                        ← Group policy
├── 07_Partages/                   ← SMB shares & SYSVOL                  [NEW]
├── 08_Vulnerabilites/             ← CVE checks + enum4linux-ng           [NEW]
├── 09_BloodHound/                 ← BloodHound data
├── 10_Hardening/                  ← MAQ, functional level, Recycle Bin   [NEW]
├── 11_Ordinateurs/                ← Computer objects
├── 12_Delegation/                 ← Kerberos delegation
├── 13_ACL/                        ← ACL analysis
├── 14_Trusts/                     ← Trust relationships
├── 15_LAPS/                       ← LAPS coverage
├── 16_Certificats/                ← ADCS analysis
└── 17_DNS/                        ← DNS security tests                   [NEW]
```

## 🔧 Dependencies

### Critical
| Tool | Purpose |
|------|---------|
| `nmap` | Network scanning |
| `ldapsearch` | LDAP queries |
| `python3` | Runtime |
| `bloodhound-python` | AD graph collection |
| `impacket` | BloodHound dependency |

### Optional (enhances audit depth)
| Tool | Purpose | Module |
|------|---------|--------|
| `nxc` (NetExec) | SMB enumeration, GPP passwords, CVE checks | shares, vulns, dc_config |
| `certipy` | ADCS vulnerability scanning (ESC1-ESC8) | adcs |
| `enum4linux-ng` | Anonymous SMB enumeration | smb_unauth |
| `smbclient` | SYSVOL content scanning, null share test | shares, smb_unauth |
| `dig` | DNS zone transfer, wildcard, SRV records | dns |
| `rpcdump.py` | RPC service enumeration | vulns |
| `gpg` | Output encryption | archive |

Install everything:
```bash
sudo ./requirements.sh              # Install all
sudo ./requirements.sh --check-only # Verify only
```

## 🌍 Internationalization

The script supports **bilingual group detection** for both English and French-locale Active Directory installations:

| English DC | French DC |
|-----------|----------|
| Domain Admins | Admins du domaine |
| Enterprise Admins | Administrateurs de l'entreprise |
| Administrators | Administrateurs |
| Schema Admins | Administrateurs du schéma |
| Account Operators | Opérateurs de compte |
| Backup Operators | Opérateurs de sauvegarde |
| Server Operators | Opérateurs de serveur |

Group membership is also resolved via `primaryGroupID` fallback for the built-in Administrator account.

## 🔒 Security

- Passwords are stored in temporary files with mode `600` and securely deleted after use
- All output files containing credentials are automatically redacted (`[REDACTED]`)
- Output directory is created with mode `700`
- Optional GPG encryption of the final archive (`--encrypt`)
- `umask 077` enforced throughout execution

## ⚠️ Disclaimer

This tool is for **authorized security audits only**. Use only on systems where you have explicit written authorization. Unauthorized use is illegal.

## 📜 License

MIT License
