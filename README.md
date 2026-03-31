# 🛡️ AD Audit Framework v4.0

Enterprise-grade Active Directory security assessment tool. Automates comprehensive AD auditing — from network discovery to BloodHound collection, ADCS analysis, and delegated permissions review — with professional HTML and text reporting.

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| 🔍 **Discovery** | Network scan, AD service detection, SMB protocol analysis |
| 🔐 **Authentication** | NetExec/CrackMapExec/LDAP credential validation |
| 👥 **Users & Groups** | Inactive accounts, password-never-expires, AS-REP Roasting, Kerberoasting, privileged groups |
| 🔑 **Password Policy** | Default domain policy, FGPP, lockout thresholds |
| 📋 **GPO** | GPO enumeration, GPP password detection (MS14-025) |
| 🔗 **Delegation** | Unconstrained, constrained, RBCD |
| 🛡️ **ACL** | AdminSDHolder, adminCount analysis |
| 🌐 **Trusts** | Forest/domain trusts, SID filtering |
| 💻 **LAPS** | Schema detection, coverage analysis |
| 📜 **ADCS** | CA enumeration, ESC1-ESC8 vulnerability detection (certipy) |
| 🩸 **BloodHound** | Automated collection with FQDN auto-resolution |
| 📊 **Reporting** | HTML report, text report, security summary, SHA256 checksums |

## 🚀 Quick Start

```bash
# 1. Install dependencies
sudo ./requirements.sh

# 2. Run a full audit
./activeD_Audit.sh -t [IP_ADDRESS] -d [DOMAIN] -u [USERNAME]

# 3. Run with config file
./activeD_Audit.sh --config audit.conf -u [USERNAME]

# 4. Non-authenticated scan only
./activeD_Audit.sh -t [IP_ADDRESS] -d [DOMAIN] --unauth-only
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

## 🏗️ Architecture

```
activeD_Audit.sh
├── Phase 1: Prerequisites & Connectivity
│   ├── Tool detection (nmap, ldapsearch, nxc, certipy...)
│   └── Port scanning (Kerberos, LDAP, SMB, LDAPS, GC)
│
├── Phase 2: Non-Authenticated Audits
│   ├── Network inventory (parallel nmap scans)
│   ├── DC configuration (SMBv1, SMB signing, LDAP signing)
│   └── LDAP anonymous bind test
│
├── Phase 3: Authenticated Audits
│   ├── User accounts (pwd never expires, AS-REP, disabled)
│   ├── Privileged groups (8 groups + Kerberoastable SPNs)
│   ├── Inactive users & computers (obsolete OS detection)
│   ├── Password policy (default + FGPP)
│   ├── GPO audit (enumeration + GPP passwords)
│   ├── Kerberos delegation (unconstrained, constrained, RBCD)
│   ├── ACL abuse (adminCount, AdminSDHolder)
│   ├── Trust relationships (SID filtering)
│   ├── LAPS (schema + coverage analysis)
│   ├── ADCS (CA servers, ESC1-ESC8 via certipy)
│   └── BloodHound collection (FQDN auto-resolution)
│
└── Phase 4: Reporting
    ├── HTML report (dark theme, findings table, risk score)
    ├── Text report + security summary
    ├── SHA256 checksums
    └── Encrypted .tar.gz archive (optional)
```

## 📁 Output Structure

```
DOMAIN_Audit_YYYYMMDD_HHMMSS/
├── 00_RESUME_SECURITE.txt
├── RAPPORT_AUDIT_AD.txt
├── RAPPORT_AUDIT_AD.html          ← Professional HTML report
├── audit_execution.log
├── log_summary.txt
├── checksums.sha256
├── 01_Inventaire/                 ← Network discovery
├── 02_Configuration_DC/           ← SMB/LDAP config
├── 03_Comptes_Utilisateurs/       ← User analysis
├── 04_Groupes_Privileges/         ← Group membership
├── 05_Politique_Mots_de_Passe/    ← Password policies
├── 06_GPO/                        ← Group policy
├── 07_Partages/                   ← Shares
├── 08_Vulnerabilites/             ← Vulns
├── 09_BloodHound/                 ← BloodHound data
├── 10_Preuves/                    ← Evidence
├── 11_Ordinateurs/                ← Computer objects
├── 12_Delegation/                 ← Kerberos delegation
├── 13_ACL/                        ← ACL analysis
├── 14_Trusts/                     ← Trust relationships
├── 15_LAPS/                       ← LAPS coverage
└── 16_Certificats/                ← ADCS analysis
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
| Tool | Purpose |
|------|---------|
| `nxc` (NetExec) | SMB enumeration, GPP passwords |
| `certipy` | ADCS vulnerability scanning |
| `enum4linux-ng` | Extended enumeration |
| `gpg` | Output encryption |

Install everything:
```bash
sudo ./requirements.sh           # Install all
sudo ./requirements.sh --check-only  # Verify only
```

## ⚠️ Disclaimer

This tool is for **authorized security audits only**. Use only on systems where you have explicit written authorization. Unauthorized use is illegal.

## 📜 License

MIT License
