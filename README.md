# Cisco IOS-XE / IOS-SE Security Configuration Auditor
<img width="1740" height="922" alt="image" src="https://github.com/user-attachments/assets/4b3c5f2e-eb98-4603-b359-c89b0700b305" />

A zero-dependency, single-file Python auditor that ingests a manually-exported Cisco `show running-config` text file and produces a scored, categorized, actionable security audit — with copy-paste-ready remediation commands for every finding it can fix, and honest `MANUAL_REVIEW` flags for the things it structurally can't see from a config file alone.

Built by [Jafar Tavana](https://github.com/jafartavana01) — network security engineer (Cisco / Fortinet / MikroTik / Linux / Windows Server), CCIE-track.

```
python cisco_audit.py -c running.conf --all
```

> **What's new:** `--compliance` now cross-references every finding against NIST SP 800-53, ISO/IEC 27002:2022, the CIS Cisco IOS-XE Benchmark, and DISA STIG — with zero changes to the existing ~160 checks. See [Compliance Framework Mapping](#compliance-framework-mapping) and the [Changelog](#changelog) for full detail.

---

## Table of Contents

1. [Why This Exists](#why-this-exists)
2. [What It Actually Checks](#what-it-actually-checks)
3. [Architecture](#architecture)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [CLI Reference](#cli-reference)
7. [Worked Examples on Four Different Device Roles](#worked-examples-on-four-different-device-roles)
8. [Understanding the Output](#understanding-the-output)
9. [The Correlation Engine](#the-correlation-engine)
10. [Policy Customization](#policy-customization)
11. [Compliance Framework Mapping](#compliance-framework-mapping)
12. [Extending the Tool: Adding a New Domain Check](#extending-the-tool-adding-a-new-domain-check)
13. [Known Limitations & Roadmap](#known-limitations--roadmap)
14. [FAQ](#faq)
15. [Contributing](#contributing)
16. [Changelog](#changelog)
17. [License & Disclaimer](#license--disclaimer)

---

## Why This Exists

Most "config auditors" you'll find are either:

- A checklist in a spreadsheet someone maintains by hand, or
- A commercial NCCM/compliance platform that wants SNMP/SSH access to your production gear and a five-figure PO, or
- A shell script full of `grep` one-liners that tells you *whether* a feature string exists, but nothing about *whether it's configured correctly*, *which interfaces are missing it*, or *how the finding relates to five other findings elsewhere in the same config*.

This tool sits in a different spot: **it reads a config you already have** (a `show running-config` paste, no live device access required, no credentials, no SNMP, no risk to production), and gives you a structured report you can actually act on — not just "port security: FAIL" but *which* interfaces, *why* it matters, and the *exact CLI* to fix it.

It's built the same way as my other IOS/FortiOS auditing tools: stdlib-only Python, single file, no telemetry, no external calls, safe to run on an air-gapped jump host.

---

## What It Actually Checks

The tool is organized into **9 domains**, each independently selectable via a CLI flag, covering **~160 individual checks**:

| Domain | Flag | Checks | What it covers |
|---|---|---|---|
| Management Plane | `--mgmt` | ~50 | AAA/TACACS+/RADIUS, local users, SSH/VTY, HTTP(S), SNMP, NTP, logging, banners, DNS, MPP, a full service-exposure matrix (RESTCONF/NETCONF/gNMI/TFTP/FTP/SCP/GuestShell/IOx), password hygiene |
| Layer 2 Security | `--l2` | ~26 | Port Security (with voice-VLAN-aware thresholds), STP (BPDU Guard/Root Guard/Loop Guard), UDLD, Storm Control, DHCP Snooping (with rate-limit range checking), Dynamic ARP Inspection, IP Source Guard, trunk/native-VLAN/VTP hygiene, EtherChannel/LACP |
| Layer 3 Security | `--l3` | ~21 | uRPF, routing-protocol authentication (OSPF/EIGRP/RIP/BGP/IS-IS), FHRP authentication (HSRP/VRRP), ICMP/IP hardening, **ACL analysis** (unused ACLs, permissive `any any`, exact-duplicate rules, missing `log`), object tracking / IP SLA dependency validation |
| Control Plane (CoPP) | `--cp` | ~15 | CoPP framework presence, then per-traffic-class coverage across 8 categories (ICMP, routing protocols, ARP, L2 control protocols, management protocols, DHCP, FHRP, multicast) — **resolves ACL-based class-maps back to their actual match criteria**, not just class-map names — plus CPU-exhaustion risk indicators (EEM applet count/danger, legacy `ip accounting`, oversized ACLs, stray `debug`) |
| IPsec VPN | `--vpn` | up to 7 | *Conditional — auto-skips if no `crypto ikev2`/`crypto map`/GRE-over-IPsec tunnel exists.* IKEv2 proposal strength, DPD, IPsec transform-set strength, PFS, PSK-reuse-across-peers detection, legacy crypto-map usage |
| Zone-Based Firewall | `--zbfw` | up to 4 | *Conditional — auto-skips if no `zone security` exists.* Zone-pair completeness, inspect policy-maps, actual service-policy application, **self-zone protection** (the device protecting itself, not just transit traffic) |
| Cryptography & PKI | `--pki` | ~11 | Trustpoint revocation-checking, self-signed cert usage, enrollment method, hash algorithm strength, RSA key size — plus explicit `MANUAL_REVIEW` markers for anything that needs live cert data |
| Physical Security & Boot | `--physical` | ~13 | Password-recovery posture, console/AUX line hardening, `boot system` hygiene, config-register sanity, USB-boot posture, Secure Boot / SELinux / hardware-backed storage (flagged manual — platform-verified only) |
| Unnecessary Services & Misc | `--misc` | ~19 | Legacy service disablement (`tcp/udp-small-servers`, BOOTP, Finger, Identd, PAD), Smart Install (`vstack`), CDP/LLDP posture, errdisable recovery, multicast routing awareness, DHCP relay trust review, management VRF isolation |

Plus a **10th cross-cutting layer that isn't a domain at all**: the [Correlation Engine](#the-correlation-engine), which reasons over combinations of findings from every domain above.

---

## Architecture

This is not a pile of `grep` calls. It's a small, deliberately layered pipeline:

```
+------------------+     +-------------------+     +---------------------+
|  CiscoConfig     |---->|  Domain Checks     |---->|  Correlation         |
|  (parser)        |     |  (9 modules,       |     |  Engine              |
|                  |     |   ~160 checks)     |     |  (10 cross-feature   |
+------------------+     +-------------------+     |   rules)             |
                                  |                 +---------------------+
                                  v                           |
                          +---------------+                   |
                          |   Context      |<------------------+
                          | (shared facts) |
                          +---------------+
                                  |
                                  v
                       +----------------------+
                       |  Scoring + Report     |
                       |  (text / JSON, one    |
                       |   file per domain)    |
                       +----------------------+
```

### 1. `CiscoConfig` — the parser

Cisco IOS/IOS-XE config text has a simple but load-bearing structural property: **every stanza is a column-0 header line followed by indented child lines**, terminated by the next column-0 line. `interface`, `router ospf`, `line vty`, `crypto ikev2 profile`, `class-map`, `zone-pair security` — all of it follows this shape. So instead of a line-by-line regex sweep, the parser builds a real (if lightweight) tree:

```python
@dataclass
class ConfigBlock:
    header: str            # e.g. "interface GigabitEthernet1/0/2"
    lines: list[str]        # indented child lines belonging to this stanza
    block_type: str         # coarse classification: interface / line / router / crypto / ...
```

Two things the parser handles that a naive line-scanner gets wrong:

- **Banners.** `banner motd ^C ... multi-line text ... ^C` uses an arbitrary delimiter character and its body is *not indented* — a naive indentation parser would misread every banner line as a new top-level command. The parser extracts banner bodies with a dedicated regex pass *before* indentation parsing runs, and stores them separately (`cfg.banners['motd']`).
- **Terminal capture artifacts.** Configs pasted from a PuTTY/SecureCRT session on Windows often carry `--More--` pagination prompts, stray backspace characters, and BOM/CRLF encoding quirks. `read_config_file()` tries `utf-8-sig -> utf-8 -> cp1252 -> latin-1` in order (common for configs captured through a Windows terminal), and a cleanup pass strips pagination artifacts before parsing.

Every check function queries this structure through a small set of primitives:

```python
cfg.get_blocks("interface ")                 # all interface stanzas
cfg.physical_interfaces()                    # filtered to Gig/TenGig/FastEthernet/etc.
cfg.is_access_port(block) / is_trunk_port(block)
block.has(r"switchport port-security\b")     # bool, searches header + body
block.find(r"maximum (\d+)")                 # returns the re.Match or None
block.name()                                 # "GigabitEthernet1/0/2" from "interface GigabitEthernet1/0/2"
```

> **A bug worth knowing about, because it's instructive:** `CiscoConfig.search()` originally defaulted to `re.IGNORECASE` only. Since the full config text is multi-line, every `^anchored` pattern was silently only matching at *byte offset 0 of the entire file* — not the start of each line — because Python's `re` module needs `re.MULTILINE` explicitly for `^`/`$` to mean "line boundary" rather than "string boundary." This meant most presence checks (`aaa new-model`, `ip dhcp snooping`, etc.) were failing even when the line was clearly present, just not at the very top of the file. It was caught by actually running the tool against a test config and seeing `aaa new-model` reported as missing when it plainly wasn't. Fixed by making `re.MULTILINE` part of the default flags everywhere the full config text is searched. A second, related bug surfaced later: a few checks pass a **pre-compiled** `re.Pattern` object into the same helper methods, and Python's `re.search()` raises `ValueError` if you supply a `flags` argument alongside an already-compiled pattern. Fixed by branching on `isinstance(pattern, re.Pattern)` in `ConfigBlock.has()`/`.find()` and skipping the flags argument entirely in that case. Both bugs were found by actually exercising the tool against real config content across multiple device roles, not by inspection — which is why this repo ships several example configs rather than just the script.

### 2. The `Finding` model

Every single check — pass, fail, not-applicable, or "can't tell from a config file" — produces one of these:

```python
@dataclass
class Finding:
    check_id: str            # "L2PS-01", "COPP-CLASS-ICMP", "CORR-03", ...
    domain: str               # "Layer 2 / Port Security"
    title: str
    status: Status            # PASS | FAIL | NA | MANUAL_REVIEW
    severity: Severity        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    evidence: list[str]       # the actual interface names / lines involved
    evidence_label: str       # a *contextual* header, e.g. "Port Security DISABLED on these access interfaces"
    recommendation: str       # prose explanation of the fix
    detail: str               # caveats, heuristic notes, "why this is MANUAL not FAIL"
    fix_command: str          # copy-paste-ready CLI, e.g.:
                              #   interface <interface>
                              #    switchport port-security
                              #    switchport port-security maximum 1
                              #    ...
```

The `fix_command` field is what turns this from a linter into something you'd actually use at 2am during a change window: **117 of the ~160 checks carry a literal, ready-to-paste remediation block** (with `<placeholder>` tokens only where a value is genuinely site-specific, like an interface name or a shared secret). The remaining ~43 are checks where a single canned command wouldn't make sense — certificate expiry, live stack-election state, and the like — and those are marked `MANUAL_REVIEW` with an explanation of *why*, rather than silently omitted or faked.

### 3. `Context` — the shared fact-sheet

Domain checks don't know about each other directly. Instead, each one can stash a boolean/set/count into a shared `Context` object as a side effect:

```python
ctx.set("dhcp_snooping_enabled", True)
ctx.set("dai_enabled", False)
ctx.set("copp_class_coverage", 3)
```

This is what lets the correlation engine (next section) reason across domains without every domain module needing a dependency on every other one. If you only run `--l2` (skipping `--mgmt`), correlation rules that need a management-plane fact (like `ssh_enabled`) simply see `None` and don't fire — no crash, no false positive, the rule just doesn't apply because its precondition wasn't populated.

### 4. Domain Registry

Adding or selecting a domain is a one-line registry entry:

```python
DOMAIN_REGISTRY = {
    "l2": {
        "title": "Layer 2 Security",
        "file": "layer2_security.txt",
        "funcs": [check_port_security, check_stp, check_udld, check_storm_control,
                  check_dhcp_snooping, check_dai, check_ip_source_guard,
                  check_trunk_native_vtp, check_etherchannel],
    },
    ...
}
```

Each function has the signature `(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]`. Selecting `--l2 --l3` on the CLI runs exactly those two domains' function lists and nothing else; `--all` (or no domain flag at all) runs everything.

### 5. Scoring

```python
SEVERITY_WEIGHT = {CRITICAL: 12, HIGH: 7, MEDIUM: 3, LOW: 1, INFO: 0}
score = max(0, 100 - sum(WEIGHT[f.severity] for f in findings if f.status == FAIL))
```

Scored per-domain and overall. This is deliberately simple (a weighted deduction, not a fitted model) so it's predictable and auditable — you can always explain *why* a score is what it is by looking at which FAIL findings exist.

### 6. Report Generation

Three artifacts per run:

- `summary.txt` — hostname, IOS-XE version, overall + per-domain scores, a top-critical/high findings list, and correlation-engine output surfaced separately.
- `sections/<domain>.txt` — one file per domain, full detail, every FAIL finding shown with its complete evidence list and fix command (not truncated — full per-interface detail is always shown for failures, not hidden behind a verbose flag).
- `findings.json` — the entire structured finding set, for anyone who wants to pipe this into a dashboard, diff two audits over time, or feed a SIEM.

---

## Installation

Requires **Python 3.12+**. Zero third-party dependencies — the entire tool is stdlib (`argparse`, `re`, `json`, `dataclasses`, `enum`, `pathlib`, `datetime`).

**Windows:**
```powershell
# Confirm Python 3.12+ is on PATH
python --version

# Just drop cisco_audit.py anywhere and run it
python cisco_audit.py -c C:\configs\running.conf --all
```

**Linux / macOS:**
```bash
python3 --version
python3 cisco_audit.py -c ./running.conf --all
```

**Getting the config file itself** (on the actual Cisco device):
```
terminal length 0
show running-config
```
Paste the output into a text file (`.conf`/`.txt`, doesn't matter — the tool reads raw text regardless of extension). `terminal length 0` avoids `--More--` pagination breaking the capture; the parser also strips pagination artifacts defensively if they slip through anyway.

---

## Quick Start

```bash
# Full audit, every domain, text report
python cisco_audit.py -c running.conf --all

# Just Layer 2 and Layer 3
python cisco_audit.py -c running.conf --l2 --l3

# Everything, both text and machine-readable JSON, to a specific folder
python cisco_audit.py -c running.conf --all -o C:\audits\core-sw01 --format text,json

# Only show me High/Critical findings (skip the Low/Info noise)
python cisco_audit.py -c running.conf --all --min-severity high

# Full evidence + PASS/N-A findings shown too (not just failures)
python cisco_audit.py -c running.conf --all -v

# Use in a pipeline / CI gate: non-zero exit if anything Critical is unresolved
python cisco_audit.py -c running.conf --all --exit-on-critical
```

---

## CLI Reference

| Flag | Description |
|---|---|
| `-c, --config <file>` | **Required.** Path to the running-config text export. |
| `--all` | Run every domain. Default behavior if no domain flag is passed at all. Also automatically enables `--compliance`. |
| `--mgmt` | Management plane (AAA, SSH, HTTP, SNMP, NTP, logging, banners, DNS, exposure matrix, passwords) |
| `--l2` | Layer 2 (port security, STP, UDLD, storm-control, DHCP snooping, DAI, IPSG, trunk/native VLAN, VTP) |
| `--l3` | Layer 3 (uRPF, routing-protocol auth, FHRP auth, ICMP hardening, ACL analysis, object tracking) |
| `--cp` | Control plane (CoPP framework + per-traffic-class policing, high-CPU-risk indicators) |
| `--vpn` | IPsec VPN — auto-skips (reports `N/A`) if no VPN config is found |
| `--zbfw` | Zone-Based Policy Firewall — auto-skips if not configured |
| `--pki` | Cryptography & PKI trustpoints |
| `--physical` | Physical security, boot configuration, secure boot posture |
| `--misc` | Unnecessary services, miscellaneous/often-missed hardening, IOS-XE version extraction |
| `-o, --outdir <dir>` | Output directory. Default: `.\audit_<hostname>_<timestamp>\` |
| `--format <text,json>` | Comma-separated. Default: `text` |
| `--min-severity <level>` | `critical\|high\|medium\|low\|info`. Filters what's shown. Default: `info` (everything) |
| `--policy <file.json>` | Override built-in thresholds (see [Policy Customization](#policy-customization)) |
| `--compliance` | Generate compliance cross-reference reports (NIST 800-53, ISO 27002, CIS Benchmark, DISA STIG — see [Compliance Framework Mapping](#compliance-framework-mapping)). Automatically enabled by `--all`; use standalone for a partial-domain run (e.g. `--l2 --compliance`). |
| `--exit-on-critical` | Exit code `2` if any unresolved CRITICAL finding exists — for pipeline/CI gating |
| `-v, --verbose` | Show PASS/N-A findings too, plus uncapped evidence lists everywhere |

Multiple domain flags are **additive**: `--l2 --l3 --pki` runs exactly those three, nothing else.

---

## Worked Examples on Four Different Device Roles

The `examples/` folder ships four realistic (fictional) configs so you can see the tool's actual behavior across different roles rather than take the feature list on faith. All output below is real, unedited tool output.

### Example 1 — Access-Layer Switch

A typical wiring-closet switch: local users, basic AAA, DHCP snooping/DAI, a handful of user ports plus a voice VLAN.

```bash
python cisco_audit.py -c examples/sample_access_switch.conf --all
```

```
  [    mgmt] Management Plane                  47 checks, 20 failed, score  9/100
  [      l2] Layer 2 Security                  26 checks,  7 failed, score 81/100
  [      l3] Layer 3 Security                  14 checks,  2 failed, score 94/100
  [      cp] Control Plane (CoPP)               8 checks,  2 failed, score 76/100
  [     vpn] IPsec VPN                          1 checks,  0 failed, score 100/100  (N/A -- no VPN config)
  [    zbfw] Zone-Based Firewall                1 checks,  0 failed, score 100/100  (N/A -- no ZBFW config)
  [     pki] Cryptography & PKI                 1 checks,  0 failed, score 100/100  (N/A -- no trustpoints)
  [physical] Physical Security & Boot          12 checks,  2 failed, score 94/100
  [    misc] Unnecessary Services & Misc       19 checks,  2 failed, score 98/100
OVERALL SCORE: 14/100
```

Notice VPN, ZBFW, and PKI all correctly report **100/100 with an N/A note** — this switch has none of that configuration, so the domains self-report as not-applicable rather than manufacturing failures for features that were never meant to be there. The low overall score here is realistic for this fixture: it's missing IPsec/ZBFW/PKI *and* has real management-plane gaps by design, to demonstrate the range of findings.

### Example 2 — Core/Distribution Switch (Layer 3 + CoPP-heavy)

A switch running OSPF, HSRP, and a real CoPP policy — but with a legacy/weak PKI trustpoint and no DAI.

```bash
python cisco_audit.py -c examples/sample_core_switch.conf --l2 --l3 --cp --pki -v
```

Real excerpt from `sections/correlation_findings.txt` — this is the **correlation engine catching a gap that no single-feature check would notice**:

```
[HIGH] FAIL  CORR-03 -- SSH enabled with no VTY access-class ACL
--------------------------------------------------------------------------------
Notes: Management plane is reachable from anywhere that can route to this device.
Recommendation: Apply a restrictive 'access-class' ACL to every VTY line.

[MED ] FAIL  CORR-02 -- DAI enabled without Device Tracking (SISF) policy
--------------------------------------------------------------------------------
Recommendation: Configure and attach a device-tracking policy so DAI/IPSG have a
populated, current binding table to validate against.

[LOW ] FAIL  CORR-06 -- Port Security enabled without sticky MAC learning on some ports
--------------------------------------------------------------------------------
Recommendation: Enable sticky learning where static/dynamic learning isn't
specifically required.
```

### Example 3 — Edge Router with IPsec VPN + BGP

A WAN edge router terminating a route-based VTI tunnel, with two IKEv2 proposals — one strong, one deliberately left as a legacy/weak proposal to show detection working.

```bash
python cisco_audit.py -c examples/sample_edge_router_vpn.conf --vpn --pki --l3
```

Real excerpt from `sections/ipsec_vpn.txt` — note the tool correctly ignores the strong proposal and flags only the weak one **by name**:

```
[HIGH] FAIL  VPN-01 -- IKEv2 proposals use strong encryption/integrity/DH-group
--------------------------------------------------------------------------------
IKEv2 proposals using weak algorithms (1):
    - ikev2 proposal IKEV2-PROP-LEGACY

Recommendation: Use AES-GCM (or AES-CBC-256 + SHA-256/384/512), SHA-256+
integrity/PRF, and DH group 14+ (19/20/21 preferred). Avoid DES/3DES, MD5/SHA-1,
and DH groups 1/2/5.

Suggested fix:
    crypto ikev2 proposal <proposal-name>
     encryption aes-gcm-256
     prf sha384
     group 20
    ! Replace the weak encryption/integrity/PRF/group lines shown above.

--------------------------------------------------------------------------------
[HIGH] FAIL  VPN-05 -- No pre-shared key reused across multiple VPN peers
--------------------------------------------------------------------------------
Notes: 1 PSK value(s) appear to be reused.
```

(`IKEV2-PROP-STRONG` — using `aes-gcm-256` / `prf sha384` / `group 20` — correctly reports no failure at all.)

### Example 4 — Hardened "Gold Standard" Reference Config

To show the tool isn't just a fault-finder: a deliberately well-hardened distribution switch — full AAA/TACACS+, SNMPv3, NTP auth, CoPP with real per-class ACLs, PKI with proper revocation checking, `no service password-recovery`, the works.

```bash
python cisco_audit.py -c examples/sample_hardened_gold_standard.conf --all
```

```
OVERALL SCORE: 81/100

Findings by status:
  FAIL:   11
  MANUAL: 19
  PASS:   113
  N/A:    9

Failed findings by severity:
  Critical: 0
  High:     0
  Medium:   4
```

Zero Critical, zero High — the 11 remaining FAILs are genuinely minor/Low items (a couple of CoPP traffic-class categories not broken out separately, one interface-risk item). The 19 `MANUAL` findings are exactly the honest limitation this tool is upfront about: things like certificate expiry, live stack-election state, and Secure Boot/TAm status that **cannot** be determined from a text config export no matter how good the parser is.

---

## Understanding the Output

Every failed check reports in the same shape, so scanning a report is predictable regardless of domain:

```
--------------------------------------------------------------------------------
[HIGH] FAIL  L2PS-01 -- Port Security enabled on access ports
--------------------------------------------------------------------------------
Port Security DISABLED on these access interfaces (1):
    - GigabitEthernet1/0/4

Notes: Heuristic: excludes trunk ports and ports whose description suggests an
uplink; verify any remaining false positives manually.

Recommendation: Enable 'switchport port-security' on every genuine access port.

Suggested fix:
    interface <interface>
     switchport port-security
     switchport port-security maximum 1
     switchport port-security violation restrict
     switchport port-security mac-address sticky
    ! Repeat for each interface listed above.
    ! Use 'maximum 2' instead of 1 on ports with a voice VLAN configured.
```

Status meanings:

| Status | Meaning |
|---|---|
| `PASS` | Check ran and the config meets the bar. |
| `FAIL` | Check ran and found a gap. Severity-weighted into the score. |
| `N/A` | The relevant feature/protocol isn't configured at all (e.g. no VPN -> all VPN checks report N/A, not FAIL). Doesn't penalize the score. |
| `MANUAL_REVIEW` | The check genuinely cannot be determined from a running-config text file (live device state, hardware sensors, certificate binary data). Never silently skipped -- always shown with an explanation of what live command would answer it. |

---

## The Correlation Engine

This is the part that separates a config linter from an actual security analyzer. Every domain check above evaluates **one feature in isolation**. The correlation engine runs *after* all domain checks complete and reasons over **combinations** of findings — because the gap between two individually-fine-looking controls is very often the actual exposure.

It works off the shared `Context` fact-sheet, not off re-parsing the config:

```python
if ctx.get("dhcp_snooping_enabled") and not ctx.get("dai_enabled"):
    # DHCP Snooping without DAI is half a control: the binding table
    # exists, but ARP traffic isn't validated against it.
    emit(CORR-01, severity=HIGH, ...)
```

**10 rules currently implemented:**

| ID | Condition | Why it matters |
|---|---|---|
| CORR-01 | DHCP Snooping enabled, DAI disabled | Binding table exists but nothing validates ARP against it |
| CORR-02 | DAI enabled, no Device Tracking policy | DAI/IPSG need a populated, current binding table |
| CORR-03 | SSH enabled, no VTY access-class | Management plane reachable from anywhere routable |
| CORR-04 | SNMP configured, no ACL restriction | Same exposure pattern, different service |
| CORR-05 | Native VLAN hardened but trunk still allows all VLANs | The native-VLAN fix was only half done |
| CORR-06 | Port Security enabled without sticky learning | Lower-friction hardening left on the table |
| CORR-07 | CoPP applied but covers <=1 traffic category | CoPP exists on paper but isn't actually protecting the CPU |
| CORR-08 | VPN configured + PKI trustpoint(s) with no revocation checking | A compromised/revoked peer cert wouldn't be caught |
| CORR-09 | `no service password-recovery` set + config-register still allows console break | The two settings contradict each other |
| CORR-10 | Both GuestShell and IOx app-hosting surfaces present | Redundant attack surface if only one is actually used |

One rule (802.1X + MAB) is intentionally **not** implemented yet, because the 802.1X domain itself isn't built out — it's marked `N/A` with an explicit note rather than faked. See [Roadmap](#known-limitations--roadmap).

---

## Compliance Framework Mapping

`--compliance` cross-references every finding against four external frameworks. It's automatically enabled whenever you run `--all` (explicitly or as the implicit default with no domain flag), and stays fully optional/additive on a partial-domain run — nothing else about the audit changes, and without it no compliance files are produced.

```bash
# --compliance is automatic here (running every domain)
python cisco_audit.py -c running.conf --all

# explicit flag still needed on a partial-domain run
python cisco_audit.py -c running.conf --l2 --l3 --compliance
```

Produces:
- `sections/compliance_nist_800_53.txt`, `compliance_iso27002.txt`, `compliance_cis_benchmark.txt`, `compliance_disa_stig.txt` — one file per framework, findings grouped **by control number** (the way you'd actually navigate the framework document itself), not by domain.
- `compliance_overview.txt` — a single cross-framework matrix of FAILED findings only, all four frameworks side by side, sorted by severity.

### Architecture

The mapping data lives entirely outside the check functions, in standalone JSON files under `mappings/`:

```json
{
  "framework_id": "iso27002",
  "framework_name": "ISO/IEC 27002:2022",
  "license_note": "...",
  "checks": {
    "L2PS-01": [{"control": "8.20", "title": "Networks security", "relationship": "direct"}],
    "DHCPSNOOP-01": [
      {"control": "8.20", "title": "Networks security", "relationship": "direct"}
    ]
  }
}
```

`load_compliance_mappings()` loads whatever mapping files exist in `mappings/` and cross-references them against `check_id` at report-generation time — **none of the ~160 check functions were touched to add this feature**. That was a deliberate design choice: it means adding a 5th framework later is "drop in another JSON file," not a re-edit of every check. `tools/generate_mappings.py` is the (non-runtime) generator script used to build the shipped JSON files — kept in the repo so the mapping can be regenerated or extended without hand-editing JSON.

Each mapped control carries a **relationship** tag:
- `direct` — the check is essentially the technical implementation of that control.
- `supporting` — the check contributes evidence toward the control but doesn't fully satisfy it alone (most controls in People/Organizational/Physical-adjacent themes need policy or procedural evidence this tool can't see).

### Honest scope per framework — this is not evenly populated, on purpose

| Framework | Status | Why |
|---|---|---|
| **NIST SP 800-53 Rev. 5** | Substantially populated | Public domain (U.S. government work) — no copyright constraint on quoting control IDs/titles, and the control catalog is stable and well-documented. |
| **ISO/IEC 27002:2022** | Substantially populated | Structure (93 controls, 4 themes, clause 8 = Technological) is well-documented; only control **numbers and short conventional titles** are referenced — never the descriptive/guidance text, which is ISO's copyrighted, commercially-sold content. Only ~34 of 93 controls (clause 8) are even theoretically reachable from a config file — the rest are Organizational/People/Physical controls no device config can speak to. |
| **CIS Cisco IOS-XE 17.x Benchmark v2.1.0** | Minimally populated (2 entries) | Only entries directly confirmed against real benchmark text are included. The full PDF is gated behind a CIS SecureSuite login, and section numbering differs across benchmark versions (15 / 16 / 17.x) — guessing was not an option here. |
| **DISA STIG — Cisco IOS-XE Switch (NDM/L2S/RTR)** | Empty (architecture only) | The STIG package and its general structure (~42 NDM requirements, currently at v3r5) are confirmed, but no specific V-ID could be verified without DoD Cyber Exchange/CAC access. Ships ready to populate the moment someone with access can supply the actual checklist text. |

This is the same honesty pattern the tool already applies to `MANUAL_REVIEW` findings: a confident-looking wrong control number is worse than an explicit "not yet mapped." If you have access to the current CIS Benchmark PDF or a DISA STIG checklist export, contributions to `mappings/cis_ios_xe_benchmark.json` / `mappings/disa_stig_cisco_iosxe.json` are very welcome.

### Standard disclaimer (repeated in every generated compliance file)

> This is a practitioner-built cross-reference, not an official statement of compliance or a certified mapping. Verify against the current published framework document before using this as audit evidence.

---

## Policy Customization

Thresholds (port-security max-hosts, DHCP-snooping rate-limit range, SSH timeout ceilings, weak-secret wordlists, etc.) live in one dict and can be overridden without touching the script:

```json
{
  "port_security_max_hosts_data": 1,
  "port_security_max_hosts_voice": 2,
  "dhcp_snooping_rate_limit_min": 5,
  "dhcp_snooping_rate_limit_recommended_max": 10,
  "dhcp_snooping_rate_limit_hard_max": 15,
  "ssh_timeout_max_seconds": 60,
  "min_rsa_key_bits": 2048
}
```

```bash
python cisco_audit.py -c running.conf --l2 --policy my_policy.json
```

Only the keys you include are overridden; everything else falls back to the built-in default. Full default set is in `DEFAULT_POLICY` near the top of `cisco_audit.py`.

---

## Extending the Tool: Adding a New Domain Check

The pattern is deliberately mechanical so it's easy to keep extending (this is the same growth model as my [FortiGate UTM Analyzer](https://github.com/jafartavana01/fortigate-utm-analyzer), which went from a single script to 35 audit domains / 300+ checks over four versions):

```python
def check_my_new_thing(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "My New Domain"
    out: list[Finding] = []

    bad_interfaces = [ifname(b.header) for b in cfg.physical_interfaces()
                       if not b.has(r"some-hardening-command")]

    out.append(F("MYCHECK-01", d, "Some hardening command is present",
                  Status.FAIL if bad_interfaces else Status.PASS,
                  Severity.MEDIUM,
                  evidence=bad_interfaces,
                  evidence_label="Interfaces missing the hardening command",
                  recommendation="Configure 'some-hardening-command' on every interface.",
                  fix_command="interface <interface>\n some-hardening-command"))

    ctx.set("my_new_fact", bool(bad_interfaces))  # optional: feed the correlation engine
    return out
```

Then register it:

```python
DOMAIN_REGISTRY["mynew"] = {
    "title": "My New Domain",
    "file": "my_new_domain.txt",
    "funcs": [check_my_new_thing],
}
DOMAIN_ORDER.append("mynew")
```

And add the CLI flag in `build_arg_parser()` / `DOMAIN_FLAG_HELP`. That's the whole contract — the report generator, scoring engine, and `--all`/`--min-severity`/`-v` behavior all pick it up automatically.

---

## Known Limitations & Roadmap

Stated plainly, because a security tool that overclaims what it checked is worse than one that's honest about its gaps:

**Structurally out of scope (by design — this tool only reads static config text):**
- Certificate expiration, CRL/OCSP live reachability, certificate chain validation (needs `show crypto pki certificates`)
- Live stack state: split-brain/dual-active detection, election status, member/image/license mismatch (needs `show switch`)
- Environmental sensors: fan, power supply, temperature (needs `show environment`)
- Interface error counters: CRC, input/output drops (needs `show interface`)
- Secure Boot / Trust Anchor / SELinux enforcing-mode / hardware-backed storage state (platform-verified, not config-visible)
- ROMMON password state, live recovery-mode status

All of the above are reported as `MANUAL_REVIEW` with the specific live command that would answer them — never silently skipped.

**Not yet built (planned):**
- Full ACL shadow/unreachable-rule detection (requires wildcard-mask-to-CIDR conversion and protocol/port-range overlap math — currently only exact-duplicate-line and `permit ip any any` detection are implemented)
- 802.1X / MAB / TrustSec domain
- Wireless (WLC) domain
- MACsec domain
- Compliance-framework mapping is now built (see [Compliance Framework Mapping](#compliance-framework-mapping)) — NIST 800-53 and ISO 27002 are substantially populated; CIS Benchmark and DISA STIG are architecture-only pending verified access to their gated source documents; Cisco SAFE is not planned as a mapping target (it's an architecture framework, not a control catalog)
- Configuration-hygiene domain (unused route-maps/prefix-lists/object-groups/VRFs — distinct from the security-severity ACL-unused check that already exists)
- IOS-XE version → Cisco PSIRT/CVE cross-reference (the version is already extracted; the lookup against a CVE feed is the missing piece)
- HTML report format (currently `text` and `json` only)

Contributions on any of the above are very welcome — see [Contributing](#contributing).

---

## FAQ

**Does this connect to my device?**
No. It reads a text file you already exported. No SSH, no SNMP, no credentials, nothing touches the network.

**Will running this against a huge config be slow?**
The parser is a single pass plus per-check regex scans; a few thousand lines of config runs in well under a second. It hasn't been benchmarked against carrier-scale (50k+ line) configs yet.

**Why does my VPN-less switch show `IPsec VPN: 100/100`?**
Because there's nothing to fail — the domain detected no `crypto ikev2`/`crypto map`/tunnel config at all and reported a single `N/A` finding rather than manufacturing failures for a feature that was never meant to exist on that device. Same logic applies to `--zbfw` and (partially) `--pki`.

**Can I trust the score as an absolute number?**
Treat it as a relative signal, not a certification. It's a simple, transparent weighted-deduction formula (see [Architecture § Scoring](#5-scoring)) — always inspect the actual FAIL list, especially anything Critical/High, rather than the number alone.

**Windows path with backslashes for `-o`?**
Works fine — the tool uses `pathlib.Path` throughout, so `-o C:\audits\core-sw01` is handled correctly.

---

## Contributing

Issues and PRs welcome — especially for the roadmap items above. If you're adding a domain, please follow the existing pattern (`Finding` objects with `evidence_label` + `fix_command` populated wherever a concrete remediation exists, `MANUAL_REVIEW` rather than a guess wherever it doesn't) so the report style stays consistent across the whole tool.

---

## Changelog

### v1.1.1 — `--all` implies `--compliance`
- Running `--all` (explicitly, or implicitly by passing no domain flag at all) now automatically generates the compliance cross-reference reports too — no need to separately pass `--compliance` for a full run.
- `--compliance` still works exactly as before as a standalone flag for partial-domain runs (e.g. `--l2 --compliance`), where it is **not** auto-enabled — the tool only assumes you want the compliance view when every domain actually ran, since a partial run's cross-reference would be incomplete by definition.
- No other behavior change; this only affects whether the compliance files get written by default.

### v1.1 — Compliance Framework Mapping
- **New `--compliance` flag.** When set, every finding is cross-referenced against four frameworks: **NIST SP 800-53 Rev. 5**, **ISO/IEC 27002:2022**, the **CIS Cisco IOS-XE Benchmark**, and **DISA STIG (Cisco IOS-XE Switch)**.
- **Architecture:** the mapping lives entirely outside the check functions — one JSON file per framework in `mappings/`, keyed by `check_id`. This means the existing ~160 checks in `cisco_audit.py` were **not touched at all** to add this feature; the mapping is loaded and cross-referenced at report-generation time only. Adding a fifth framework later is "add a JSON file," not "edit 160 function calls."
- **Two new report views**, matching the two most useful ways to actually use a compliance mapping:
  - `sections/compliance_<framework>.txt` — one file per framework, findings grouped by control number, for anyone doing a deep-dive against one specific standard during an audit.
  - `compliance_overview.txt` — a single cross-framework matrix of every FAILED finding with its severity and control reference in each framework side-by-side, for a fast management-facing view.
- **Every mapped control carries a `relationship` tag** — `direct` (the check is essentially the technical implementation of that control) or `supporting` (contributes to, but doesn't fully satisfy, an organizational-level control on its own). This avoids the tool overclaiming compliance from a single technical config check.
- **Honest, uneven coverage by design, not oversight:**
  - NIST SP 800-53 and ISO/IEC 27002:2022 are substantially populated (180 check IDs each) — both are stable, well-documented, and (for NIST) public domain, so these could be built with real confidence.
  - The CIS Cisco IOS-XE Benchmark mapping ships with only the handful of entries directly verified against the actual v2.1.0 document; the rest are intentionally left unmapped rather than guessed, since CIS section numbering differs across benchmark versions and the full PDF requires a CIS SecureSuite login.
  - The DISA STIG mapping ships as an empty, ready-to-populate scaffold — the STIG package (NDM/L2S/RTR sub-STIGs, currently v3r5) was confirmed to exist, but no specific V-ID could be verified without DoD Cyber Exchange access. Same principle as the tool's `MANUAL_REVIEW` status elsewhere: don't fabricate a number that looks authoritative but might be wrong.
  - See `tools/generate_mappings.py` for the full reasoning behind every mapped (and deliberately unmapped) control — it's kept in-repo specifically so the mapping can be extended by editing that script rather than hand-writing JSON.
- **No breaking changes.** `--compliance` is fully opt-in; running the tool without it produces byte-identical behavior to v1.0.

### v1.0 — Initial Release
- 9 audit domains, ~160 checks: Management Plane, Layer 2, Layer 3, Control Plane (CoPP), IPsec VPN, Zone-Based Firewall, Cryptography & PKI, Physical Security & Boot, Unnecessary Services & Misc.
- 10-rule correlation engine reasoning across domain findings.
- `fix_command` generation for actionable, copy-paste-ready remediation on the majority of checks.
- Four example configs covering different device roles (access switch, core/distribution switch, edge router with IPsec VPN, hardened reference config).
- Text and JSON report formats, per-domain output files, weighted scoring.

---

## License & Disclaimer

MIT License — see [LICENSE](LICENSE).

This tool is provided for **defensive security auditing of infrastructure you own or are explicitly authorized to assess**. It performs static analysis of a text file only; it does not connect to, modify, or interact with any live device. No warranty of any kind — review every finding and generated command before applying it to a production device, the same way you would review any change before a maintenance window.
