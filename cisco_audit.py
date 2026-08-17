#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cisco IOS-XE/SE Security Configuration Auditor
================================================
Zero external dependencies (Python 3.12+ stdlib only). Runs on Windows, Linux, macOS.

Imports a manually-exported `show running-config` text file and audits it against
a large set of Cisco hardening checks (management plane, L2, L3, control-plane
CoPP, IPsec VPN, PKI, physical/boot security, and more), then runs a correlation
engine that reasons over combinations of findings.

USAGE (Windows examples):
    python cisco_audit.py -c running.conf --all
    python cisco_audit.py -c running.conf --l2 --l3
    python cisco_audit.py -c running.conf --all -o C:\\audits\\switch01
    python cisco_audit.py -c running.conf --all --format text,json --min-severity high
    python cisco_audit.py -c running.conf --all --policy my_policy.json

NOTE ON SCOPE: this tool works ONLY from a static running-config text export.
Anything that requires live device state (show interface counters, show switch,
show environment, show crypto pki certificates, etc.) cannot be checked here and
is reported with status MANUAL_REVIEW so it isn't silently skipped.

Author: built for Alexar (jafartavana01) — network security engineer.
Version: 1.0.0 (first release)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

TOOL_NAME = "Cisco IOS-XE/SE Security Auditor"
TOOL_VERSION = "1.0.0"


# =============================================================================
# 1. CORE DATA MODELS
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_TAG = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED ]",
    Severity.LOW: "[LOW ]",
    Severity.INFO: "[INFO]",
}

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 12,
    Severity.HIGH: 7,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NA = "na"                 # not applicable (feature/protocol not in use)
    MANUAL = "manual_review"  # cannot be determined from running-config alone


STATUS_TAG = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.NA: "N/A ",
    Status.MANUAL: "MANUAL",
}


@dataclass
class Finding:
    check_id: str
    domain: str
    title: str
    status: Status
    severity: Severity
    evidence: list[str] = field(default_factory=list)
    evidence_label: str = "Affected items"
    recommendation: str = ""
    detail: str = ""
    fix_command: str = ""  # copy-paste-ready CLI remediation, may contain <placeholders>

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d


def F(check_id: str, domain: str, title: str, status: Status, severity: Severity,
      evidence: Optional[list[str]] = None, recommendation: str = "", detail: str = "",
      evidence_label: str = "Affected items", fix_command: str = "") -> Finding:
    """Shorthand constructor used throughout the check functions below."""
    return Finding(
        check_id=check_id,
        domain=domain,
        title=title,
        status=status,
        severity=severity if status == Status.FAIL else (
            Severity.INFO if status in (Status.PASS, Status.NA) else severity
        ),
        evidence=evidence or [],
        evidence_label=evidence_label,
        recommendation=recommendation,
        detail=detail,
        fix_command=fix_command,
    )


class Context:
    """
    Shared fact-sheet populated by domain check functions as a side effect.
    The correlation engine reads these facts to reason across domains without
    each domain module needing to know about any other domain's internals.
    """

    def __init__(self):
        self.facts: dict[str, object] = {}

    def set(self, key: str, value) -> None:
        self.facts[key] = value

    def get(self, key: str, default=None):
        return self.facts.get(key, default)


# =============================================================================
# 2. CONFIG PARSER
# =============================================================================

@dataclass
class ConfigBlock:
    header: str
    lines: list[str] = field(default_factory=list)
    block_type: str = "other"

    def body(self) -> str:
        return "\n".join(self.lines)

    def has(self, pattern, flags=re.IGNORECASE | re.MULTILINE) -> bool:
        # body() is multi-line, so MULTILINE is included by default for consistency
        # with CiscoConfig.search(), even though most block-level patterns are unanchored.
        # `pattern` may be a plain string OR an already-compiled re.Pattern (some checks
        # share a precompiled pattern across many calls) -- re.search() rejects a `flags`
        # argument when given a compiled pattern, so branch on that explicitly.
        if isinstance(pattern, re.Pattern):
            return bool(pattern.search(self.header) or pattern.search(self.body()))
        if re.search(pattern, self.header, flags):
            return True
        return re.search(pattern, self.body(), flags) is not None

    def find(self, pattern, flags=re.IGNORECASE | re.MULTILINE):
        if isinstance(pattern, re.Pattern):
            return pattern.search(self.header) or pattern.search(self.body())
        m = re.search(pattern, self.header, flags)
        if m:
            return m
        return re.search(pattern, self.body(), flags)

    def matching_lines(self, pattern: str, flags=re.IGNORECASE) -> list[str]:
        rx = re.compile(pattern, flags)
        return [l for l in ([self.header] + self.lines) if rx.search(l)]

    def name(self) -> str:
        """Best-effort extraction of the block's identifying name (2nd+ token)."""
        parts = self.header.split(None, 1)
        return parts[1] if len(parts) > 1 else self.header


def ifname(header: str) -> str:
    """Strip the leading 'interface ' keyword for cleaner display in report evidence lists."""
    return re.sub(r"^interface\s+", "", header, flags=re.I)


def _classify(header: str) -> str:
    h = header.lower()
    for prefix in ("interface", "line", "router", "crypto", "class-map", "policy-map",
                   "track", "ip access-list", "ipv6 access-list", "mac access-list",
                   "control-plane", "zone security", "zone-pair", "key chain",
                   "aaa group server", "banner", "event manager applet", "vlan"):
        if h.startswith(prefix):
            return prefix
    return "global"


class CiscoConfig:
    """
    Lightweight hierarchical parser for Cisco IOS/IOS-XE running-config text.
    Not a full CLI grammar parser -- relies on the fact that IOS config stanzas
    are column-0 header lines followed by indented child lines, which holds
    true for the vast majority of real-world running-config exports.
    """

    def __init__(self, raw_text: str):
        self.raw_text = raw_text
        self.banners: dict[str, str] = {}
        self.text = ""
        self.blocks: list[ConfigBlock] = []
        self._parse()

    # ---- parsing --------------------------------------------------------

    def _parse(self) -> None:
        text = self.raw_text.replace("\r\n", "\n").replace("\r", "\n")

        # Extract banners first -- their body lines are NOT indented and would
        # otherwise be misread as top-level commands by the indentation parser.
        banner_pattern = re.compile(
            r"^banner (motd|login|exec|incoming|slip-ppp)\s+(\S)(.*?)\2",
            re.DOTALL | re.MULTILINE,
        )

        def _extract(m: re.Match) -> str:
            btype, _delim, body = m.group(1), m.group(2), m.group(3)
            self.banners[btype] = body.strip("\n")
            return f"banner {btype} <extracted-see-context>"

        text = banner_pattern.sub(_extract, text)

        # Strip common terminal-capture artifacts (paging prompts, backspace).
        cleaned_lines = []
        for raw_line in text.split("\n"):
            if "--More--" in raw_line or "---- More ----" in raw_line:
                continue
            cleaned_lines.append(raw_line.replace("\x08", "").rstrip())
        text = "\n".join(cleaned_lines)
        self.text = text

        blocks: list[ConfigBlock] = []
        current: Optional[ConfigBlock] = None
        for raw_line in text.split("\n"):
            if not raw_line.strip() or raw_line.strip() == "!":
                continue
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            stripped = raw_line.strip()
            if indent == 0:
                if current is not None:
                    blocks.append(current)
                current = ConfigBlock(header=stripped, lines=[], block_type=_classify(stripped))
            else:
                if current is None:
                    current = ConfigBlock(header="<global>", lines=[], block_type="global")
                current.lines.append(stripped)
        if current is not None:
            blocks.append(current)
        self.blocks = blocks

    # ---- convenience accessors ------------------------------------------

    def get_blocks(self, *prefixes: str) -> list[ConfigBlock]:
        low = tuple(p.lower() for p in prefixes)
        return [b for b in self.blocks if b.header.lower().startswith(low)]

    def search(self, pattern: str, flags=re.IGNORECASE | re.MULTILINE) -> bool:
        # NOTE: defaults include re.MULTILINE because self.text is the full,
        # multi-line config -- every '^'/'$' anchored check depends on this.
        return re.search(pattern, self.text, flags) is not None

    def findall(self, pattern: str, flags=re.IGNORECASE | re.MULTILINE) -> list:
        return re.findall(pattern, self.text, flags)

    def search_lines(self, pattern: str, flags=re.IGNORECASE) -> list[str]:
        rx = re.compile(pattern, flags)
        return [l for l in self.text.split("\n") if rx.search(l)]

    def get_hostname(self) -> str:
        m = re.search(r"^hostname (\S+)", self.text, re.MULTILINE | re.IGNORECASE)
        return m.group(1) if m else "unknown-host"

    def get_version(self) -> str:
        m = re.search(r"^version (\S+)", self.text, re.MULTILINE | re.IGNORECASE)
        return m.group(1) if m else "unknown"

    def interfaces(self) -> list[ConfigBlock]:
        return self.get_blocks("interface ")

    def physical_interfaces(self) -> list[ConfigBlock]:
        rx = re.compile(
            r"^interface (GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|"
            r"FortyGigabitEthernet|HundredGigE|FastEthernet)",
            re.IGNORECASE,
        )
        return [b for b in self.interfaces() if rx.match(b.header)]

    def is_access_port(self, block: ConfigBlock) -> bool:
        if block.has(r"switchport mode trunk"):
            return False
        if block.has(r"no switchport"):
            return False
        if block.has(r"switchport mode access") or block.has(r"switchport"):
            return True
        return False

    def is_trunk_port(self, block: ConfigBlock) -> bool:
        return block.has(r"switchport mode trunk")

    def looks_like_uplink(self, block: ConfigBlock) -> bool:
        desc = block.find(r"description (.+)")
        if desc:
            d = desc.group(1).lower() if desc.lastindex else ""
            if any(k in d for k in ("uplink", "trunk", "core", "backbone")):
                return True
        return False


# =============================================================================
# 3. DEFAULT POLICY (THRESHOLDS) -- OVERRIDABLE VIA --policy some.json
# =============================================================================

DEFAULT_POLICY = {
    "port_security_max_hosts_data": 1,
    "port_security_max_hosts_voice": 2,
    "dhcp_snooping_rate_limit_min": 5,
    "dhcp_snooping_rate_limit_recommended_max": 10,
    "dhcp_snooping_rate_limit_hard_max": 15,
    "arp_inspection_rate_limit_hard_max": 20,
    "ssh_timeout_max_seconds": 60,
    "ssh_auth_retries_max": 3,
    "console_exec_timeout_max_minutes": 15,
    "vty_exec_timeout_max_minutes": 15,
    "min_rsa_key_bits": 2048,
    "tacacs_radius_key_min_length": 12,
    "eem_applet_count_warn_threshold": 5,
    "weak_shared_secrets": ["cisco", "password", "secret", "admin", "changeme", "key"],
    "generic_usernames": ["admin", "cisco", "test", "guest", "user", "root"],
}


def load_policy(policy_path: Optional[Path]) -> dict:
    policy = dict(DEFAULT_POLICY)
    if policy_path:
        try:
            override = json.loads(policy_path.read_text(encoding="utf-8"))
            policy.update(override)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user directly
            print(f"[!] Warning: could not load policy file '{policy_path}': {exc}", file=sys.stderr)
    return policy


# =============================================================================
# 4. DOMAIN CHECKS -- MANAGEMENT PLANE
# =============================================================================

def check_aaa_and_users(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / AAA"
    out: list[Finding] = []

    aaa_new_model = cfg.search(r"^aaa new-model\b")
    out.append(F("AAA-01", d, "AAA framework enabled (aaa new-model)",
                  Status.PASS if aaa_new_model else Status.FAIL,
                  Severity.CRITICAL,
                  recommendation="Enable 'aaa new-model' as the foundation for centralized AuthN/AuthZ/Acct.",
                  fix_command="aaa new-model"))

    login_lines = cfg.search_lines(r"^aaa authentication login")
    uses_group = any(re.search(r"group (tacacs\+|radius)", l, re.I) for l in login_lines)
    has_local_fallback = any(re.search(r"\blocal\b", l, re.I) for l in login_lines)
    out.append(F("AAA-02", d, "Login authentication uses centralized AAA (TACACS+/RADIUS)",
                  Status.PASS if uses_group else Status.FAIL,
                  Severity.HIGH, evidence=login_lines,
                  evidence_label="Current 'aaa authentication login' lines",
                  recommendation="Use 'aaa authentication login default group tacacs+ local' (or radius).",
                  fix_command="aaa authentication login default group tacacs+ local"))
    if uses_group:
        out.append(F("AAA-03", d, "Local fallback configured for AAA login",
                      Status.PASS if has_local_fallback else Status.FAIL,
                      Severity.MEDIUM, evidence=login_lines,
                      evidence_label="Current 'aaa authentication login' lines",
                      recommendation="Add 'local' as a fallback method in case TACACS+/RADIUS servers are unreachable.",
                      fix_command="aaa authentication login default group tacacs+ local"))

    authz_cmds = cfg.search(r"^aaa authorization commands")
    out.append(F("AAA-04", d, "Command authorization configured",
                  Status.PASS if authz_cmds else Status.FAIL,
                  Severity.LOW,
                  recommendation="Configure 'aaa authorization commands <level> default group tacacs+ local'.",
                  fix_command="aaa authorization commands 15 default group tacacs+ local"))

    authz_cfg_cmds = cfg.search(r"^aaa authorization config-commands")
    out.append(F("AAA-05", d, "Config-command authorization configured",
                  Status.PASS if authz_cfg_cmds else Status.FAIL,
                  Severity.LOW,
                  recommendation="Configure 'aaa authorization config-commands' to gate configuration changes.",
                  fix_command="aaa authorization config-commands"))

    acct_cmds = cfg.search(r"^aaa accounting commands")
    out.append(F("AAA-06", d, "Command accounting configured",
                  Status.PASS if acct_cmds else Status.FAIL,
                  Severity.LOW,
                  recommendation="Configure command accounting for audit trail of privileged actions.",
                  fix_command="aaa accounting commands 15 default start-stop group tacacs+"))

    acct_exec = cfg.search(r"^aaa accounting exec")
    out.append(F("AAA-07", d, "EXEC accounting configured",
                  Status.PASS if acct_exec else Status.FAIL,
                  Severity.LOW,
                  recommendation="Configure 'aaa accounting exec default start-stop group tacacs+'.",
                  fix_command="aaa accounting exec default start-stop group tacacs+"))

    lockout = cfg.search(r"^aaa local authentication attempts max-fail")
    out.append(F("AAA-08", d, "Local account lockout after repeated failures",
                  Status.PASS if lockout else Status.FAIL,
                  Severity.MEDIUM,
                  recommendation="Configure 'aaa local authentication attempts max-fail <n>'.",
                  fix_command="aaa local authentication attempts max-fail 5"))

    # TACACS+/RADIUS shared secret strength
    weak_secrets = policy["weak_shared_secrets"]
    suspect_keys = []
    for blk in cfg.get_blocks("tacacs server", "radius server"):
        m = blk.find(r"key\s+(?:\d\s+)?(\S+)")
        if m:
            secret = m.group(1)
            if secret.lower() in weak_secrets or len(secret) < policy["tacacs_radius_key_min_length"]:
                suspect_keys.append(f"{blk.name()}: key length/strength looks weak")
    legacy_key_lines = cfg.search_lines(r"^(tacacs-server|radius-server) key\s")
    out.append(F("AAA-09", d, "TACACS+/RADIUS shared secret strength",
                  Status.FAIL if (suspect_keys or legacy_key_lines) else Status.PASS,
                  Severity.HIGH,
                  evidence=suspect_keys + legacy_key_lines,
                  evidence_label="Weak or legacy-style shared secrets found",
                  recommendation="Use long, random shared secrets; avoid legacy global 'tacacs-server key' / "
                                 "'radius-server key' in favor of per-server keys under 'tacacs server'/'radius server'.",
                  fix_command="tacacs server <name>\n"
                              " address ipv4 <ip>\n"
                              " key <long-random-secret>\n"
                              "! Migrate off any global 'tacacs-server key' / 'radius-server key' lines."))

    # Enable secret vs enable password, algorithm strength
    has_enable_password = cfg.search(r"^enable password\b")
    has_enable_secret = cfg.search(r"^enable secret\b")
    out.append(F("AAA-10", d, "No legacy 'enable password' in use",
                  Status.FAIL if has_enable_password else Status.PASS,
                  Severity.CRITICAL,
                  recommendation="Remove 'enable password'; use 'enable secret' with a strong hash algorithm.",
                  fix_command="no enable password\nenable algorithm-type scrypt secret <strong-secret>"))
    if has_enable_secret:
        weak_secret = cfg.search(r"^enable secret 5\b") or cfg.search(r"^enable secret 0\b")
        out.append(F("AAA-11", d, "Enable secret uses a strong hash algorithm (Type 8/9)",
                      Status.FAIL if weak_secret else Status.PASS,
                      Severity.HIGH,
                      recommendation="Use 'enable algorithm-type scrypt secret ...' (Type 9) or SHA-256 (Type 8) "
                                     "instead of Type 5 (MD5) or plaintext.",
                      fix_command="enable algorithm-type scrypt secret <strong-secret>"))

    ctx.set("aaa_new_model", aaa_new_model)
    return out


def check_local_users(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / Local Users"
    out: list[Finding] = []
    user_lines = cfg.search_lines(r"^username \S+ ")

    weak_type_users = []
    generic_users = []
    priv15_users = []
    generic_list = policy["generic_usernames"]

    for line in user_lines:
        m = re.match(r"^username (\S+)", line, re.I)
        if not m:
            continue
        uname = m.group(1)
        if uname.lower() in generic_list:
            generic_users.append(uname)
        type_m = re.search(r"(secret|password)\s+(\d+)\s", line, re.I)
        if type_m and type_m.group(2) in ("0", "5", "7"):
            weak_type_users.append(f"{uname}  (type {type_m.group(2)})")
        if re.search(r"privilege 15", line, re.I):
            priv15_users.append(uname)

    out.append(F("USR-01", d, "Local accounts use strong secret type (Type 8/9, not 0/5/7)",
                  Status.FAIL if weak_type_users else (Status.PASS if user_lines else Status.NA),
                  Severity.HIGH, evidence=weak_type_users,
                  evidence_label="Accounts using a weak/reversible secret type",
                  recommendation="Recreate accounts with 'username <name> privilege <n> algorithm-type scrypt secret <pw>'.",
                  fix_command="no username <name>\n"
                              "username <name> privilege <n> algorithm-type scrypt secret <strong-password>\n"
                              "! Repeat for each account listed above."))
    out.append(F("USR-02", d, "No generic/default local usernames (admin, cisco, test, ...)",
                  Status.FAIL if generic_users else (Status.PASS if user_lines else Status.NA),
                  Severity.HIGH, evidence=generic_users,
                  evidence_label="Generic/default account names found",
                  recommendation="Rename generic accounts to named, individually-attributable accounts.",
                  fix_command="no username <generic-name>\n"
                              "username <first.last> privilege <n> algorithm-type scrypt secret <strong-password>"))
    out.append(F("USR-03", d, f"Privilege-15 local account count ({len(priv15_users)})",
                  Status.PASS,
                  Severity.INFO, evidence=priv15_users,
                  evidence_label="Privilege-15 accounts found",
                  recommendation="Review whether every privilege-15 local account is still required; "
                                 "prefer AAA-based authorization over broad local privilege 15."))
    return out


def check_ssh_and_vty(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / SSH & VTY"
    out: list[Finding] = []

    ssh_v2 = cfg.search(r"^ip ssh version 2\b")
    out.append(F("SSH-01", d, "SSH version 2 explicitly configured",
                  Status.PASS if ssh_v2 else Status.FAIL,
                  Severity.HIGH,
                  recommendation="Configure 'ip ssh version 2'.",
                  fix_command="ip ssh version 2"))

    vty_blocks = cfg.get_blocks("line vty")
    telnet_allowed = False
    telnet_allowed_lines = []
    vty_without_acl = []
    vty_no_timeout = []
    ssh_enabled_anywhere = ssh_v2 or cfg.search(r"^ip ssh ")
    for blk in vty_blocks:
        transport = blk.find(r"transport input (\S.*)")
        if transport and re.search(r"\btelnet\b", transport.group(1), re.I):
            telnet_allowed = True
            telnet_allowed_lines.append(blk.header)
        if not blk.has(r"access-class \S+ in"):
            vty_without_acl.append(blk.header)
        timeout_m = blk.find(r"exec-timeout (\d+) (\d+)")
        if not timeout_m or (timeout_m.group(1) == "0" and timeout_m.group(2) == "0"):
            vty_no_timeout.append(blk.header)

    out.append(F("SSH-02", d, "Telnet disabled on all VTY lines",
                  Status.FAIL if telnet_allowed else Status.PASS,
                  Severity.CRITICAL, evidence=telnet_allowed_lines,
                  evidence_label="VTY line blocks that still allow Telnet",
                  recommendation="Set 'transport input ssh' only on every VTY line block.",
                  fix_command="line vty 0 15\n transport input ssh\n! Repeat for each VTY block listed above."))

    vty_acl_present = bool(vty_blocks) and not vty_without_acl
    out.append(F("SSH-03", d, "VTY lines restricted by access-class ACL",
                  Status.FAIL if vty_without_acl else (Status.PASS if vty_blocks else Status.NA),
                  Severity.HIGH, evidence=vty_without_acl,
                  evidence_label="VTY line blocks with no access-class ACL",
                  recommendation="Apply 'access-class <mgmt-acl> in' to every VTY line block.",
                  fix_command="ip access-list standard MGMT-ACL\n"
                              " permit <trusted-mgmt-subnet> <wildcard-mask>\n"
                              "!\n"
                              "line vty 0 15\n"
                              " access-class MGMT-ACL in\n"
                              "! Repeat the access-class line for each VTY block listed above."))

    out.append(F("SSH-04", d, "VTY exec-timeout configured (not 0 0 / infinite)",
                  Status.FAIL if vty_no_timeout else (Status.PASS if vty_blocks else Status.NA),
                  Severity.MEDIUM, evidence=vty_no_timeout,
                  evidence_label="VTY line blocks with no bounded exec-timeout",
                  recommendation=f"Set 'exec-timeout' on VTY lines to <= {policy['vty_exec_timeout_max_minutes']} minutes.",
                  fix_command=f"line vty 0 15\n exec-timeout {policy['vty_exec_timeout_max_minutes']} 0"))

    ssh_timeout_m = re.search(r"^ip ssh time-out (\d+)", cfg.text, re.M | re.I)
    ssh_timeout_ok = bool(ssh_timeout_m) and int(ssh_timeout_m.group(1)) <= policy["ssh_timeout_max_seconds"]
    out.append(F("SSH-05", d, "SSH session timeout configured and bounded",
                  Status.PASS if ssh_timeout_ok else Status.FAIL,
                  Severity.LOW,
                  recommendation=f"Configure 'ip ssh time-out <= {policy['ssh_timeout_max_seconds']}'.",
                  fix_command=f"ip ssh time-out {policy['ssh_timeout_max_seconds']}"))

    retries_m = re.search(r"^ip ssh authentication-retries (\d+)", cfg.text, re.M | re.I)
    retries_ok = bool(retries_m) and int(retries_m.group(1)) <= policy["ssh_auth_retries_max"]
    out.append(F("SSH-06", d, "SSH authentication retry limit configured",
                  Status.PASS if retries_ok else Status.FAIL,
                  Severity.LOW,
                  recommendation=f"Configure 'ip ssh authentication-retries <= {policy['ssh_auth_retries_max']}'.",
                  fix_command=f"ip ssh authentication-retries {policy['ssh_auth_retries_max']}"))

    out.append(F("SSH-07", d, "RSA/ECDSA key size >= policy minimum",
                  Status.MANUAL, Severity.MEDIUM,
                  detail="Key modulus is generally set via the interactive 'crypto key generate rsa modulus <n>' "
                         "exec command and is usually NOT reflected in running-config text. Verify separately with "
                         "'show crypto key mypubkey rsa' on the live device.",
                  recommendation=f"Confirm RSA key size is >= {policy['min_rsa_key_bits']} bits (or ECDSA in use)."))

    algo_restricted = cfg.search(r"^ip ssh server algorithm (kex|encryption|mac)")
    out.append(F("SSH-08", d, "SSH KEX/cipher/MAC algorithms explicitly restricted",
                  Status.PASS if algo_restricted else Status.FAIL,
                  Severity.LOW,
                  recommendation="Restrict 'ip ssh server algorithm kex|encryption|mac' to modern, strong algorithms only.",
                  fix_command="ip ssh server algorithm kex ecdh-sha2-nistp256 diffie-hellman-group16-sha512\n"
                              "ip ssh server algorithm encryption aes256-ctr aes256-gcm\n"
                              "ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512"))

    ctx.set("ssh_enabled", ssh_enabled_anywhere)
    ctx.set("telnet_enabled", telnet_allowed)
    ctx.set("vty_acl_present", vty_acl_present)
    return out


def check_http(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / HTTP(S)"
    out: list[Finding] = []
    http_disabled = cfg.search(r"^no ip http server\b")
    http_enabled = cfg.search(r"^ip http server\b")
    out.append(F("HTTP-01", d, "HTTP server disabled",
                  Status.FAIL if (http_enabled and not http_disabled) else Status.PASS,
                  Severity.HIGH,
                  recommendation="Configure 'no ip http server'; use HTTPS only if a WebUI is required.",
                  fix_command="no ip http server"))

    https_enabled = cfg.search(r"^ip http secure-server\b")
    if https_enabled:
        acl_ref = re.search(r"^ip http access-class \S+", cfg.text, re.M | re.I)
        out.append(F("HTTP-02", d, "HTTPS server restricted by ACL",
                      Status.PASS if acl_ref else Status.FAIL,
                      Severity.MEDIUM,
                      recommendation="Apply 'ip http access-class <mgmt-acl>' when HTTPS/WebUI is enabled.",
                      fix_command="ip http access-class MGMT-ACL"))
    return out


def check_snmp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / SNMP"
    out: list[Finding] = []

    default_comm = cfg.search_lines(r"^snmp-server community (public|private)\b")
    out.append(F("SNMP-01", d, "No default community strings (public/private)",
                  Status.FAIL if default_comm else Status.PASS,
                  Severity.CRITICAL, evidence=default_comm,
                  evidence_label="Default community strings found",
                  recommendation="Remove default community strings immediately; migrate to SNMPv3.",
                  fix_command="no snmp-server community public\nno snmp-server community private"))

    v3_groups = cfg.search_lines(r"^snmp-server group \S+ v3")
    any_v2c_community = cfg.search(r"^snmp-server community \S+")
    community_lines = cfg.search_lines(r"^snmp-server community \S+")
    snmpv3_configured = bool(v3_groups)
    out.append(F("SNMP-02", d, "SNMPv3 in use (not v1/v2c community strings)",
                  Status.PASS if (snmpv3_configured and not any_v2c_community) else
                  (Status.FAIL if any_v2c_community else Status.NA),
                  Severity.HIGH, evidence=community_lines,
                  evidence_label="Remaining v1/v2c community strings",
                  recommendation="Migrate fully to SNMPv3 with auth+priv; remove all v1/v2c community strings.",
                  fix_command="no snmp-server community <string>\n"
                              "snmp-server group SNMP-ADMINS v3 priv\n"
                              "snmp-server user <name> SNMP-ADMINS v3 auth sha <auth-pass> priv aes 256 <priv-pass>"))

    noauth_users = cfg.search_lines(r"^snmp-server user \S+ \S+ v3 noauth")
    out.append(F("SNMP-03", d, "SNMPv3 users configured with auth+priv (not noauth)",
                  Status.FAIL if noauth_users else (Status.PASS if v3_groups else Status.NA),
                  Severity.HIGH, evidence=noauth_users,
                  evidence_label="SNMPv3 users configured without auth/priv",
                  recommendation="Configure SNMPv3 users with 'auth <algo> ... priv <algo> ...', avoid 'noauth'.",
                  fix_command="no snmp-server user <name> <group> v3\n"
                              "snmp-server user <name> <group> v3 auth sha <auth-pass> priv aes 256 <priv-pass>"))

    snmp_lines = cfg.search_lines(r"^snmp-server (community|host)")
    out.append(F("SNMP-04", d, "SNMP access restricted by ACL",
                  Status.MANUAL, Severity.MEDIUM, evidence=snmp_lines,
                  evidence_label="Current SNMP community/host lines (verify ACL binding manually)",
                  detail="Heuristic only -- verify manually whether an access-list is bound to the "
                          "community/group/host lines above.",
                  recommendation="Bind an ACL to 'snmp-server community'/'group'/'host' restricting source hosts.",
                  fix_command="ip access-list standard SNMP-ACL\n permit <trusted-nms-subnet> <wildcard-mask>\n!\n"
                              "snmp-server community <string> RO SNMP-ACL"))

    ctx.set("snmpv3_configured", snmpv3_configured and not any_v2c_community)
    ctx.set("snmp_acl_present", None)  # left as manual review; not used in a hard correlation rule
    return out


def check_ntp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / NTP"
    out: list[Finding] = []
    ntp_auth = cfg.search(r"^ntp authenticate\b")
    out.append(F("NTP-01", d, "NTP authentication enabled", Status.PASS if ntp_auth else Status.FAIL,
                  Severity.MEDIUM, recommendation="Configure 'ntp authenticate' with a trusted key.",
                  fix_command="ntp authenticate"))
    ntp_key = cfg.search(r"^ntp authentication-key \d+ md5")
    out.append(F("NTP-02", d, "NTP authentication key configured", Status.PASS if ntp_key else Status.FAIL,
                  Severity.MEDIUM, recommendation="Configure 'ntp authentication-key <id> md5 <key>' + 'ntp trusted-key <id>'.",
                  fix_command="ntp authentication-key 1 md5 <strong-key>\nntp trusted-key 1"))
    ntp_servers = cfg.search_lines(r"^ntp server \S+")
    out.append(F("NTP-03", d, "At least one NTP server configured",
                  Status.PASS if ntp_servers else Status.FAIL, Severity.LOW, evidence=ntp_servers,
                  evidence_label="Current NTP server lines",
                  recommendation="Configure at least two trusted NTP servers for accurate log correlation.",
                  fix_command="ntp server <trusted-ntp-server-1>\nntp server <trusted-ntp-server-2>"))
    ntp_acl = cfg.search(r"^ntp access-group")
    out.append(F("NTP-04", d, "NTP access restricted by ACL", Status.PASS if ntp_acl else Status.FAIL,
                  Severity.LOW, recommendation="Configure 'ntp access-group peer|query-only <acl>'.",
                  fix_command="ip access-list standard NTP-ACL\n permit <trusted-ntp-server>\n!\nntp access-group peer NTP-ACL"))
    return out


def check_logging(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / Logging"
    out: list[Finding] = []
    log_host = cfg.search_lines(r"^logging (host )?\S+")
    out.append(F("LOG-01", d, "Remote syslog host(s) configured",
                  Status.PASS if log_host else Status.FAIL, Severity.HIGH, evidence=log_host,
                  evidence_label="Current logging destination lines",
                  recommendation="Configure 'logging host <syslog-server>'.",
                  fix_command="logging host <syslog-server-ip>"))
    ts = cfg.search(r"^service timestamps")
    out.append(F("LOG-02", d, "Timestamps enabled on log/debug messages",
                  Status.PASS if ts else Status.FAIL, Severity.LOW,
                  recommendation="Configure 'service timestamps log datetime msec localtime show-timezone'.",
                  fix_command="service timestamps log datetime msec localtime show-timezone\n"
                              "service timestamps debug datetime msec localtime show-timezone"))
    on_fail = cfg.search(r"^login on-failure log")
    on_success = cfg.search(r"^login on-success log")
    out.append(F("LOG-03", d, "Failed login attempts logged", Status.PASS if on_fail else Status.FAIL,
                  Severity.MEDIUM, recommendation="Configure 'login on-failure log'.",
                  fix_command="login on-failure log"))
    out.append(F("LOG-04", d, "Successful login attempts logged", Status.PASS if on_success else Status.FAIL,
                  Severity.LOW, recommendation="Configure 'login on-success log'.",
                  fix_command="login on-success log"))
    return out


def check_banners(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / Banners"
    out: list[Finding] = []
    has_login_or_motd = "login" in cfg.banners or "motd" in cfg.banners
    out.append(F("BAN-01", d, "Login/MOTD banner present",
                  Status.PASS if has_login_or_motd else Status.FAIL, Severity.LOW,
                  recommendation="Configure a login/MOTD banner with an appropriate legal notice.",
                  fix_command="banner login ^\n"
                              "Authorized access only. All activity may be monitored and reported.\n"
                              "^"))
    return out


def check_dns(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / DNS"
    out: list[Finding] = []
    lookup_enabled = cfg.search(r"^ip domain lookup\b") and not cfg.search(r"^no ip domain lookup\b")
    name_servers = cfg.search_lines(r"^ip name-server\b")
    if not lookup_enabled:
        out.append(F("DNS-01", d, "DNS lookup posture", Status.PASS, Severity.INFO,
                      detail="'ip domain lookup' is disabled (or not enabled) -- lowest-risk posture.",
                      recommendation="No action needed unless DNS resolution is actually required."))
    elif name_servers:
        out.append(F("DNS-01", d, "DNS lookup enabled with explicit trusted name-server(s)",
                      Status.PASS, Severity.INFO, evidence=name_servers,
                      evidence_label="Configured name-servers",
                      recommendation="Confirm the configured name-servers are trusted, internal resolvers."))
    else:
        out.append(F("DNS-01", d, "DNS lookup enabled without an explicit trusted name-server",
                      Status.FAIL, Severity.MEDIUM,
                      recommendation="Either disable 'ip domain lookup' or configure explicit trusted 'ip name-server' entries.",
                      fix_command="ip name-server <trusted-internal-dns-server>\n"
                                  "! OR, if DNS resolution isn't actually needed:\n"
                                  "no ip domain lookup"))
    return out


def check_mpp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / MPP"
    out: list[Finding] = []
    mpp = cfg.search(r"^management-interface \S+ allow")
    out.append(F("MPP-01", d, "Management Plane Protection (MPP) configured",
                  Status.PASS if mpp else Status.NA, Severity.LOW,
                  recommendation="Optional hardening: restrict management protocols to a specific interface via MPP.",
                  fix_command="control-plane host\n"
                              " management-interface <mgmt-interface> allow ssh https snmp"))
    return out


def check_mgmt_exposure_matrix(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / Exposure Matrix"
    out: list[Finding] = []

    probes = [
        ("EXP-RESTCONF", "RESTCONF", r"^restconf\b", Severity.MEDIUM, "no restconf"),
        ("EXP-NETCONF", "NETCONF-YANG", r"^netconf-yang\b", Severity.MEDIUM, "no netconf-yang"),
        ("EXP-GNMI", "gNMI", r"\bgnmi-yang\b|\bgnmi\s", Severity.MEDIUM, "no gnmi-yang"),
        ("EXP-IOX", "IOx / App-Hosting", r"^iox\b", Severity.LOW, "no iox"),
        ("EXP-TFTP", "TFTP server", r"^tftp-server\b", Severity.HIGH, "no tftp-server"),
        ("EXP-FTP", "FTP server", r"^ftp-server enable\b", Severity.HIGH, "no ftp-server enable"),
        ("EXP-SCP", "SCP server", r"^ip scp server enable\b", Severity.LOW, "no ip scp server enable"),
    ]
    iox_present = False
    for check_id, label, pattern, sev, disable_cmd in probes:
        found = cfg.search(pattern)
        if check_id == "EXP-IOX":
            iox_present = found
        if not found:
            out.append(F(check_id, d, f"{label}: not enabled", Status.PASS, Severity.INFO))
            continue
        out.append(F(check_id, d, f"{label} is enabled -- confirm ACL/VRF/AuthN/Encryption are all in place",
                      Status.FAIL, sev,
                      recommendation=f"If {label} is required, restrict it with an ACL/VRF and strong authentication; "
                                     f"disable it otherwise.",
                      fix_command=f"{disable_cmd}\n! Only if {label} is not actually required on this device."))

    guestshell_hint = cfg.search(r"\bguestshell\b")
    out.append(F("EXP-GUESTSHELL", d, "GuestShell reference found in config",
                  Status.MANUAL if guestshell_hint else Status.PASS,
                  Severity.LOW,
                  detail="GuestShell is normally enabled via an exec-level command, not persisted in running-config; "
                         "this only flags incidental references (e.g. app-hosting resource profiles).",
                  recommendation="Verify GuestShell status live with 'show guestshell'; disable if unused."))

    ctx.set("guestshell_iox_present", bool(guestshell_hint) and iox_present)
    return out


def check_password_security(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Password Security"
    out: list[Finding] = []
    svc_enc = cfg.search(r"^service password-encryption\b")
    out.append(F("PWD-01", d, "service password-encryption enabled",
                  Status.PASS if svc_enc else Status.FAIL, Severity.MEDIUM,
                  recommendation="Configure 'service password-encryption' as a baseline (Type 7 is weak but "
                                 "better than plaintext for legacy password types).",
                  fix_command="service password-encryption"))

    type7 = cfg.search_lines(r"password 7 \S+")
    out.append(F("PWD-02", d, "No Type 7 (reversible) passwords in use",
                  Status.FAIL if type7 else Status.PASS, Severity.HIGH, evidence=type7,
                  evidence_label="Lines using Type 7 (reversible) passwords",
                  recommendation="Migrate any Type 7 passwords to Type 8/9 secrets or Type 6 (AES) where applicable.",
                  fix_command="! For local user accounts:\n"
                              "username <name> algorithm-type scrypt secret <strong-password>\n"
                              "! For protocol keys (routing/NTP/etc.), use Type 6 instead:\n"
                              "key config-key password-encrypt <master-key>\npassword encryption aes"))

    type5 = cfg.search_lines(r"(secret|password) 5 \S+")
    out.append(F("PWD-03", d, "No Type 5 (MD5, weak) secrets in use",
                  Status.FAIL if type5 else Status.PASS, Severity.MEDIUM, evidence=type5,
                  evidence_label="Lines using Type 5 (MD5) secrets",
                  recommendation="Migrate Type 5 secrets to Type 8/9 (scrypt/SHA-256).",
                  fix_command="enable algorithm-type scrypt secret <strong-secret>\n"
                              "username <name> algorithm-type scrypt secret <strong-password>"))

    min_len = cfg.search(r"^security passwords min-length")
    out.append(F("PWD-04", d, "Minimum password length policy enforced",
                  Status.PASS if min_len else Status.FAIL, Severity.LOW,
                  recommendation="Configure 'security passwords min-length <n>' (e.g. 12+).",
                  fix_command="security passwords min-length 12"))
    return out


# =============================================================================
# 5. DOMAIN CHECKS -- LAYER 2 SECURITY
# =============================================================================

def check_port_security(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Port Security"
    out: list[Finding] = []
    access_ports = [b for b in cfg.physical_interfaces()
                     if cfg.is_access_port(b) and not cfg.looks_like_uplink(b)]

    no_portsec = []
    bad_max = []
    no_sticky = []
    weak_violation = []
    any_portsec_enabled = False

    for blk in access_ports:
        if not blk.has(r"switchport port-security\b"):
            no_portsec.append(ifname(blk.header))
            continue
        any_portsec_enabled = True
        has_voice = blk.has(r"switchport voice vlan")
        max_allowed = policy["port_security_max_hosts_voice"] if has_voice else policy["port_security_max_hosts_data"]
        max_m = blk.find(r"switchport port-security maximum (\d+)")
        if max_m and int(max_m.group(1)) > max_allowed:
            bad_max.append(f"{ifname(blk.header)}  (maximum {max_m.group(1)}, policy allows <= {max_allowed})")
        if not blk.has(r"switchport port-security mac-address sticky"):
            no_sticky.append(ifname(blk.header))
        if blk.has(r"switchport port-security violation protect\b"):
            weak_violation.append(ifname(blk.header))

    out.append(F("L2PS-01", d, "Port Security enabled on access ports",
                  Status.FAIL if no_portsec else (Status.PASS if access_ports else Status.NA),
                  Severity.HIGH, evidence=no_portsec,
                  evidence_label="Port Security DISABLED on these access interfaces",
                  detail="Heuristic: excludes trunk ports and ports whose description suggests an uplink; "
                          "verify any remaining false positives manually." if access_ports else "",
                  recommendation="Enable 'switchport port-security' on every genuine access port.",
                  fix_command="interface <interface>\n"
                              " switchport port-security\n"
                              " switchport port-security maximum 1\n"
                              " switchport port-security violation restrict\n"
                              " switchport port-security mac-address sticky\n"
                              "! Repeat for each interface listed above.\n"
                              "! Use 'maximum 2' instead of 1 on ports with a voice VLAN configured."))

    out.append(F("L2PS-02", d, "Port Security maximum MAC count within policy",
                  Status.FAIL if bad_max else (Status.PASS if any_portsec_enabled else Status.NA),
                  Severity.MEDIUM, evidence=bad_max,
                  evidence_label="Interfaces with maximum MAC count above policy",
                  recommendation=f"Set maximum to {policy['port_security_max_hosts_data']} on data-only ports, "
                                 f"{policy['port_security_max_hosts_voice']} where a voice VLAN is present.",
                  fix_command=f"interface <interface>\n"
                              f" switchport port-security maximum {policy['port_security_max_hosts_data']}\n"
                              f"! Use {policy['port_security_max_hosts_voice']} instead if a voice VLAN is present on that port."))

    out.append(F("L2PS-03", d, "Port Security uses sticky MAC learning",
                  Status.FAIL if no_sticky else (Status.PASS if any_portsec_enabled else Status.NA),
                  Severity.LOW, evidence=no_sticky,
                  evidence_label="Interfaces without sticky MAC learning",
                  recommendation="Use 'switchport port-security mac-address sticky' where static learning is appropriate.",
                  fix_command="interface <interface>\n"
                              " switchport port-security mac-address sticky\n"
                              "! Repeat for each interface listed above."))

    out.append(F("L2PS-04", d, "Port Security violation action is not 'protect' (silent)",
                  Status.FAIL if weak_violation else (Status.PASS if any_portsec_enabled else Status.NA),
                  Severity.LOW, evidence=weak_violation,
                  evidence_label="Interfaces using the silent 'protect' violation action",
                  recommendation="Prefer 'shutdown' or 'restrict' (both log/alert) over 'protect' (silently drops, no log).",
                  fix_command="interface <interface>\n"
                              " switchport port-security violation restrict\n"
                              "! Use 'shutdown' instead of 'restrict' if you want the port err-disabled on violation."))

    ctx.set("port_security_any_without_sticky", bool(no_sticky) and any_portsec_enabled)
    return out



def check_stp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Spanning Tree"
    out: list[Finding] = []
    access_ports = [b for b in cfg.physical_interfaces() if cfg.is_access_port(b)]
    global_bpduguard = cfg.search(r"^spanning-tree portfast bpduguard default")

    no_bpduguard = []
    for blk in access_ports:
        if global_bpduguard:
            continue
        if not blk.has(r"spanning-tree bpduguard enable"):
            no_bpduguard.append(ifname(blk.header))
    out.append(F("STP-01", d, "BPDU Guard enabled on access/edge ports",
                  Status.FAIL if (no_bpduguard and not global_bpduguard) else Status.PASS,
                  Severity.HIGH, evidence=no_bpduguard,
                  evidence_label="Access interfaces without BPDU Guard",
                  recommendation="Enable 'spanning-tree portfast bpduguard default' globally, or per-port "
                                 "'spanning-tree bpduguard enable' on every access port.",
                  fix_command="! Global (simplest, applies to every PortFast-enabled port):\n"
                              "spanning-tree portfast bpduguard default\n"
                              "!\n"
                              "! OR per-interface, repeated for each interface listed above:\n"
                              "interface <interface>\n"
                              " spanning-tree bpduguard enable"))

    root_guard_count = len(cfg.search_lines(r"spanning-tree guard root"))
    out.append(F("STP-02", d, "Root Guard present on at least one interface",
                  Status.PASS if root_guard_count else Status.FAIL, Severity.MEDIUM,
                  recommendation="Apply 'spanning-tree guard root' on uplinks toward the root bridge to prevent "
                                 "an unauthorized switch from taking over as root.",
                  fix_command="interface <uplink-interface>\n"
                              " spanning-tree guard root\n"
                              "! Apply on every uplink facing the root bridge, not access ports."))

    loop_guard = cfg.search(r"^spanning-tree loopguard default") or cfg.search(r"spanning-tree guard loop")
    out.append(F("STP-03", d, "Loop Guard configured (global default or per-interface)",
                  Status.PASS if loop_guard else Status.FAIL, Severity.MEDIUM,
                  recommendation="Configure 'spanning-tree loopguard default' globally where root/loop guard "
                                 "aren't both needed on the same ports.",
                  fix_command="spanning-tree loopguard default"))

    stp_mode = re.search(r"^spanning-tree mode (\S+)", cfg.text, re.M | re.I)
    out.append(F("STP-04", d, f"Spanning-tree mode: {stp_mode.group(1) if stp_mode else 'default (PVST+)'}",
                  Status.PASS, Severity.INFO,
                  recommendation="Rapid-PVST+ or MST recommended over legacy PVST+ for faster convergence."))

    return out



def check_udld(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / UDLD"
    out: list[Finding] = []
    global_udld = cfg.search(r"^udld (enable|aggressive)")
    per_intf_udld = cfg.search(r"udld port aggressive")
    out.append(F("UDLD-01", d, "UDLD enabled (globally or per fiber interface)",
                  Status.PASS if (global_udld or per_intf_udld) else Status.FAIL,
                  Severity.LOW,
                  recommendation="Enable 'udld aggressive' globally, or 'udld port aggressive' on fiber uplinks, "
                                 "to detect unidirectional link failures.",
                  fix_command="udld aggressive\n"
                              "! Global setting; applies to all fiber-capable interfaces."))
    return out


def check_storm_control(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Storm Control"
    out: list[Finding] = []
    access_ports = [b for b in cfg.physical_interfaces() if cfg.is_access_port(b)]
    missing = [ifname(b.header) for b in access_ports if not b.has(r"storm-control (broadcast|multicast|unicast)")]
    out.append(F("STORM-01", d, "Storm control configured on access ports",
                  Status.FAIL if missing else (Status.PASS if access_ports else Status.NA),
                  Severity.MEDIUM, evidence=missing,
                  evidence_label="Access interfaces without storm control",
                  recommendation="Configure 'storm-control broadcast|multicast|unicast level <x>' on access ports.",
                  fix_command="interface <interface>\n"
                              " storm-control broadcast level 1.00\n"
                              " storm-control multicast level 1.00\n"
                              " storm-control action trap\n"
                              "! Repeat for each interface listed above; tune the level to your traffic baseline."))
    return out


def check_dhcp_snooping(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / DHCP Snooping"
    out: list[Finding] = []
    enabled = cfg.search(r"^ip dhcp snooping\b(?! vlan)") or cfg.search(r"^ip dhcp snooping$")
    vlan_scoped = cfg.search_lines(r"^ip dhcp snooping vlan\b")
    out.append(F("DHCPSNOOP-01", d, "DHCP Snooping enabled globally",
                  Status.PASS if enabled else Status.FAIL, Severity.CRITICAL,
                  recommendation="Configure 'ip dhcp snooping' globally.",
                  fix_command="ip dhcp snooping"))
    out.append(F("DHCPSNOOP-02", d, "DHCP Snooping scoped to specific VLANs",
                  Status.PASS if vlan_scoped else Status.FAIL, Severity.MEDIUM, evidence=vlan_scoped,
                  evidence_label="Current VLAN-scoping lines found",
                  recommendation="Configure 'ip dhcp snooping vlan <list>' to scope enforcement.",
                  fix_command="ip dhcp snooping vlan <vlan-list>\n! e.g. ip dhcp snooping vlan 10,20,30"))

    access_ports = [b for b in cfg.physical_interfaces() if cfg.is_access_port(b)]
    trusted_ports = [b for b in cfg.physical_interfaces() if b.has(r"ip dhcp snooping trust")]
    bad_rate = []
    missing_rate = []
    lo = policy["dhcp_snooping_rate_limit_min"]
    rec_hi = policy["dhcp_snooping_rate_limit_recommended_max"]
    hard_hi = policy["dhcp_snooping_rate_limit_hard_max"]
    for blk in access_ports:
        if blk in trusted_ports:
            continue
        m = blk.find(r"ip dhcp snooping limit rate (\d+)")
        if not m:
            if enabled:
                missing_rate.append(ifname(blk.header))
            continue
        rate = int(m.group(1))
        if rate < lo or rate > hard_hi:
            bad_rate.append(f"{ifname(blk.header)}  (rate {rate}, policy: {lo}-{hard_hi}, recommended <= {rec_hi})")
        elif rate > rec_hi:
            bad_rate.append(f"{ifname(blk.header)}  (rate {rate}, above recommended {rec_hi}, within hard max {hard_hi})")

    out.append(F("DHCPSNOOP-03", d, "Untrusted ports have a rate limit configured",
                  Status.FAIL if missing_rate else (Status.PASS if (access_ports and enabled) else Status.NA),
                  Severity.MEDIUM, evidence=missing_rate,
                  evidence_label="Untrusted interfaces with no DHCP Snooping rate limit",
                  recommendation=f"Configure 'ip dhcp snooping limit rate <n>' ({lo}-{rec_hi} recommended) on untrusted access ports.",
                  fix_command=f"interface <interface>\n"
                              f" ip dhcp snooping limit rate {rec_hi}\n"
                              f"! Repeat for each interface listed above. Keep within {lo}-{rec_hi} pps "
                              f"({hard_hi} is a hard ceiling)."))
    out.append(F("DHCPSNOOP-04", d, "DHCP Snooping rate limit within policy range",
                  Status.FAIL if bad_rate else (Status.PASS if (access_ports and enabled) else Status.NA),
                  Severity.LOW, evidence=bad_rate,
                  evidence_label="Interfaces with a rate limit outside policy",
                  recommendation=f"Keep rate limit between {lo} and {rec_hi} pps; {hard_hi} is a hard ceiling.",
                  fix_command=f"interface <interface>\n ip dhcp snooping limit rate {rec_hi}"))

    trust_count = len(trusted_ports)
    total_physical = len(cfg.physical_interfaces())
    out.append(F("DHCPSNOOP-05", d, f"Trusted-port count is small relative to total interfaces ({trust_count}/{total_physical})",
                  Status.FAIL if (total_physical and trust_count > max(2, total_physical // 4)) else Status.PASS,
                  Severity.LOW,
                  evidence=[ifname(b.header) for b in trusted_ports] if (total_physical and trust_count > max(2, total_physical // 4)) else [],
                  evidence_label="Currently trusted interfaces",
                  recommendation="Only uplinks toward the legitimate DHCP server should be trusted; "
                                 "a large trusted-port count usually indicates over-trusting.",
                  fix_command="interface <non-uplink-interface>\n no ip dhcp snooping trust\n"
                              "! Remove trust from any interface that isn't a genuine uplink toward the DHCP server."))

    ctx.set("dhcp_snooping_enabled", enabled)
    return out


def check_dai(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Dynamic ARP Inspection"
    out: list[Finding] = []
    dai_vlans = cfg.search_lines(r"^ip arp inspection vlan\b")
    enabled = bool(dai_vlans)
    out.append(F("DAI-01", d, "DAI enabled on at least one VLAN",
                  Status.PASS if enabled else Status.FAIL, Severity.HIGH, evidence=dai_vlans,
                  evidence_label="Current DAI VLAN lines found",
                  recommendation="Configure 'ip arp inspection vlan <list>' on VLANs where DHCP Snooping is active.",
                  fix_command="ip arp inspection vlan <vlan-list>\n! e.g. ip arp inspection vlan 10,20,30"))

    dai_trust = {b.header for b in cfg.physical_interfaces() if b.has(r"ip arp inspection trust")}
    snoop_trust = {b.header for b in cfg.physical_interfaces() if b.has(r"ip dhcp snooping trust")}
    mismatch = [ifname(h) for h in dai_trust.symmetric_difference(snoop_trust)]
    out.append(F("DAI-02", d, "DAI trust state matches DHCP Snooping trust state",
                  Status.FAIL if mismatch else (Status.PASS if enabled else Status.NA),
                  Severity.MEDIUM, evidence=mismatch,
                  evidence_label="Interfaces where DAI trust and DHCP Snooping trust disagree",
                  recommendation="Trusted ports for DAI and DHCP Snooping should normally be identical (uplinks only).",
                  fix_command="interface <interface>\n"
                              " ip dhcp snooping trust\n"
                              " ip arp inspection trust\n"
                              "! Align both settings on genuine uplinks; remove both from anywhere else."))

    validation = cfg.search(r"^ip arp inspection validate")
    out.append(F("DAI-03", d, "DAI additional validation checks enabled (src-mac/dst-mac/ip)",
                  Status.PASS if validation else Status.FAIL, Severity.LOW,
                  recommendation="Configure 'ip arp inspection validate src-mac dst-mac ip'.",
                  fix_command="ip arp inspection validate src-mac dst-mac ip"))

    rate_missing = []
    hard_hi = policy["arp_inspection_rate_limit_hard_max"]
    bad_rate = []
    for blk in cfg.physical_interfaces():
        if blk.header in snoop_trust:
            continue
        m = blk.find(r"ip arp inspection limit rate (\d+)")
        if enabled and cfg.is_access_port(blk) and not m:
            rate_missing.append(ifname(blk.header))
        elif m and int(m.group(1)) > hard_hi:
            bad_rate.append(f"{ifname(blk.header)}  (rate {m.group(1)}, policy hard max {hard_hi})")
    out.append(F("DAI-04", d, "ARP inspection rate limit configured on untrusted ports",
                  Status.FAIL if rate_missing else (Status.PASS if enabled else Status.NA),
                  Severity.LOW, evidence=rate_missing,
                  evidence_label="Untrusted interfaces with no ARP inspection rate limit",
                  recommendation="Configure 'ip arp inspection limit rate <n>' on untrusted access ports.",
                  fix_command="interface <interface>\n ip arp inspection limit rate 15"))

    device_tracking = cfg.search(r"^device-tracking policy") or cfg.search(r"device-tracking attach-policy")
    ctx.set("dai_enabled", enabled)
    ctx.set("device_tracking_configured", bool(device_tracking))
    out.append(F("DAI-05", d, "Device Tracking (SISF) policy configured",
                  Status.PASS if device_tracking else Status.FAIL, Severity.LOW,
                  recommendation="Configure a 'device-tracking policy' and attach it where IPSG/DAI rely on the "
                                 "binding table.",
                  fix_command="device-tracking policy IPDT-POLICY\n"
                              " limit address-count 4\n"
                              " security-level glean\n"
                              "!\n"
                              "interface <interface>\n"
                              " device-tracking attach-policy IPDT-POLICY"))
    return out


def check_ip_source_guard(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / IP Source Guard"
    out: list[Finding] = []
    access_ports = [b for b in cfg.physical_interfaces() if cfg.is_access_port(b)]
    missing = [ifname(b.header) for b in access_ports if not b.has(r"ip verify source")]
    dhcp_snoop_enabled = ctx.get("dhcp_snooping_enabled", False)
    out.append(F("IPSG-01", d, "IP Source Guard enabled on untrusted access ports",
                  Status.FAIL if (missing and dhcp_snoop_enabled) else (Status.PASS if access_ports else Status.NA),
                  Severity.MEDIUM, evidence=missing,
                  evidence_label="Access interfaces without IP Source Guard",
                  recommendation="Configure 'ip verify source' on untrusted access ports (requires DHCP Snooping).",
                  fix_command="interface <interface>\n ip verify source\n! Repeat for each interface listed above."))
    return out



def check_trunk_native_vtp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Trunk, Native VLAN & VTP"
    out: list[Finding] = []
    trunks = [b for b in cfg.physical_interfaces() if cfg.is_trunk_port(b)]

    native_default = []
    native_changed = False
    for blk in trunks:
        m = blk.find(r"switchport trunk native vlan (\d+)")
        if not m or m.group(1) == "1":
            native_default.append(blk.header)
        else:
            native_changed = True
    out.append(F("TRUNK-01", d, "Native VLAN changed from default (VLAN 1)",
                  Status.FAIL if native_default else (Status.PASS if trunks else Status.NA),
                  Severity.MEDIUM, evidence=[ifname(h) for h in native_default],
                  evidence_label="Trunk interfaces still on native VLAN 1",
                  recommendation="Set an explicit, non-default native VLAN with 'switchport trunk native vlan <n>' "
                                 "(and ideally an unused VLAN).",
                  fix_command="interface <trunk-interface>\n"
                              " switchport trunk native vlan <unused-vlan-id>\n"
                              "! Repeat for each trunk listed above; use a dedicated unused VLAN, not VLAN 1."))

    allows_all = [ifname(b.header) for b in trunks if not b.has(r"switchport trunk allowed vlan")]
    out.append(F("TRUNK-02", d, "Trunk allowed-VLAN list explicitly pruned",
                  Status.FAIL if allows_all else (Status.PASS if trunks else Status.NA),
                  Severity.MEDIUM, evidence=allows_all,
                  evidence_label="Trunks with no pruned allowed-VLAN list (implicitly allowing all)",
                  recommendation="Configure 'switchport trunk allowed vlan <pruned-list>' on every trunk.",
                  fix_command="interface <trunk-interface>\n"
                              " switchport trunk allowed vlan <comma-separated-list>\n"
                              "! e.g. switchport trunk allowed vlan 10,20,30"))

    dtp_on = [ifname(b.header) for b in trunks if not b.has(r"switchport nonegotiate")]
    out.append(F("TRUNK-03", d, "DTP disabled on trunks (switchport nonegotiate)",
                  Status.FAIL if dtp_on else (Status.PASS if trunks else Status.NA),
                  Severity.LOW, evidence=dtp_on,
                  evidence_label="Trunks still negotiating via DTP",
                  recommendation="Configure 'switchport nonegotiate' on statically-configured trunks.",
                  fix_command="interface <trunk-interface>\n switchport nonegotiate"))

    vtp_mode = re.search(r"^vtp mode (\S+)", cfg.text, re.M | re.I)
    mode_val = vtp_mode.group(1).lower() if vtp_mode else "server"  # server is IOS default
    out.append(F("VTP-01", d, f"VTP mode is transparent/off (found: {mode_val})",
                  Status.PASS if mode_val in ("transparent", "off") else Status.FAIL,
                  Severity.MEDIUM,
                  recommendation="Set 'vtp mode transparent' unless VTP is deliberately and carefully managed.",
                  fix_command="vtp mode transparent"))

    ctx.set("native_vlan_changed", native_changed)
    ctx.set("trunk_allows_all_vlans", bool(allows_all))
    return out


def check_etherchannel(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / EtherChannel"
    out: list[Finding] = []
    static_on = cfg.search_lines(r"channel-group \d+ mode on\b")
    out.append(F("ECHAN-01", d, "EtherChannel members use LACP (not static 'mode on')",
                  Status.FAIL if static_on else Status.PASS, Severity.LOW, evidence=static_on,
                  evidence_label="Member interfaces using static 'mode on'",
                  recommendation="Prefer 'channel-group <n> mode active' (LACP) over static 'mode on' so "
                                 "misconfiguration is detected instead of silently forwarding/looping.",
                  fix_command="interface <member-interface>\n"
                              " channel-group <n> mode active\n"
                              "! Apply on every member of the port-channel, matching on both ends."))
    return out


# =============================================================================
# 6. DOMAIN CHECKS -- LAYER 3 SECURITY
# =============================================================================

def check_urpf(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / uRPF"
    out: list[Finding] = []
    urpf_lines = cfg.search_lines(r"ip verify unicast source reachable-via")
    out.append(F("URPF-01", d, "uRPF configured on at least one interface",
                  Status.PASS if urpf_lines else Status.FAIL, Severity.MEDIUM, evidence=urpf_lines,
                  evidence_label="Current uRPF lines found",
                  recommendation="Configure uRPF (strict on single-homed edge interfaces, loose on multi-homed) "
                                 "to prevent source-IP spoofing.",
                  fix_command="interface <edge-interface>\n"
                              " ip verify unicast source reachable-via rx\n"
                              "! Use 'reachable-via any' instead on multi-homed/asymmetric-routed interfaces."))
    loose = [l for l in urpf_lines if "any" in l]
    if loose:
        out.append(F("URPF-02", d, "Loose-mode uRPF in use -- confirm this is intentional",
                      Status.MANUAL, Severity.LOW, evidence=loose,
                      evidence_label="Interfaces using loose-mode uRPF",
                      recommendation="Loose mode is appropriate for multi-homed/asymmetric routing; strict mode "
                                     "is stronger where the topology allows it."))
    return out


def check_routing_auth(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / Routing Protocol Authentication"
    out: list[Finding] = []

    ospf_blocks = cfg.get_blocks("router ospf")
    if ospf_blocks:
        area_auth = any(b.has(r"area \S+ authentication") for b in ospf_blocks)
        intf_auth = cfg.search(r"ip ospf authentication")
        passive_default = any(b.has(r"passive-interface default") for b in ospf_blocks)
        out.append(F("RTAUTH-OSPF-01", d, "OSPF authentication configured (area or per-interface)",
                      Status.PASS if (area_auth or intf_auth) else Status.FAIL, Severity.HIGH,
                      recommendation="Configure OSPF MD5/SHA authentication at the area or interface level.",
                      fix_command="router ospf <process-id>\n"
                                  " area <area-id> authentication message-digest\n"
                                  "!\n"
                                  "interface <ospf-interface>\n"
                                  " ip ospf message-digest-key 1 md5 <key>\n"
                                  "! Prefer SHA where supported: 'ip ospf authentication key-chain <chain>' with a "
                                  "key chain configured for hmac-sha-256."))
        out.append(F("RTAUTH-OSPF-02", d, "OSPF 'passive-interface default' hygiene",
                      Status.PASS if passive_default else Status.FAIL, Severity.LOW,
                      recommendation="Use 'passive-interface default' + explicit 'no passive-interface' on real "
                                     "OSPF-speaking links, so new interfaces don't form adjacencies by accident.",
                      fix_command="router ospf <process-id>\n"
                                  " passive-interface default\n"
                                  " no passive-interface <interface-that-should-speak-ospf>"))

    eigrp_blocks = cfg.get_blocks("router eigrp")
    if eigrp_blocks:
        eigrp_auth = cfg.search(r"ip authentication (mode|key-chain) eigrp") or cfg.search(r"authentication mode (md5|hmac-sha-256)")
        out.append(F("RTAUTH-EIGRP-01", d, "EIGRP authentication configured",
                      Status.PASS if eigrp_auth else Status.FAIL, Severity.HIGH,
                      recommendation="Configure EIGRP HMAC/key-chain authentication on all EIGRP-speaking interfaces.",
                      fix_command="key chain EIGRP-KEYS\n"
                                  " key 1\n"
                                  "  key-string <strong-key>\n"
                                  "!\n"
                                  "interface <eigrp-interface>\n"
                                  " ip authentication mode eigrp <as-number> md5\n"
                                  " ip authentication key-chain eigrp <as-number> EIGRP-KEYS"))

    rip_blocks = cfg.get_blocks("router rip")
    if rip_blocks:
        rip_auth = cfg.search(r"ip rip authentication mode md5")
        out.append(F("RTAUTH-RIP-01", d, "RIP authentication configured",
                      Status.PASS if rip_auth else Status.FAIL, Severity.MEDIUM,
                      recommendation="Configure 'ip rip authentication mode md5' + key-chain on RIP interfaces.",
                      fix_command="key chain RIP-KEYS\n"
                                  " key 1\n"
                                  "  key-string <strong-key>\n"
                                  "!\n"
                                  "interface <rip-interface>\n"
                                  " ip rip authentication mode md5\n"
                                  " ip rip authentication key-chain RIP-KEYS"))

    bgp_blocks = cfg.get_blocks("router bgp")
    if bgp_blocks:
        neighbor_lines = cfg.search_lines(r"^\s*neighbor \S+ ")
        no_pw = [l.strip() for l in cfg.search_lines(r"neighbor \S+ remote-as")
                 if not any(re.search(re.escape(l.split()[1]) + r" password", x) for x in cfg.search_lines(r"neighbor \S+ password"))]
        ttl_sec = cfg.search(r"neighbor \S+ ttl-security hops")
        max_prefix = cfg.search(r"neighbor \S+ maximum-prefix")
        dampening = any(b.has(r"bgp dampening") for b in bgp_blocks)
        out.append(F("RTAUTH-BGP-01", d, "BGP neighbors use TCP MD5 authentication",
                      Status.FAIL if no_pw else (Status.PASS if neighbor_lines else Status.NA),
                      Severity.HIGH, evidence=no_pw,
                      evidence_label="BGP neighbor statements with no password configured",
                      recommendation="Configure 'neighbor <ip> password <secret>' on every eBGP/iBGP session.",
                      fix_command="router bgp <as-number>\n neighbor <peer-ip> password <strong-secret>"))
        out.append(F("RTAUTH-BGP-02", d, "BGP TTL Security (GTSM) in use",
                      Status.PASS if ttl_sec else Status.FAIL, Severity.MEDIUM,
                      recommendation="Configure 'neighbor <ip> ttl-security hops <n>' on eBGP sessions.",
                      fix_command="router bgp <as-number>\n neighbor <peer-ip> ttl-security hops 1"))
        out.append(F("RTAUTH-BGP-03", d, "BGP maximum-prefix limits configured",
                      Status.PASS if max_prefix else Status.FAIL, Severity.MEDIUM,
                      recommendation="Configure 'neighbor <ip> maximum-prefix <n>' to bound route-table impact "
                                     "of a misbehaving/compromised peer.",
                      fix_command="router bgp <as-number>\n neighbor <peer-ip> maximum-prefix <n> 80 restart 15"))
        out.append(F("RTAUTH-BGP-04", d, "BGP route flap dampening reviewed",
                      Status.MANUAL, Severity.LOW,
                      detail=f"Dampening is {'configured' if dampening else 'not configured'}.",
                      recommendation="Route dampening is a tradeoff (can suppress legitimate flapping routes); "
                                     "confirm this matches your operational intent rather than treating it as a "
                                     "simple pass/fail."))

    isis_blocks = cfg.get_blocks("router isis")
    if isis_blocks:
        isis_auth = cfg.search(r"isis authentication mode")
        out.append(F("RTAUTH-ISIS-01", d, "IS-IS authentication configured",
                      Status.PASS if isis_auth else Status.FAIL, Severity.HIGH,
                      recommendation="Configure 'isis authentication mode md5' (or key-chain based) globally/per-interface.",
                      fix_command="router isis\n"
                                  " authentication mode md5\n"
                                  " authentication key-chain ISIS-KEYS"))

    if not any([ospf_blocks, eigrp_blocks, rip_blocks, bgp_blocks, isis_blocks]):
        out.append(F("RTAUTH-00", d, "No dynamic routing protocol detected in running-config",
                      Status.NA, Severity.INFO))
    return out


def check_fhrp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / FHRP (HSRP/VRRP/GLBP)"
    out: list[Finding] = []
    hsrp_intfs = [b for b in cfg.interfaces() if b.has(r"standby \d+ ")]
    if hsrp_intfs:
        no_auth = [ifname(b.header) for b in hsrp_intfs if not b.has(r"standby \d+ authentication")]
        plaintext = [ifname(b.header) for b in hsrp_intfs
                     if b.has(r"standby \d+ authentication") and not b.has(r"standby \d+ authentication md5")]
        out.append(F("FHRP-HSRP-01", d, "HSRP authentication configured",
                      Status.FAIL if no_auth else Status.PASS, Severity.HIGH, evidence=no_auth,
                      evidence_label="HSRP interfaces without authentication",
                      recommendation="Configure 'standby <grp> authentication md5 key-string <key>' on every HSRP group.",
                      fix_command="interface <interface>\n"
                                  " standby <group> authentication md5 key-string <strong-key>\n"
                                  "! Repeat for each interface/group listed above."))
        out.append(F("FHRP-HSRP-02", d, "HSRP authentication uses MD5 (not plaintext)",
                      Status.FAIL if plaintext else (Status.PASS if not no_auth else Status.NA),
                      Severity.MEDIUM, evidence=plaintext,
                      evidence_label="HSRP interfaces using plaintext authentication",
                      recommendation="Replace plaintext HSRP authentication strings with MD5-based authentication.",
                      fix_command="interface <interface>\n"
                                  " standby <group> authentication md5 key-string <strong-key>"))

    vrrp_intfs = [b for b in cfg.interfaces() if b.has(r"vrrp \d+ ")]
    if vrrp_intfs:
        no_auth_v = [ifname(b.header) for b in vrrp_intfs if not b.has(r"vrrp \d+ authentication")]
        out.append(F("FHRP-VRRP-01", d, "VRRP authentication configured",
                      Status.FAIL if no_auth_v else Status.PASS, Severity.MEDIUM, evidence=no_auth_v,
                      evidence_label="VRRP interfaces without authentication",
                      recommendation="Configure VRRP authentication where the platform/version supports it "
                                     "(note: authentication was removed from later VRRPv3 RFCs -- rely on "
                                     "network segmentation if unsupported).",
                      fix_command="interface <interface>\n vrrp <group> authentication text <key>"))

    if not hsrp_intfs and not vrrp_intfs:
        out.append(F("FHRP-00", d, "No FHRP (HSRP/VRRP) detected in running-config", Status.NA, Severity.INFO))
    return out


def check_icmp_hardening(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / ICMP & IP Hardening"
    out: list[Finding] = []
    external_intfs = [b for b in cfg.physical_interfaces() if b.has(r"ip address")]

    no_redirects = [ifname(b.header) for b in external_intfs if not b.has(r"no ip redirects")]
    out.append(F("ICMP-01", d, "ICMP redirects disabled on routed interfaces",
                  Status.FAIL if no_redirects else (Status.PASS if external_intfs else Status.NA),
                  Severity.MEDIUM, evidence=no_redirects,
                  evidence_label="Routed interfaces still sending ICMP redirects",
                  recommendation="Configure 'no ip redirects' on routed interfaces (especially external-facing).",
                  fix_command="interface <interface>\n no ip redirects"))

    no_proxyarp = [ifname(b.header) for b in external_intfs if not b.has(r"no ip proxy-arp")]
    out.append(F("ICMP-02", d, "Proxy ARP disabled on routed interfaces (default is ON)",
                  Status.FAIL if no_proxyarp else (Status.PASS if external_intfs else Status.NA),
                  Severity.MEDIUM, evidence=no_proxyarp,
                  evidence_label="Routed interfaces still running Proxy ARP",
                  recommendation="Configure 'no ip proxy-arp' -- Proxy ARP defaults to enabled on Cisco IOS.",
                  fix_command="interface <interface>\n no ip proxy-arp"))

    no_unreach = [ifname(b.header) for b in external_intfs if not b.has(r"no ip unreachables")]
    out.append(F("ICMP-03", d, "ICMP unreachables disabled where appropriate",
                  Status.FAIL if no_unreach else (Status.PASS if external_intfs else Status.NA),
                  Severity.LOW, evidence=no_unreach,
                  evidence_label="Routed interfaces still sending ICMP unreachables",
                  recommendation="Configure 'no ip unreachables' on internet-facing interfaces to reduce recon/DoS surface.",
                  fix_command="interface <interface>\n no ip unreachables"))

    src_route = cfg.search(r"^no ip source-route\b")
    out.append(F("ICMP-04", d, "IP source-routing disabled globally",
                  Status.PASS if src_route else Status.FAIL, Severity.MEDIUM,
                  recommendation="Configure 'no ip source-route' globally.",
                  fix_command="no ip source-route"))

    tcp_intercept = cfg.search(r"^ip tcp intercept")
    out.append(F("ICMP-05", d, "TCP Intercept / SYN-flood protection reviewed",
                  Status.MANUAL, Severity.LOW,
                  detail=f"{'Configured' if tcp_intercept else 'Not configured'} -- only relevant on devices "
                          "actually fronting server subnets.",
                  recommendation="Configure 'ip tcp intercept' where this device protects server-side TCP endpoints."))
    return out


def check_acl_analysis(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / ACL Analysis"
    out: list[Finding] = []

    named_acls = cfg.get_blocks("ip access-list extended", "ip access-list standard")
    if not named_acls:
        out.append(F("ACL-00", d, "No named IP ACLs found in running-config", Status.NA, Severity.INFO))
        return out

    # Build the set of ACL names referenced anywhere else in the config.
    # This is necessarily a heuristic -- an ACL can be referenced from many
    # contexts (route-maps, NAT, crypto maps, ip tcp intercept, etc.) and this
    # list won't be exhaustive; false "unused" positives are possible, which
    # is why this check is LOW severity rather than HIGH/CRITICAL.
    referenced_names = set()
    ref_patterns = [
        r"ip access-group (\S+)", r"access-class (\S+)", r"match access-group name (\S+)",
        r"match access-group (\d+)", r"match address (\S+)", r"distribute-list (\S+)",
        r"ip tcp intercept list (\S+)", r"ip nat \S+ source list (\S+)",
        r"crypto map \S+ \d+ ipsec-isakmp[\s\S]{0,80}?match address (\S+)",
    ]
    for pat in ref_patterns:
        for m in re.finditer(pat, cfg.text, re.I):
            referenced_names.add(m.group(1))

    unused = []
    permissive = []
    dup_rules = []
    missing_log = []

    for blk in named_acls:
        name = blk.name().split()[-1] if blk.name() else blk.header
        if name not in referenced_names:
            unused.append(name)

        seen = set()
        for line in blk.lines:
            norm = re.sub(r"\s+", " ", line.strip().lower())
            if norm in seen:
                dup_rules.append(f"{name}:  {line.strip()}")
            seen.add(norm)
            if re.search(r"^permit ip any any\s*$", line.strip(), re.I):
                permissive.append(f"{name}:  {line.strip()}")
            if re.match(r"^deny ", line.strip(), re.I) and "log" not in line.lower():
                missing_log.append(f"{name}:  {line.strip()}")

    out.append(F("ACL-01", d, "Named ACLs are referenced somewhere in the config (not orphaned)",
                  Status.FAIL if unused else Status.PASS, Severity.LOW, evidence=unused,
                  evidence_label="ACLs defined but not referenced anywhere else in the config",
                  recommendation="Remove unused ACLs, or apply them if they were meant to be in use.",
                  fix_command="no ip access-list extended <acl-name>\n"
                              "! Remove if genuinely unused, or apply it where intended, e.g.:\n"
                              "interface <interface>\n ip access-group <acl-name> in"))
    out.append(F("ACL-02", d, "No unrestricted 'permit ip any any' entries",
                  Status.FAIL if permissive else Status.PASS, Severity.HIGH, evidence=permissive,
                  evidence_label="Overly permissive entries found",
                  recommendation="Replace broad 'permit ip any any' with the minimum necessary scope.",
                  fix_command="ip access-list extended <acl-name>\n"
                              " no permit ip any any\n"
                              " permit <protocol> <specific-source> <specific-destination> [eq <port>]\n"
                              "! Replace with the narrowest rule that satisfies the actual requirement."))
    out.append(F("ACL-03", d, "No exact-duplicate ACL entries",
                  Status.FAIL if dup_rules else Status.PASS, Severity.LOW, evidence=dup_rules,
                  evidence_label="Duplicate rules found",
                  recommendation="Remove duplicate ACEs -- they add no value and complicate review.",
                  fix_command="ip access-list extended <acl-name>\n"
                              " no <sequence-number-of-duplicate-line>\n"
                              "! Use 'show access-list <acl-name>' to get sequence numbers, then remove the duplicate(s)."))
    out.append(F("ACL-04", d, "Deny entries include 'log' where visibility is expected",
                  Status.MANUAL, Severity.LOW, evidence=missing_log,
                  evidence_label="Deny entries without 'log'",
                  detail="Flagged for review rather than a hard fail -- logging every deny can itself create a "
                          "CPU/log-volume risk (see Control Plane / High-CPU-Risk section).",
                  recommendation="Add 'log' selectively to deny rules where you specifically want visibility, "
                                 "not universally."))
    out.append(F("ACL-05", d, "Shadowed / fully-unreachable rule detection",
                  Status.MANUAL, Severity.INFO,
                  detail="Full shadow/unreachable-rule analysis requires wildcard-to-CIDR conversion and "
                          "protocol/port range overlap logic -- not implemented in this version. Roadmap item.",
                  recommendation="Review ACL rule order manually, most-specific-first, until this is automated."))
    return out


def check_object_tracking(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / Object Tracking"
    out: list[Finding] = []
    track_blocks = cfg.get_blocks("track ")
    if not track_blocks:
        out.append(F("TRACK-00", d, "No object tracking configured", Status.NA, Severity.INFO))
        return out

    sla_defs = {m for m in re.findall(r"^ip sla (\d+)", cfg.text, re.M | re.I)}
    broken = []
    unused = []
    all_refs = cfg.text
    for blk in track_blocks:
        track_id_m = re.match(r"track (\d+)", blk.header, re.I)
        track_id = track_id_m.group(1) if track_id_m else "?"
        sla_ref = blk.find(r"ip sla (\d+)") or re.match(r"track \d+ ip sla (\d+)", blk.header, re.I)
        if sla_ref:
            sla_num = sla_ref.group(1)
            if sla_num not in sla_defs:
                broken.append(f"{blk.header}: references non-existent 'ip sla {sla_num}'")
        if not re.search(rf"\btrack {re.escape(track_id)}\b", all_refs.replace(blk.header, "", 1)):
            unused.append(blk.header)

    out.append(F("TRACK-01", d, "Tracked objects reference an existing IP SLA entry",
                  Status.FAIL if broken else Status.PASS, Severity.HIGH, evidence=broken,
                  evidence_label="Track objects with a broken IP SLA reference",
                  recommendation="Fix or remove track objects pointing at a non-existent IP SLA -- the dependent "
                                 "FHRP/routing failover silently will not work.",
                  fix_command="ip sla <sla-number>\n"
                              " icmp-echo <target-ip>\n"
                              " frequency 10\n"
                              "ip sla schedule <sla-number> life forever start-time now\n"
                              "! Create the missing IP SLA entry referenced by the track object, or remove the track object."))
    out.append(F("TRACK-02", d, "No unused/orphaned track objects",
                  Status.FAIL if unused else Status.PASS, Severity.INFO, evidence=unused,
                  evidence_label="Track objects not referenced anywhere",
                  recommendation="Remove track objects that nothing (HSRP/VRRP/route) actually references.",
                  fix_command="no track <track-id>"))
    return out


# =============================================================================
# 7. DOMAIN CHECKS -- CONTROL PLANE (CoPP)
# =============================================================================

_COPP_CATEGORY_KEYWORDS = {
    "ICMP": [r"\bicmp\b"],
    "ROUTING": [r"\bospf\b", r"\beigrp\b", r"\bbgp\b", r"\brip\b", r"eq 179"],
    "ARP": [r"\barp\b"],
    "L2CTRL": [r"\bcdp\b", r"bpdu", r"\blldp\b", r"\bvtp\b"],
    "MGMT": [r"\bssh\b", r"\btelnet\b", r"\bsnmp\b", r"\bntp\b", r"eq 22", r"eq 23", r"eq 161", r"eq 123"],
    "DHCP": [r"\bdhcp\b", r"eq 67", r"eq 68"],
    "FHRP": [r"\bhsrp\b", r"\bvrrp\b", r"\bglbp\b", r"eq 1985"],
    "MCAST": [r"\bigmp\b", r"\bpim\b"],
}


def check_copp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Control Plane / CoPP"
    out: list[Finding] = []

    cp_blocks = cfg.get_blocks("control-plane")
    service_policy = None
    for blk in cp_blocks:
        m = blk.find(r"service-policy input (\S+)")
        if m:
            service_policy = m.group(1)
            break

    out.append(F("COPP-01", d, "CoPP service-policy applied to control-plane",
                  Status.PASS if service_policy else Status.FAIL, Severity.CRITICAL,
                  detail=f"Policy in use: {service_policy}" if service_policy else "",
                  recommendation="Apply a CoPP policy-map to the control-plane with 'service-policy input <name>'.",
                  fix_command="policy-map COPP-POLICY\n"
                              " class class-default\n"
                              "  police 8000 conform-action transmit exceed-action drop\n"
                              "!\n"
                              "control-plane\n"
                              " service-policy input COPP-POLICY\n"
                              "! This is a minimal starting policy -- see COPP-CLASS-* findings below to build "
                              "out per-protocol classes rather than relying on class-default alone."))

    if not service_policy:
        out.append(F("COPP-02", d, "Per-traffic-class CoPP coverage",
                      Status.NA, Severity.INFO,
                      detail="Skipped -- no CoPP policy is applied at all (see COPP-01)."))
        ctx.set("copp_configured", False)
        ctx.set("copp_class_coverage", 0)
        return out

    policy_blk = None
    for blk in cfg.get_blocks("policy-map"):
        if blk.name() == service_policy or blk.header.split(None, 1)[-1] == service_policy:
            policy_blk = blk
            break

    covered = set()
    if policy_blk:
        class_refs = re.findall(r"class (\S+)", policy_blk.body(), re.I)
        class_bodies = []
        acl_names_used = set()
        for cname in class_refs:
            for cm in cfg.get_blocks("class-map"):
                if cm.name().split()[-1] == cname or cname in cm.header:
                    class_bodies.append(cm.header + "\n" + cm.body())
                    acl_names_used.update(re.findall(r"access-group (?:name )?(\S+)", cm.body(), re.I))
        # Class-maps often reference an ACL by name rather than matching a protocol
        # directly (e.g. "match access-group name MGMT-ACL") -- resolve those ACLs
        # and pull their actual match criteria (ports/protocols) into the haystack too,
        # otherwise ACL-based classes are invisible to the keyword matcher below.
        acl_bodies = []
        for acl_blk in cfg.get_blocks("ip access-list", "mac access-list", "ipv6 access-list"):
            acl_name = acl_blk.name().split()[-1] if acl_blk.name() else ""
            if acl_name in acl_names_used:
                acl_bodies.append(acl_blk.body())
        haystack = policy_blk.body() + "\n" + "\n".join(class_bodies) + "\n" + "\n".join(acl_bodies)
        for category, patterns in _COPP_CATEGORY_KEYWORDS.items():
            if any(re.search(p, haystack, re.I) for p in patterns):
                covered.add(category)

    _COPP_FIX_EXAMPLES = {
        "ICMP": "class-map match-any CM-ICMP\n match protocol icmp\n!\n"
                "policy-map COPP-POLICY\n class CM-ICMP\n  police 64000 conform-action transmit exceed-action drop",
        "ROUTING": "ip access-list extended ACL-ROUTING\n permit ospf any any\n permit eigrp any any\n"
                   " permit tcp any any eq 179\n!\nclass-map match-any CM-ROUTING\n match access-group name ACL-ROUTING\n!\n"
                   "policy-map COPP-POLICY\n class CM-ROUTING\n  police 256000 conform-action transmit exceed-action drop",
        "ARP": "class-map CM-ARP\n match protocol arp\n!\n"
               "policy-map COPP-POLICY\n class CM-ARP\n  police rate 10 pps conform-action transmit exceed-action drop",
        "L2CTRL": "ip access-list extended ACL-L2CTRL\n permit udp any any eq 68\n!\n"
                  "class-map match-any CM-L2CTRL\n match access-group name ACL-L2CTRL\n!\n"
                  "policy-map COPP-POLICY\n class CM-L2CTRL\n  police 32000 conform-action transmit exceed-action drop\n"
                  "! CDP/BPDU/LLDP/VTP -- on IOS-XE these often ride the system-defined "
                  "'system-cpp-cdp'/'system-cpp-bpdu-range' classes; check 'show policy-map system-cpp'.",
        "MGMT": "ip access-list extended ACL-MGMT\n permit tcp any any eq 22\n permit udp any any eq 161\n"
                " permit udp any any eq 123\n!\nclass-map match-any CM-MGMT\n match access-group name ACL-MGMT\n!\n"
                "policy-map COPP-POLICY\n class CM-MGMT\n  police 32000 conform-action transmit exceed-action drop",
        "DHCP": "ip access-list extended ACL-DHCP\n permit udp any any eq 67\n permit udp any any eq 68\n!\n"
                "class-map match-all CM-DHCP\n match access-group name ACL-DHCP\n!\n"
                "policy-map COPP-POLICY\n class CM-DHCP\n  police 16000 conform-action transmit exceed-action drop",
        "FHRP": "ip access-list extended ACL-FHRP\n permit udp any host 224.0.0.2 eq 1985\n!\n"
                "class-map match-all CM-FHRP\n match access-group name ACL-FHRP\n!\n"
                "policy-map COPP-POLICY\n class CM-FHRP\n  police 64000 conform-action transmit exceed-action drop",
        "MCAST": "ip access-list extended ACL-MCAST\n permit pim any any\n permit igmp any any\n!\n"
                 "class-map match-any CM-MCAST\n match access-group name ACL-MCAST\n!\n"
                 "policy-map COPP-POLICY\n class CM-MCAST\n  police 64000 conform-action transmit exceed-action drop",
    }

    total_categories = len(_COPP_CATEGORY_KEYWORDS)
    for category in _COPP_CATEGORY_KEYWORDS:
        hit = category in covered
        out.append(F(f"COPP-CLASS-{category}", d, f"CoPP has a distinct traffic class for {category}",
                      Status.PASS if hit else Status.FAIL,
                      Severity.MEDIUM if category in ("ICMP", "ARP", "ROUTING", "MGMT") else Severity.LOW,
                      recommendation=f"Add a class-map/policy-map entry specifically policing {category} traffic "
                                     f"toward the control plane.",
                      fix_command=_COPP_FIX_EXAMPLES.get(category, "")))

    ctx.set("copp_configured", True)
    ctx.set("copp_class_coverage", len(covered))
    return out


def check_cpu_risk(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Control Plane / High CPU Risk Indicators"
    out: list[Finding] = []

    copp_configured = ctx.get("copp_configured", False)
    out.append(F("CPURISK-01", d, "CoPP configured (umbrella CPU-protection control)",
                  Status.PASS if copp_configured else Status.FAIL, Severity.CRITICAL,
                  recommendation="See COPP-01 -- this is the single biggest CPU-exhaustion risk factor."))

    eem_blocks = cfg.get_blocks("event manager applet")
    threshold = policy["eem_applet_count_warn_threshold"]
    out.append(F("CPURISK-02", d, f"EEM applet count within reason ({len(eem_blocks)} found, warn > {threshold})",
                  Status.FAIL if len(eem_blocks) > threshold else Status.PASS, Severity.MEDIUM,
                  evidence=[b.name() for b in eem_blocks],
                  evidence_label="EEM applets configured",
                  recommendation="Review EEM applets for necessity; a large number increases both CPU load and "
                                 "the attack surface if one is compromised/malicious.",
                  fix_command="no event manager applet <name>\n! Remove applets that are no longer needed."))

    dangerous_eem = []
    for blk in eem_blocks:
        if blk.has(r"cli command.*(reload|write erase|no aaa|erase|format)", re.I):
            dangerous_eem.append(blk.name())
    out.append(F("CPURISK-03", d, "No EEM applets with potentially destructive actions",
                  Status.FAIL if dangerous_eem else Status.PASS, Severity.HIGH, evidence=dangerous_eem,
                  evidence_label="EEM applets containing reload/erase/no-aaa/format actions",
                  recommendation="Manually review any EEM applet capable of reload/erase/config-wipe actions.",
                  fix_command="no event manager applet <name>\n"
                              "! Remove or rework the action after manual review; do not leave a destructive "
                              "trigger in place without a documented operational reason."))

    ip_accounting = cfg.search(r"^ip accounting\b")
    out.append(F("CPURISK-04", d, "Legacy 'ip accounting' not in use (deprecated, CPU-intensive)",
                  Status.FAIL if ip_accounting else Status.PASS, Severity.LOW,
                  recommendation="Remove legacy 'ip accounting' in favor of NetFlow/Flexible NetFlow.",
                  fix_command="no ip accounting\n"
                              "! Replace with Flexible NetFlow if traffic accounting is still needed:\n"
                              "flow record MY-RECORD\nflow exporter MY-EXPORTER\nflow monitor MY-MONITOR"))

    large_acl_count = 0
    large_acl_names = []
    for blk in cfg.get_blocks("ip access-list extended", "ip access-list standard"):
        if len(blk.lines) > 100:
            large_acl_count += 1
            large_acl_names.append(f"{blk.name()}  ({len(blk.lines)} entries)")
    out.append(F("CPURISK-05", d, "No unusually large ACLs (>100 entries) on this device",
                  Status.FAIL if large_acl_count else Status.PASS, Severity.LOW,
                  evidence=large_acl_names,
                  evidence_label="ACLs exceeding 100 entries",
                  recommendation="Very large ACLs increase per-packet lookup cost; consider object-groups or "
                                 "hardware TCAM limits review.",
                  fix_command="object-group network <name>\n <member-entries>\n!\n"
                              "object-group service <name>\n <member-ports>\n!\n"
                              "! Rewrite the large ACL using object-groups to reduce entry count and improve "
                              "maintainability."))

    debug_lines = cfg.search_lines(r"^debug ")
    out.append(F("CPURISK-06", d, "No 'debug' commands present in the captured config",
                  Status.FAIL if debug_lines else Status.PASS, Severity.MEDIUM, evidence=debug_lines,
                  evidence_label="Active debug commands found",
                  detail="debug is normally a runtime-only command; its presence in a config capture suggests "
                          "it may have been left running.",
                  recommendation="Disable any active debug output not needed for an active troubleshooting session.",
                  fix_command="undebug all\n! Or the specific 'no debug <feature>' for the debug(s) listed above."))
    return out


# =============================================================================
# 8. DOMAIN CHECKS -- IPSEC VPN (conditional)
# =============================================================================

_WEAK_ENCRYPTION = re.compile(r"\b(des|3des)\b", re.I)
_WEAK_INTEGRITY = re.compile(r"\b(md5|sha1|sha)\b", re.I)  # bare 'sha' without a bit-size = SHA-1 on IOS
_WEAK_DH = re.compile(r"\bgroup (1|2|5)\b", re.I)


def check_vpn(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "IPsec VPN"
    out: list[Finding] = []

    vpn_present = (cfg.get_blocks("crypto ikev2") or cfg.get_blocks("crypto map") or
                   any(b.has(r"tunnel mode ipsec") for b in cfg.interfaces()))
    ctx.set("vpn_configured", bool(vpn_present))
    if not vpn_present:
        out.append(F("VPN-00", d, "No IPsec/VPN configuration detected in running-config",
                      Status.NA, Severity.INFO))
        return out

    proposals = cfg.get_blocks("crypto ikev2 proposal")
    weak_proposals = [b.name() for b in proposals
                       if b.has(_WEAK_ENCRYPTION) or b.has(_WEAK_INTEGRITY) or b.has(_WEAK_DH)]
    out.append(F("VPN-01", d, "IKEv2 proposals use strong encryption/integrity/DH-group",
                  Status.FAIL if weak_proposals else (Status.PASS if proposals else Status.MANUAL),
                  Severity.HIGH, evidence=weak_proposals,
                  evidence_label="IKEv2 proposals using weak algorithms",
                  recommendation="Use AES-GCM (or AES-CBC-256 + SHA-256/384/512), SHA-256+ integrity/PRF, and "
                                 "DH group 14+ (19/20/21 preferred). Avoid DES/3DES, MD5/SHA-1, and DH groups 1/2/5.",
                  fix_command="crypto ikev2 proposal <proposal-name>\n"
                              " encryption aes-gcm-256\n"
                              " prf sha384\n"
                              " group 20\n"
                              "! Replace the weak encryption/integrity/PRF/group lines shown above."))

    profiles = cfg.get_blocks("crypto ikev2 profile")
    no_dpd = [b.name() for b in profiles if not b.has(r"\bdpd\b")]
    out.append(F("VPN-02", d, "IKEv2 profiles have Dead Peer Detection (DPD) enabled",
                  Status.FAIL if no_dpd else (Status.PASS if profiles else Status.NA),
                  Severity.MEDIUM, evidence=no_dpd,
                  evidence_label="IKEv2 profiles without DPD",
                  recommendation="Configure 'dpd <interval> <retry> on-demand|periodic' in every IKEv2 profile.",
                  fix_command="crypto ikev2 profile <profile-name>\n dpd 10 5 on-demand"))

    transforms = cfg.get_blocks("crypto ipsec transform-set")
    weak_transforms = [b.name() for b in transforms
                        if b.has(_WEAK_ENCRYPTION) or b.has(r"esp-null") or b.has(r"esp-md5-hmac")]
    out.append(F("VPN-03", d, "IPsec transform-sets use strong encryption/HMAC",
                  Status.FAIL if weak_transforms else (Status.PASS if transforms else Status.MANUAL),
                  Severity.HIGH, evidence=weak_transforms,
                  evidence_label="Transform-sets using weak encryption/HMAC",
                  recommendation="Use esp-gcm (preferred) or esp-aes 256 with esp-sha256-hmac+. Avoid DES/3DES, "
                                 "esp-null, and MD5-based HMAC.",
                  fix_command="crypto ipsec transform-set <name> esp-gcm 256\nmode tunnel"))

    ipsec_profiles = cfg.get_blocks("crypto ipsec profile")
    no_pfs = [b.name() for b in ipsec_profiles if not b.has(r"set pfs")]
    out.append(F("VPN-04", d, "IPsec profiles have PFS enabled",
                  Status.FAIL if no_pfs else (Status.PASS if ipsec_profiles else Status.NA),
                  Severity.MEDIUM, evidence=no_pfs,
                  evidence_label="IPsec profiles without PFS",
                  recommendation="Configure 'set pfs group19' (or stronger) in every IPsec profile.",
                  fix_command="crypto ipsec profile <profile-name>\n set pfs group19"))

    keyring_psks = re.findall(r"pre-shared-key\s+(?:address\s+\S+\s+)?(\S+)", cfg.text, re.I)
    dup_psks = {p for p in keyring_psks if keyring_psks.count(p) > 1}
    out.append(F("VPN-05", d, "No pre-shared key reused across multiple VPN peers",
                  Status.FAIL if dup_psks else (Status.PASS if keyring_psks else Status.NA),
                  Severity.HIGH,
                  detail=f"{len(dup_psks)} PSK value(s) appear to be reused." if dup_psks else "",
                  recommendation="Use a unique PSK per peer, or migrate to certificate-based authentication.",
                  fix_command="crypto ikev2 keyring <keyring-name>\n"
                              " peer <peer-name>\n"
                              "  address <peer-ip>\n"
                              "  pre-shared-key <unique-strong-key-for-this-peer>\n"
                              "! Or migrate to 'authentication local/remote rsa-sig' with a PKI trustpoint."))

    legacy_maps = cfg.get_blocks("crypto map")
    out.append(F("VPN-06", d, "Legacy policy-based crypto-map VPN usage reviewed",
                  Status.MANUAL if legacy_maps else Status.PASS, Severity.LOW,
                  evidence=[b.name() for b in legacy_maps],
                  evidence_label="Legacy crypto maps in use",
                  recommendation="Legacy crypto-map VPNs still work but are harder to scale/troubleshoot than "
                                 "VTI/FlexVPN; consider migrating." if legacy_maps else ""))

    # Facts for correlation: does any IKEv2 profile reference a PKI trustpoint used with weak/no revocation checking?
    vpn_trustpoints = set(re.findall(r"pki trustpoint (\S+)", cfg.text, re.I))
    ctx.set("vpn_trustpoints_used", vpn_trustpoints)

    out.append(F("VPN-07", d, "Certificate expiration / CRL / OCSP reachability",
                  Status.MANUAL, Severity.INFO,
                  detail="Not visible in running-config text -- see the PKI domain and verify live with "
                          "'show crypto pki certificates'.",
                  recommendation="Cross-reference with the PKI section; supplement with a live cert dump if possible."))
    return out


# =============================================================================
# 9. DOMAIN CHECKS -- ZONE-BASED FIREWALL (conditional)
# =============================================================================

def check_zbfw(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Zone-Based Policy Firewall"
    out: list[Finding] = []
    zones = cfg.get_blocks("zone security")
    if not zones:
        out.append(F("ZBFW-00", d, "No Zone-Based Firewall configuration detected", Status.NA, Severity.INFO))
        return out

    zone_pairs = cfg.get_blocks("zone-pair security")
    out.append(F("ZBFW-01", d, "Zone-pairs defined for the configured security zones",
                  Status.PASS if zone_pairs else Status.FAIL, Severity.HIGH,
                  recommendation="Define 'zone-pair security' for every intended traffic direction between zones.",
                  fix_command="zone-pair security IN-OUT source INSIDE destination OUTSIDE"))

    inspect_policies = [b for b in cfg.get_blocks("policy-map") if b.has(r"type inspect")]
    out.append(F("ZBFW-02", d, "Inspect policy-maps exist for zone-pairs",
                  Status.PASS if inspect_policies else Status.FAIL, Severity.HIGH,
                  recommendation="Define 'policy-map type inspect' with class-maps matching intended traffic.",
                  fix_command="class-map type inspect match-any CM-INSPECT\n match protocol tcp\n match protocol udp\n"
                              " match protocol icmp\n!\n"
                              "policy-map type inspect PM-INSPECT\n class type inspect CM-INSPECT\n  inspect\n"
                              " class class-default\n  drop"))

    applied = any(zp.has(r"service-policy type inspect") for zp in zone_pairs)
    out.append(F("ZBFW-03", d, "Inspect policy actually applied via service-policy on zone-pairs",
                  Status.PASS if applied else Status.FAIL, Severity.HIGH,
                  recommendation="Apply 'service-policy type inspect <policy>' inside each zone-pair.",
                  fix_command="zone-pair security IN-OUT source INSIDE destination OUTSIDE\n"
                              " service-policy type inspect PM-INSPECT"))

    self_zone = any("self" in zp.header.lower() for zp in zone_pairs)
    out.append(F("ZBFW-04", d, "Self-zone protection configured (device itself, not just transit traffic)",
                  Status.PASS if self_zone else Status.FAIL, Severity.MEDIUM,
                  recommendation="Configure a zone-pair with 'source self' or 'destination self' to protect the "
                                 "device's own control/management plane, not just transit traffic.",
                  fix_command="zone-pair security SELF-PROTECT source self destination OUTSIDE\n"
                              " service-policy type inspect PM-SELF-INSPECT"))
    return out


# =============================================================================
# 10. DOMAIN CHECKS -- CRYPTOGRAPHY & PKI
# =============================================================================

def check_pki(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Cryptography & PKI"
    out: list[Finding] = []
    trustpoints = cfg.get_blocks("crypto pki trustpoint")
    if not trustpoints:
        out.append(F("PKI-00", d, "No PKI trustpoints configured", Status.NA, Severity.INFO))
        return out

    no_revocation = []
    revocation_none = []
    self_signed = []
    weak_hash = []
    weak_key = []
    no_enrollment = []

    for blk in trustpoints:
        rc = blk.find(r"revocation-check (\S+)")
        if not rc:
            no_revocation.append(blk.name())
        elif "none" in rc.group(1).lower():
            revocation_none.append(blk.name())

        if blk.has(r"enrollment selfsigned"):
            self_signed.append(blk.name())
        elif not blk.has(r"enrollment (url|terminal|mode ra)"):
            no_enrollment.append(blk.name())

        hash_m = blk.find(r"hash (\S+)")
        if hash_m and hash_m.group(1).lower() in ("md5", "sha1"):
            weak_hash.append(f"{blk.name()}: hash {hash_m.group(1)}")

        key_m = blk.find(r"rsakeypair \S+ (\d+)")
        if key_m and int(key_m.group(1)) < policy["min_rsa_key_bits"]:
            weak_key.append(f"{blk.name()}: RSA {key_m.group(1)}-bit (< {policy['min_rsa_key_bits']})")

    out.append(F("PKI-01", d, "Revocation checking explicitly disabled (revocation-check none)",
                  Status.FAIL if revocation_none else Status.PASS, Severity.HIGH, evidence=revocation_none,
                  evidence_label="Trustpoints with revocation-check none",
                  recommendation="Avoid 'revocation-check none'; use 'crl' and/or 'ocsp' (with a sane fallback).",
                  fix_command="crypto pki trustpoint <trustpoint-name>\n revocation-check crl ocsp"))
    out.append(F("PKI-02", d, "Revocation checking explicitly configured (not left to default)",
                  Status.FAIL if no_revocation else Status.PASS, Severity.MEDIUM, evidence=no_revocation,
                  evidence_label="Trustpoints with no explicit revocation-check",
                  recommendation="Explicitly configure 'revocation-check crl ocsp' rather than relying on platform default.",
                  fix_command="crypto pki trustpoint <trustpoint-name>\n revocation-check crl ocsp"))
    out.append(F("PKI-03", d, "Self-signed certificates reviewed (expected only for internal/test use)",
                  Status.MANUAL if self_signed else Status.PASS, Severity.MEDIUM, evidence=self_signed,
                  evidence_label="Trustpoints using self-signed certificates",
                  recommendation="Confirm self-signed usage is intentional; production-facing services should use "
                                 "a CA-issued certificate."))
    out.append(F("PKI-04", d, "Trustpoints have an enrollment method configured",
                  Status.FAIL if no_enrollment else Status.PASS, Severity.LOW, evidence=no_enrollment,
                  evidence_label="Trustpoints with no enrollment method",
                  recommendation="Configure 'enrollment url/terminal/mode ra' explicitly.",
                  fix_command="crypto pki trustpoint <trustpoint-name>\n enrollment url http://<ca-server>:80"))
    out.append(F("PKI-05", d, "No weak hash algorithm (MD5/SHA-1) on trustpoints",
                  Status.FAIL if weak_hash else Status.PASS, Severity.MEDIUM, evidence=weak_hash,
                  evidence_label="Trustpoints using a weak hash algorithm",
                  recommendation="Use 'hash sha256' or stronger.",
                  fix_command="crypto pki trustpoint <trustpoint-name>\n hash sha256"))
    out.append(F("PKI-06", d, "RSA key size meets policy minimum",
                  Status.FAIL if weak_key else Status.PASS, Severity.HIGH, evidence=weak_key,
                  evidence_label="Trustpoints with an undersized RSA key",
                  recommendation=f"Use RSA >= {policy['min_rsa_key_bits']} bits, or ECDSA keypairs.",
                  fix_command=f"crypto pki trustpoint <trustpoint-name>\n rsakeypair <keypair-name> {policy['min_rsa_key_bits']}\n"
                              f"! Or use ECDSA instead: 'ecdsakeypair <keypair-name>'"))

    for item, label in ((None, "PKI-07 Certificate expiration"), (None, "PKI-08 CRL reachability"),
                         (None, "PKI-09 OCSP reachability"), (None, "PKI-10 Certificate chain completeness"),
                         (None, "PKI-11 Weak CA (issuing CA key size / signature algorithm)")):
        check_id, title = label.split(" ", 1)
        out.append(F(check_id, d, title, Status.MANUAL, Severity.INFO,
                      detail="Not visible in a running-config text export -- requires "
                              "'show crypto pki certificates [verbose]' from the live device.",
                      recommendation="Capture and review 'show crypto pki certificates verbose' alongside this audit."))

    ctx.set("pki_trustpoints", {b.name() for b in trustpoints})
    ctx.set("pki_revocation_none_or_missing", set(revocation_none) | set(no_revocation))
    return out


# =============================================================================
# 11. DOMAIN CHECKS -- PHYSICAL SECURITY, BOOT CONFIG & SECURE BOOT
# =============================================================================

def check_physical(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Physical Security"
    out: list[Finding] = []

    pw_recovery_disabled = cfg.search(r"^no service password-recovery\b")
    out.append(F("PHYS-01", d, "Password recovery disabled",
                  Status.PASS if pw_recovery_disabled else Status.FAIL, Severity.MEDIUM,
                  detail="High-impact / irreversible on some platforms without a full re-image -- confirm this "
                          "is an intentional, documented decision either way.",
                  recommendation="Configure 'no service password-recovery' if physical security cannot be "
                                 "otherwise guaranteed; ensure this is a deliberate, documented decision.",
                  fix_command="no service password-recovery\n! Confirm this is intentional before applying -- see the note above."))

    con_blocks = cfg.get_blocks("line con")
    if con_blocks:
        m = con_blocks[0].find(r"exec-timeout (\d+) (\d+)")
        never = m and m.group(1) == "0" and m.group(2) == "0"
        max_min = policy["console_exec_timeout_max_minutes"]
        bad = never or not m or int(m.group(1)) > max_min
        out.append(F("PHYS-02", d, "Console exec-timeout configured and bounded",
                      Status.FAIL if bad else Status.PASS,
                      Severity.HIGH if never else Severity.MEDIUM,
                      recommendation=f"Set console 'exec-timeout' to a bounded value (<= {max_min} min), never 0 0.",
                      fix_command=f"line con 0\n exec-timeout {max_min} 0"))

    aux_blocks = cfg.get_blocks("line aux")
    if aux_blocks:
        aux_disabled = aux_blocks[0].has(r"no exec") and aux_blocks[0].has(r"transport input none")
        out.append(F("PHYS-03", d, "AUX port disabled if unused",
                      Status.PASS if aux_disabled else Status.MANUAL, Severity.MEDIUM,
                      recommendation="If the AUX port is not in active use, configure 'no exec' + "
                                     "'transport input none' on 'line aux 0'.",
                      fix_command="line aux 0\n no exec\n transport input none"))

    zeroize_capable = cfg.search(r"crypto key\b") or cfg.search(r"crypto pki trustpoint")
    out.append(F("PHYS-04", d, "Key zeroization practice on disposal/RMA",
                  Status.MANUAL, Severity.INFO,
                  detail="Procedural control, not a config-file check -- confirm 'crypto key zeroize' + "
                          "'write erase' + reload is standard practice before device disposal/RMA."
                          if zeroize_capable else "No cryptographic keys detected in this config.",
                  recommendation="Document and follow a zeroization procedure for any device holding key material."))

    out.append(F("PHYS-05", d, "Physical tamper indicators (alarm relay, tamper-evident hardware)",
                  Status.MANUAL, Severity.INFO,
                  detail="Not derivable from running-config -- hardware/physical inspection required.",
                  recommendation="Out of scope for a text-based config audit; verify physically if required by policy."))

    ctx.set("password_recovery_disabled", pw_recovery_disabled)
    return out


def check_boot_and_secure_boot(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Boot Configuration & Secure Boot"
    out: list[Finding] = []

    boot_lines = cfg.search_lines(r"^boot system\b")
    out.append(F("BOOT-01", d, "Explicit 'boot system' statement present",
                  Status.PASS if boot_lines else Status.FAIL, Severity.MEDIUM, evidence=boot_lines,
                  evidence_label="Current boot system lines",
                  recommendation="Configure an explicit 'boot system flash:<image>' rather than relying on the "
                                 "platform's default search order.",
                  fix_command="boot system flash:<image-filename>"))
    if len(boot_lines) > 1:
        out.append(F("BOOT-02", d, f"Multiple boot-system entries present ({len(boot_lines)}) -- review",
                      Status.MANUAL, Severity.LOW, evidence=boot_lines,
                      evidence_label="Boot system entries found",
                      recommendation="Confirm multiple entries are intentional redundancy, not stale/forgotten "
                                     "fallback images pointing at an old/vulnerable version."))

    usb_boot = cfg.search(r"boot system usb")
    out.append(F("BOOT-03", d, "USB boot not in use",
                  Status.FAIL if usb_boot else Status.PASS, Severity.MEDIUM,
                  recommendation="Avoid booting from USB media in production; disable if not explicitly required.",
                  fix_command="no boot system usb<...>\nboot system flash:<image-filename>"))

    reg_m = re.search(r"^config-register (0x[0-9A-Fa-f]+)", cfg.text, re.M | re.I)
    config_register_break_enabled = False
    if reg_m:
        try:
            reg_val = int(reg_m.group(1), 16)
            # Bit 6 (0x0040) = "ignore NVRAM config" behavior in some contexts; the classic console-break related
            # setting is the low nibble != 0x2 default boot field combined with bit 8 (0x0100, terminal break).
            config_register_break_enabled = bool(reg_val & 0x0100) or (reg_val & 0x000F) == 0
            out.append(F("BOOT-04", d, f"Config-register value reviewed ({reg_m.group(1)})",
                          Status.FAIL if config_register_break_enabled else Status.PASS, Severity.MEDIUM,
                          detail="Non-default config-register values can enable console-break-to-ROMMON or "
                                  "unpredictable boot behavior.",
                          recommendation="Use the standard 0x2102 unless there is a specific, documented reason "
                                          "for a different value.",
                          fix_command="config-register 0x2102\n! Requires a reload to take effect."))
        except ValueError:
            out.append(F("BOOT-04", d, "Config-register value reviewed", Status.MANUAL, Severity.LOW,
                          detail=f"Could not parse value: {reg_m.group(1)}"))
    else:
        out.append(F("BOOT-04", d, "Config-register value present in running-config",
                      Status.MANUAL, Severity.INFO,
                      detail="Not found -- some exports omit this line even when it's at the platform default (0x2102).",
                      recommendation="Verify with 'show version | include register' if not shown here."))

    out.append(F("BOOT-05", d, "Secure Boot / image signature verification enabled",
                  Status.MANUAL, Severity.INFO,
                  detail="Secure Boot state is platform-verified (Trust Anchor module), not visible in running-config.",
                  recommendation="Verify with 'show platform sudi certificate' / 'show software authenticity' on the live device."))
    out.append(F("BOOT-06", d, "SELinux / platform Mandatory Access Control (IOS-XE Linux underlay)",
                  Status.MANUAL, Severity.INFO,
                  detail="Platform-verified only.",
                  recommendation="Verify enforcing mode via 'show platform software security-briefing' "
                                  "(or applicable platform command) if this level of assurance is required."))
    out.append(F("BOOT-07", d, "Hardware-backed secure storage / configuration-at-rest encryption",
                  Status.MANUAL, Severity.INFO,
                  detail="Platform-verified only.",
                  recommendation="Confirm platform capability and enablement status out of band."))
    out.append(F("BOOT-08", d, "ROMMON password set",
                  Status.MANUAL, Severity.MEDIUM,
                  detail="ROMMON password state is not reflected in running-config.",
                  recommendation="Verify ROMMON password is set via direct console access during a maintenance window."))
    out.append(F("BOOT-09", d, "Bootloader version reviewed against known-vulnerable versions",
                  Status.MANUAL, Severity.INFO,
                  recommendation="Cross-reference bootloader/ROMMON version with Cisco PSIRT once the IOS-XE "
                                  "version check (see Software/PSIRT domain) is extended to cover it."))

    ctx.set("config_register_break_enabled", config_register_break_enabled)
    return out


# =============================================================================
# 12. DOMAIN CHECKS -- UNNECESSARY SERVICES & MISC / OFTEN-MISSED
# =============================================================================

def _service_disabled(cfg: CiscoConfig, enable_pattern: str) -> bool:
    """True if the given service does NOT appear enabled (either absent, or explicitly 'no <cmd>')."""
    return not re.search(rf"^{enable_pattern}$", cfg.text, re.M | re.I)


def check_unnecessary_services(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Unnecessary Services"
    out: list[Finding] = []

    services = [
        ("SVC-01", "TCP small-servers disabled", r"service tcp-small-servers", Severity.MEDIUM, "no service tcp-small-servers"),
        ("SVC-02", "UDP small-servers disabled", r"service udp-small-servers", Severity.MEDIUM, "no service udp-small-servers"),
        ("SVC-03", "BOOTP server disabled", r"ip bootp server", Severity.LOW, "no ip bootp server"),
        ("SVC-04", "Finger service disabled", r"ip finger", Severity.LOW, "no ip finger"),
        ("SVC-05", "Identd service disabled", r"ip identd", Severity.LOW, "no ip identd"),
        ("SVC-06", "TFTP-based config load disabled", r"service config", Severity.MEDIUM, "no service config"),
        ("SVC-07", "PAD service disabled", r"service pad", Severity.LOW, "no service pad"),
    ]
    for check_id, title, pattern, sev, fix_cmd in services:
        disabled = _service_disabled(cfg, pattern)
        out.append(F(check_id, d, title, Status.PASS if disabled else Status.FAIL, sev,
                      recommendation=f"Ensure '{pattern}' is not enabled (default-off on modern IOS-XE; "
                                     f"flagged only if explicitly present without a preceding 'no').",
                      fix_command=fix_cmd))

    vstack_no = cfg.search(r"^no vstack\b")
    vstack_yes = cfg.search(r"^vstack\b") and not vstack_no
    out.append(F("SVC-08", d, "Smart Install (vstack) explicitly disabled",
                  Status.FAIL if vstack_yes else (Status.PASS if vstack_no else Status.MANUAL),
                  Severity.CRITICAL,
                  detail="" if (vstack_no or vstack_yes) else "Neither 'vstack' nor 'no vstack' found -- default "
                                                                "state is platform/version dependent.",
                  recommendation="Explicitly configure 'no vstack' -- Smart Install has a long history of "
                                 "critical, unauthenticated remote-code-execution vulnerabilities.",
                  fix_command="no vstack"))

    cdp_off = cfg.search(r"^no cdp run\b")
    out.append(F("SVC-09", d, "CDP posture reviewed",
                  Status.PASS if cdp_off else Status.MANUAL, Severity.LOW,
                  recommendation="Disable globally with 'no cdp run' if not operationally required, or at minimum "
                                 "disable per-interface on untrusted/external-facing ports.",
                  fix_command="no cdp run\n! Or, per untrusted interface only:\ninterface <interface>\n no cdp enable"))
    lldp_off = cfg.search(r"^no lldp run\b")
    out.append(F("SVC-10", d, "LLDP posture reviewed",
                  Status.PASS if lldp_off else Status.MANUAL, Severity.LOW,
                  recommendation="Disable globally with 'no lldp run' if not operationally required, or at minimum "
                                 "disable per-interface on untrusted/external-facing ports.",
                  fix_command="no lldp run\n! Or, per untrusted interface only:\ninterface <interface>\n no lldp transmit\n no lldp receive"))
    return out


def check_misc(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Miscellaneous / Often-Missed"
    out: list[Finding] = []

    errdisable = cfg.search_lines(r"^errdisable recovery cause\b")
    out.append(F("MISC-01", d, "Errdisable recovery configured for at least one cause",
                  Status.PASS if errdisable else Status.FAIL, Severity.LOW, evidence=errdisable,
                  evidence_label="Current errdisable recovery causes",
                  recommendation="Configure 'errdisable recovery cause <cause>' + 'errdisable recovery interval "
                                 "<seconds>' so ports don't stay down indefinitely requiring manual intervention.",
                  fix_command="errdisable recovery cause bpduguard\nerrdisable recovery cause psecure-violation\n"
                              "errdisable recovery interval 300"))

    mcast_routing = cfg.search(r"^ip multicast-routing\b")
    if mcast_routing:
        out.append(F("MISC-02", d, "Multicast routing is enabled -- verify PIM/IGMP CoPP policing",
                      Status.MANUAL, Severity.LOW,
                      recommendation="Cross-check the Control Plane / CoPP domain's MCAST class coverage."))
    else:
        out.append(F("MISC-02", d, "Multicast routing not enabled", Status.PASS, Severity.INFO))

    tcl_restricted = cfg.search(r"no scripting tcl")
    out.append(F("MISC-03", d, "Tcl shell availability reviewed",
                  Status.MANUAL if not tcl_restricted else Status.PASS, Severity.LOW,
                  recommendation="Restrict/disable the Tcl shell if not operationally required."))

    dhcp_relay = cfg.search_lines(r"ip helper-address \S+")
    out.append(F("MISC-04", d, f"DHCP relay helper-address(es) present ({len(dhcp_relay)}) -- verify trust",
                  Status.MANUAL if dhcp_relay else Status.NA, Severity.LOW, evidence=dhcp_relay[:10],
                  recommendation="Confirm every 'ip helper-address' points only at a trusted, authorized DHCP server."))

    mgmt_vrf = cfg.search(r"^vrf definition (Mgmt-intf|Management|MGMT)\b") or cfg.search(r"^ip vrf (Mgmt-intf|Management|MGMT)\b")
    out.append(F("MISC-05", d, "Management-plane VRF isolation in use",
                  Status.PASS if mgmt_vrf else Status.FAIL, Severity.LOW,
                  recommendation="Consider isolating management traffic in a dedicated VRF (Mgmt-intf or similar).",
                  fix_command="vrf definition Mgmt-intf\n address-family ipv4\n!\n"
                              "interface <mgmt-interface>\n vrf forwarding Mgmt-intf\n ip address <ip> <mask>"))

    autosecure = cfg.search(r"auto secure")
    out.append(F("MISC-06", d, "AutoSecure baseline reviewed",
                  Status.MANUAL, Severity.INFO,
                  detail="AutoSecure is an interactive exec wizard and generally not reflected as a discrete "
                          "line in running-config.",
                  recommendation="Not independently verifiable from running-config; informational only."))

    dot1x_rule_note = F("MISC-07", d, "802.1X + MAB correlation rule",
                         Status.NA, Severity.INFO,
                         detail="802.1X/MAB domain checks are on the roadmap for a future version; the "
                                 "corresponding correlation rule from the checklist is intentionally not yet "
                                 "implemented rather than faked.")
    out.append(dot1x_rule_note)
    return out


def check_ios_version(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "IOS-XE Version"
    out: list[Finding] = []
    version = cfg.get_version()
    out.append(F("VER-01", d, f"Running version extracted: {version}",
                  Status.PASS if version != "unknown" else Status.MANUAL, Severity.INFO,
                  recommendation="Cross-reference this version against Cisco PSIRT openVuln / the Security "
                                 "Advisories page for known CVEs -- this tool does not call out to the internet, "
                                 "so that lookup is a manual (or future-scripted) step."))
    hostname = cfg.get_hostname()
    out.append(F("VER-02", d, f"Hostname: {hostname}", Status.PASS, Severity.INFO))
    return out


# =============================================================================
# 13. CORRELATION ENGINE
# =============================================================================

def run_correlation_engine(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    """
    Reasons over the shared fact-sheet populated by domain checks above.
    Each rule here corresponds to a row in the "Rule Correlation Engine" table
    from the design discussion. Rules that depend on domains not yet implemented
    (e.g. 802.1X/MAB) are intentionally omitted rather than faked -- see MISC-07.
    """
    d = "Correlation Engine"
    out: list[Finding] = []

    if ctx.get("dhcp_snooping_enabled") and not ctx.get("dai_enabled"):
        out.append(F("CORR-01", d, "DHCP Snooping enabled without Dynamic ARP Inspection",
                      Status.FAIL, Severity.HIGH,
                      detail="Snooping without DAI is half a control -- the binding table exists but ARP traffic "
                              "isn't validated against it.",
                      recommendation="Enable DAI on the same VLANs where DHCP Snooping is active."))

    if ctx.get("dai_enabled") and not ctx.get("device_tracking_configured"):
        out.append(F("CORR-02", d, "DAI enabled without Device Tracking (SISF) policy",
                      Status.FAIL, Severity.MEDIUM,
                      recommendation="Configure and attach a device-tracking policy so DAI/IPSG have a "
                                     "populated, current binding table to validate against."))

    if ctx.get("ssh_enabled") and not ctx.get("vty_acl_present"):
        out.append(F("CORR-03", d, "SSH enabled with no VTY access-class ACL",
                      Status.FAIL, Severity.HIGH,
                      detail="Management plane is reachable from anywhere that can route to this device.",
                      recommendation="Apply a restrictive 'access-class' ACL to every VTY line."))

    if ctx.get("snmpv3_configured") is False and ctx.get("snmp_acl_present") is False:
        # snmp_acl_present is left as None (manual) in check_snmp; only fires if explicitly False in future versions
        out.append(F("CORR-04", d, "SNMP configured with no ACL restriction",
                      Status.FAIL, Severity.HIGH,
                      recommendation="Bind an ACL restricting SNMP access to known management hosts."))

    if ctx.get("native_vlan_changed") and ctx.get("trunk_allows_all_vlans"):
        out.append(F("CORR-05", d, "Native VLAN hardened but trunk still allows all VLANs",
                      Status.FAIL, Severity.MEDIUM,
                      detail="The native-VLAN fix was only half completed.",
                      recommendation="Prune 'switchport trunk allowed vlan' on every trunk where the native "
                                     "VLAN has already been changed."))

    if ctx.get("port_security_any_without_sticky"):
        out.append(F("CORR-06", d, "Port Security enabled without sticky MAC learning on some ports",
                      Status.FAIL, Severity.LOW,
                      recommendation="Enable sticky learning where static/dynamic learning isn't specifically required."))

    if ctx.get("copp_configured") and (ctx.get("copp_class_coverage") or 0) <= 1:
        out.append(F("CORR-07", d, "CoPP is applied but covers almost no traffic classes",
                      Status.FAIL, Severity.HIGH,
                      detail=f"Only {ctx.get('copp_class_coverage')}/8 tracked traffic categories matched.",
                      recommendation="A CoPP policy that doesn't actually classify ICMP/ARP/routing/mgmt traffic "
                                     "provides little real protection -- treat this as 'CoPP present but "
                                     "ineffective' rather than a pass."))

    pki_no_revocation = ctx.get("pki_revocation_none_or_missing") or set()
    if ctx.get("vpn_configured") and pki_no_revocation:
        out.append(F("CORR-08", d, "VPN configured with PKI trustpoint(s) lacking revocation checking",
                      Status.FAIL, Severity.HIGH,
                      evidence=list(pki_no_revocation),
                      detail="A compromised or revoked peer certificate would not be caught if the VPN's "
                              "authentication relies on one of these trustpoints.",
                      recommendation="Confirm which trustpoint(s) authenticate VPN peers and ensure "
                                     "'revocation-check crl ocsp' (not 'none' or unset) on those specifically."))

    if ctx.get("password_recovery_disabled") and ctx.get("config_register_break_enabled"):
        out.append(F("CORR-09", d, "Contradictory boot-security settings",
                      Status.FAIL, Severity.MEDIUM,
                      detail="'no service password-recovery' is set, but the config-register value still "
                              "appears to allow a console break to ROMMON.",
                      recommendation="Reconcile these two settings -- as configured they work against each other."))

    if ctx.get("guestshell_iox_present"):
        out.append(F("CORR-10", d, "Both GuestShell and IOx app-hosting surfaces appear present",
                      Status.FAIL, Severity.LOW,
                      recommendation="Review whether both application-hosting surfaces are actually needed; "
                                     "disable whichever is unused."))

    return out


# =============================================================================
# 14. DOMAIN REGISTRY
# =============================================================================

DOMAIN_REGISTRY: dict[str, dict] = {
    "mgmt": {
        "title": "Management Plane",
        "file": "management_plane.txt",
        "funcs": [check_aaa_and_users, check_local_users, check_ssh_and_vty, check_http, check_snmp,
                  check_ntp, check_logging, check_banners, check_dns, check_mpp,
                  check_mgmt_exposure_matrix, check_password_security],
    },
    "l2": {
        "title": "Layer 2 Security",
        "file": "layer2_security.txt",
        "funcs": [check_port_security, check_stp, check_udld, check_storm_control, check_dhcp_snooping,
                  check_dai, check_ip_source_guard, check_trunk_native_vtp, check_etherchannel],
    },
    "l3": {
        "title": "Layer 3 Security",
        "file": "layer3_security.txt",
        "funcs": [check_urpf, check_routing_auth, check_fhrp, check_icmp_hardening, check_acl_analysis,
                  check_object_tracking],
    },
    "cp": {
        "title": "Control Plane (CoPP)",
        "file": "control_plane_copp.txt",
        "funcs": [check_copp, check_cpu_risk],
    },
    "vpn": {
        "title": "IPsec VPN",
        "file": "ipsec_vpn.txt",
        "funcs": [check_vpn],
    },
    "zbfw": {
        "title": "Zone-Based Firewall",
        "file": "zone_based_firewall.txt",
        "funcs": [check_zbfw],
    },
    "pki": {
        "title": "Cryptography & PKI",
        "file": "cryptography_pki.txt",
        "funcs": [check_pki],
    },
    "physical": {
        "title": "Physical Security & Boot",
        "file": "physical_and_boot.txt",
        "funcs": [check_physical, check_boot_and_secure_boot],
    },
    "misc": {
        "title": "Unnecessary Services & Misc",
        "file": "services_and_misc.txt",
        "funcs": [check_unnecessary_services, check_misc, check_ios_version],
    },
}

DOMAIN_ORDER = ["mgmt", "l2", "l3", "cp", "vpn", "zbfw", "pki", "physical", "misc"]


# =============================================================================
# 15. SCORING
# =============================================================================

def compute_score(findings: list[Finding]) -> int:
    deductions = sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.status == Status.FAIL)
    return max(0, 100 - deductions)


def status_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Status}
    for f in findings:
        counts[f.status.value] += 1
    return counts


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        if f.status == Status.FAIL:
            counts[f.severity.value] += 1
    return counts


# =============================================================================
# 16. REPORT GENERATION
# =============================================================================

def _fmt_finding(f: Finding, verbose: bool) -> str:
    lines = [
        "-" * 80,
        f"{SEVERITY_TAG.get(f.severity, '[????]')} {STATUS_TAG[f.status]}  {f.check_id} -- {f.title}",
        "-" * 80,
    ]

    if f.evidence:
        label = f.evidence_label or "Affected items"
        lines.append(f"{label} ({len(f.evidence)}):")
        # For FAIL findings, show the full actionable list (this is exactly what the
        # engineer needs to go fix) rather than truncating; only cap the noisier
        # PASS/N-A/MANUAL evidence dumps, and only when not in verbose mode.
        cap = len(f.evidence) if (verbose or f.status == Status.FAIL) else 10
        for e in f.evidence[:cap]:
            lines.append(f"    - {e}")
        if len(f.evidence) > cap:
            lines.append(f"    ... and {len(f.evidence) - cap} more (rerun with -v to see the full list here too)")
        lines.append("")

    if f.detail:
        lines.append(f"Notes: {f.detail}")
        lines.append("")

    if f.recommendation and f.status in (Status.FAIL, Status.MANUAL):
        lines.append(f"Recommendation: {f.recommendation}")
        lines.append("")

    if f.fix_command and f.status == Status.FAIL:
        lines.append("Suggested fix:")
        for cmd_line in f.fix_command.strip("\n").split("\n"):
            lines.append(f"    {cmd_line}")
        lines.append("")

    return "\n".join(lines)


def _min_sev_filter(findings: list[Finding], min_severity: Severity) -> list[Finding]:
    threshold = SEVERITY_RANK[min_severity]
    return [f for f in findings if SEVERITY_RANK[f.severity] <= threshold]


def write_domain_file(path: Path, domain_key: str, title: str, findings: list[Finding],
                       min_severity: Severity, verbose: bool) -> None:
    shown = _min_sev_filter(findings, min_severity)
    fails = [f for f in shown if f.status == Status.FAIL]
    manuals = [f for f in shown if f.status == Status.MANUAL]
    passes = [f for f in shown if f.status == Status.PASS]
    nas = [f for f in shown if f.status == Status.NA]

    lines = [
        f"{'=' * 78}",
        f"{title}",
        f"{'=' * 78}",
        f"Score: {compute_score(findings)}/100   "
        f"(FAIL: {len(fails)}  MANUAL: {len(manuals)}  PASS: {len(passes)}  N/A: {len(nas)})",
        "",
    ]
    if fails:
        lines.append("")
        lines.append("=" * 80)
        lines.append("FAILED CHECKS -- ACTION NEEDED")
        lines.append("=" * 80)
        for f in sorted(fails, key=lambda x: SEVERITY_RANK[x.severity]):
            lines.append(_fmt_finding(f, verbose))
    if manuals:
        lines.append("")
        lines.append("=" * 80)
        lines.append("MANUAL REVIEW REQUIRED (not visible in running-config alone)")
        lines.append("=" * 80)
        for f in manuals:
            lines.append(_fmt_finding(f, verbose))
    if verbose and passes:
        lines.append("")
        lines.append("=" * 80)
        lines.append("PASSED CHECKS")
        lines.append("=" * 80)
        for f in passes:
            lines.append(_fmt_finding(f, verbose))
    if verbose and nas:
        lines.append("")
        lines.append("=" * 80)
        lines.append("NOT APPLICABLE")
        lines.append("=" * 80)
        for f in nas:
            lines.append(_fmt_finding(f, verbose))

    path.write_text("\n".join(lines), encoding="utf-8")


def write_summary(path: Path, cfg: CiscoConfig, domain_results: dict[str, list[Finding]],
                   all_findings: list[Finding], min_severity: Severity, args) -> None:
    overall_score = compute_score(all_findings)
    sev_counts = severity_counts(all_findings)
    stat_counts = status_counts(all_findings)

    lines = [
        "=" * 78,
        f"{TOOL_NAME} v{TOOL_VERSION}",
        "=" * 78,
        f"Hostname:        {cfg.get_hostname()}",
        f"IOS-XE Version:  {cfg.get_version()}",
        f"Audit run at:    {datetime.now().isoformat(timespec='seconds')}",
        f"Config file:     {args.config}",
        "",
        f"OVERALL SCORE: {overall_score}/100",
        "",
        "Findings by status:",
        f"  FAIL:   {stat_counts['fail']}",
        f"  MANUAL: {stat_counts['manual_review']}",
        f"  PASS:   {stat_counts['pass']}",
        f"  N/A:    {stat_counts['na']}",
        "",
        "Failed findings by severity:",
        f"  Critical: {sev_counts['critical']}",
        f"  High:     {sev_counts['high']}",
        f"  Medium:   {sev_counts['medium']}",
        f"  Low:      {sev_counts['low']}",
        "",
        "-" * 78,
        "DOMAIN SCORES",
        "-" * 78,
    ]
    for key, findings in domain_results.items():
        title = DOMAIN_REGISTRY.get(key, {}).get("title", key.title())
        lines.append(f"  {title:<32} {compute_score(findings):>3}/100   "
                      f"(FAIL {sum(1 for f in findings if f.status == Status.FAIL)}, "
                      f"MANUAL {sum(1 for f in findings if f.status == Status.MANUAL)})")

    top_critical_high = [f for f in all_findings
                          if f.status == Status.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH)]
    top_critical_high.sort(key=lambda f: SEVERITY_RANK[f.severity])
    if top_critical_high:
        lines += ["", "-" * 78, "TOP CRITICAL / HIGH FINDINGS", "-" * 78]
        for f in top_critical_high[:30]:
            lines.append(f"  {SEVERITY_TAG[f.severity]} {f.check_id:<16} [{f.domain}] {f.title}")

    corr = [f for f in all_findings if f.domain == "Correlation Engine"]
    if corr:
        lines += ["", "-" * 78, "CORRELATION ENGINE FINDINGS (cross-feature reasoning)", "-" * 78]
        for f in corr:
            lines.append(_fmt_finding(f, verbose=False))
            lines.append("")

    lines += ["", "-" * 78,
              "See the per-domain files in the 'sections' subfolder for full detail.",
              "Items marked MANUAL require live-device verification and are not auto-scored as failures.",
              "-" * 78]

    path.write_text("\n".join(lines), encoding="utf-8")


def write_json(path: Path, cfg: CiscoConfig, all_findings: list[Finding], args) -> None:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "hostname": cfg.get_hostname(),
        "ios_version": cfg.get_version(),
        "config_file": str(args.config),
        "overall_score": compute_score(all_findings),
        "status_counts": status_counts(all_findings),
        "severity_counts": severity_counts(all_findings),
        "findings": [f.to_dict() for f in all_findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# =============================================================================
# 16b. COMPLIANCE FRAMEWORK MAPPING
# =============================================================================
# Design note: this deliberately does NOT touch the ~160 check functions above.
# Mapping data lives in standalone JSON files under mappings/, keyed only by
# check_id, and is cross-referenced at report-generation time. This keeps the
# check logic and the compliance mapping independently maintainable -- someone
# can improve/extend a mapping file without touching a line of check code, and
# adding a 5th framework later is "drop in another JSON file," not a rewrite.
#
# IMPORTANT SCOPE NOTE: not every framework below is populated to the same
# depth, and that's intentional rather than an oversight:
#   - NIST SP 800-53 Rev. 5 and ISO/IEC 27002:2022 are populated with a
#     substantial, deliberately-reasoned mapping across most checks.
#   - The CIS Cisco IOS-XE Benchmark mapping only contains entries that were
#     directly verified against real benchmark text; everything else is
#     left unmapped rather than guessed, since CIS numbering differs across
#     benchmark versions and the full document is gated behind a CIS
#     SecureSuite login.
#   - The DISA STIG mapping ships empty (architecture only) pending
#     verified access to the current STIG checklist text.
# See mappings/*.json "license_note" fields and tools/generate_mappings.py
# for the reasoning behind each framework's scope.

COMPLIANCE_FRAMEWORKS = [
    ("nist_800_53_rev5.json", "compliance_nist_800_53.txt"),
    ("iso27002_2022.json", "compliance_iso27002.txt"),
    ("cis_ios_xe_benchmark.json", "compliance_cis_benchmark.txt"),
    ("disa_stig_cisco_iosxe.json", "compliance_disa_stig.txt"),
]


def load_compliance_mappings(mappings_dir: Path) -> list[dict]:
    """Load every available framework mapping file. Missing files are skipped
    silently (compliance mapping is an optional bonus feature, not a hard
    dependency of the core audit)."""
    loaded = []
    for filename, _outfile in COMPLIANCE_FRAMEWORKS:
        path = mappings_dir / filename
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["_report_filename"] = _outfile
            loaded.append(data)
        except Exception as exc:  # noqa: BLE001 -- surfaced, doesn't abort the audit
            print(f"[!] Warning: could not load compliance mapping '{path}': {exc}", file=sys.stderr)
    return loaded


def write_compliance_framework_file(path: Path, framework: dict, all_findings: list[Finding]) -> None:
    """Example 2 from the design discussion: one file per framework, grouped
    by control number (not by domain) -- mirrors how someone auditing against
    a specific standard actually navigates that standard's document."""
    checks_map: dict = framework.get("checks", {})
    findings_by_id: dict[str, Finding] = {f.check_id: f for f in all_findings}

    # Group by control number
    by_control: dict[str, list] = {}
    for check_id, entries in checks_map.items():
        finding = findings_by_id.get(check_id)
        if finding is None:
            continue  # mapped check wasn't part of this run's selected domains
        for entry in entries:
            by_control.setdefault(entry["control"], []).append((entry, finding))

    total_possible = "93" if framework["framework_id"] == "iso27002" else \
                      "~1,000 (network-relevant subset far smaller)" if framework["framework_id"] == "nist_800_53" else \
                      "unknown / version-dependent"

    lines = [
        "=" * 80,
        f"{framework['framework_name']} -- Cross-Reference",
        "=" * 80,
        framework.get("license_note", ""),
        "",
        "This is a practitioner-built cross-reference, not an official statement of",
        "compliance or a certified mapping. Verify against the current published",
        "framework document before using this as audit evidence.",
        "",
        f"Coverage: {len(by_control)} control(s) referenced by this tool's checks "
        f"(out of {total_possible} total in the framework). The remainder require "
        f"evidence outside the scope of a device configuration file (policy, "
        f"process, physical, or organizational controls).",
        "",
    ]

    if not by_control:
        lines.append("No mapped controls matched findings from the domains run in this audit.")
    else:
        for control in sorted(by_control.keys()):
            pairs = by_control[control]
            title = pairs[0][0].get("title", "")
            lines.append("-" * 80)
            lines.append(f"{control}  {title}")
            lines.append("-" * 80)
            for entry, finding in sorted(pairs, key=lambda p: p[1].check_id):
                rel = entry.get("relationship", "direct")
                lines.append(f"  [{STATUS_TAG[finding.status]}] {finding.check_id:<16} {finding.title}  ({rel})")
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_compliance_overview(path: Path, frameworks: list[dict], all_findings: list[Finding]) -> None:
    """Example 3 from the design discussion: single cross-framework matrix,
    FAILED findings only, sorted by severity -- the default at-a-glance view."""
    findings_by_id: dict[str, Finding] = {f.check_id: f for f in all_findings}
    failed = [f for f in all_findings if f.status == Status.FAIL]
    failed.sort(key=lambda f: SEVERITY_RANK[f.severity])

    framework_names = [fw["framework_name"] for fw in frameworks]
    lines = [
        "=" * 80,
        "Cross-Framework Compliance Overview -- FAILED findings only",
        "=" * 80,
        f"Frameworks: {' | '.join(framework_names)}",
        "",
        "This is a practitioner-built cross-reference, not an official statement of",
        "compliance for any framework. Verify against the current published",
        "benchmark/STIG/control-catalog documents before using as audit evidence.",
        "",
    ]

    if not failed:
        lines.append("No failed findings in this run.")
    else:
        id_width = max(14, max((len(f.check_id) for f in failed), default=14) + 2)
        header = f"{'Check ID':<{id_width}}{'Severity':<10}{'Title':<42}"
        for fw in frameworks:
            header += f"{fw['framework_id']:<14}"
        lines.append(header)
        lines.append("-" * len(header))
        for finding in failed:
            title_col = (finding.title[:38] + "..") if len(finding.title) > 40 else finding.title
            row = f"{finding.check_id:<{id_width}}{finding.severity.value.upper():<10}{title_col:<42}"
            for fw in frameworks:
                entries = fw.get("checks", {}).get(finding.check_id, [])
                cell = "/".join(e["control"] for e in entries) if entries else "-"
                row += f"{cell:<14}"
            lines.append(row)

        lines.append("")
        lines.append("-" * 80)
        lines.append("Coverage summary by framework (controls with >=1 mapped check):")
        for fw in frameworks:
            n_controls = len({e["control"] for entries in fw.get("checks", {}).values() for e in entries})
            lines.append(f"  {fw['framework_name']:<45} {n_controls} control(s) mapped")

    path.write_text("\n".join(lines), encoding="utf-8")


# =============================================================================
# 17. FILE I/O HELPERS (Windows-friendly encoding handling)
# =============================================================================

def read_config_file(path: Path) -> str:
    data = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


# =============================================================================
# 18. CLI
# =============================================================================

DOMAIN_FLAG_HELP = {
    "mgmt": "Management plane (AAA, SSH, HTTP, SNMP, NTP, logging, banners, DNS, exposure matrix, passwords)",
    "l2": "Layer 2 (port security, STP, UDLD, storm-control, DHCP snooping, DAI, IPSG, trunk/native VLAN, VTP)",
    "l3": "Layer 3 (uRPF, routing-protocol auth, FHRP auth, ICMP hardening, ACL analysis, object tracking)",
    "cp": "Control plane (CoPP framework + per-traffic-class policing, high-CPU-risk indicators)",
    "vpn": "IPsec VPN (IKEv2/IPsec strength, DPD, PFS, PSK reuse) -- auto-skips if no VPN config found",
    "zbfw": "Zone-Based Policy Firewall -- auto-skips if not configured",
    "pki": "Cryptography & PKI trustpoints",
    "physical": "Physical security, boot configuration, secure boot posture",
    "misc": "Unnecessary services, miscellaneous/often-missed hardening, IOS-XE version",
}


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cisco_audit.py",
        description=f"{TOOL_NAME} v{TOOL_VERSION} -- audits a Cisco IOS-XE/SE running-config text export.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python cisco_audit.py -c running.conf --all\n"
               "  python cisco_audit.py -c running.conf --l2 --l3\n"
               "  python cisco_audit.py -c running.conf --all -o C:\\audits\\switch01\n"
               "  python cisco_audit.py -c running.conf --all --format text,json --min-severity high\n",
    )
    p.add_argument("-c", "--config", required=True, type=Path, help="Path to the running-config text export")
    p.add_argument("--all", action="store_true", help="Run every domain (default if no domain flag is given)")
    for key in DOMAIN_ORDER:
        p.add_argument(f"--{key}", action="store_true", help=DOMAIN_FLAG_HELP[key])
    p.add_argument("-o", "--outdir", type=Path, default=None,
                    help="Output directory (default: .\\audit_<hostname>_<timestamp>\\)")
    p.add_argument("--format", default="text", help="Comma-separated: text,json (default: text)")
    p.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"], default="info",
                    help="Only include findings at or above this severity in the report (default: info = all)")
    p.add_argument("--policy", type=Path, default=None, help="Optional JSON file overriding default thresholds")
    p.add_argument("--compliance", action="store_true",
                    help="Also generate compliance cross-reference reports (NIST 800-53, ISO 27002, "
                         "CIS Benchmark, DISA STIG -- coverage varies per framework, see README) "
                         "under sections/compliance_*.txt plus an overview matrix")
    p.add_argument("--exit-on-critical", action="store_true",
                    help="Exit with code 2 if any unresolved CRITICAL finding exists (useful for CI/pipelines)")
    p.add_argument("-v", "--verbose", action="store_true",
                    help="Include PASS/N-A findings and full evidence lists in output, not just failures")
    return p


def determine_domains(args: argparse.Namespace) -> list[str]:
    selected = [key for key in DOMAIN_ORDER if getattr(args, key)]
    if args.all or not selected:
        return list(DOMAIN_ORDER)
    return selected


# =============================================================================
# 19. MAIN
# =============================================================================

def main() -> int:
    args = build_arg_parser().parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows console safety
    except Exception:
        pass

    if not args.config.exists():
        print(f"[!] Config file not found: {args.config}", file=sys.stderr)
        return 1

    raw = read_config_file(args.config)
    if not raw.strip():
        print(f"[!] Config file is empty: {args.config}", file=sys.stderr)
        return 1

    cfg = CiscoConfig(raw)
    policy = load_policy(args.policy)
    domains_to_run = determine_domains(args)

    outdir = args.outdir or Path(f"audit_{cfg.get_hostname()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    sections_dir = outdir / "sections"
    sections_dir.mkdir(parents=True, exist_ok=True)

    ctx = Context()
    domain_results: dict[str, list[Finding]] = {}
    all_findings: list[Finding] = []

    print(f"{TOOL_NAME} v{TOOL_VERSION}")
    print(f"Config:   {args.config}")
    print(f"Host:     {cfg.get_hostname()}  (IOS-XE {cfg.get_version()})")
    print(f"Domains:  {', '.join(domains_to_run)}")
    print(f"Output:   {outdir}")
    print("-" * 60)

    for key in domains_to_run:
        entry = DOMAIN_REGISTRY[key]
        findings: list[Finding] = []
        for func in entry["funcs"]:
            findings.extend(func(cfg, policy, ctx))
        domain_results[key] = findings
        all_findings.extend(findings)
        fails = sum(1 for f in findings if f.status == Status.FAIL)
        print(f"  [{key:>8}] {entry['title']:<32} {len(findings):>3} checks, {fails:>2} failed, "
              f"score {compute_score(findings)}/100")

    correlated = run_correlation_engine(cfg, policy, ctx)
    domain_results["correlation"] = correlated
    all_findings.extend(correlated)
    if correlated:
        print(f"  [{'corr':>8}] {'Correlation Engine':<32} {len(correlated):>3} cross-feature findings")

    print("-" * 60)
    print(f"OVERALL SCORE: {compute_score(all_findings)}/100")

    min_sev = Severity(args.min_severity)
    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}

    if "text" in formats or not formats:
        for key, findings in domain_results.items():
            title = DOMAIN_REGISTRY.get(key, {}).get("title", "Correlation Engine")
            filename = DOMAIN_REGISTRY.get(key, {}).get("file", "correlation_findings.txt")
            write_domain_file(sections_dir / filename, key, title, findings, min_sev, args.verbose)
        write_summary(outdir / "summary.txt", cfg, domain_results, all_findings, min_sev, args)
        print(f"\nText reports written to: {outdir}")

    if "json" in formats:
        write_json(outdir / "findings.json", cfg, all_findings, args)
        print(f"JSON report written to:  {outdir / 'findings.json'}")

    if args.compliance:
        mappings_dir = Path(__file__).resolve().parent / "mappings"
        frameworks = load_compliance_mappings(mappings_dir)
        if not frameworks:
            print(f"\n[!] --compliance requested but no mapping files found under {mappings_dir}",
                  file=sys.stderr)
        else:
            for fw in frameworks:
                write_compliance_framework_file(sections_dir / fw["_report_filename"], fw, all_findings)
            write_compliance_overview(outdir / "compliance_overview.txt", frameworks, all_findings)
            print(f"Compliance cross-reference written to: {outdir / 'compliance_overview.txt'} "
                  f"(+ per-framework files in {sections_dir})")

    if args.exit_on_critical:
        unresolved_critical = any(f.status == Status.FAIL and f.severity == Severity.CRITICAL for f in all_findings)
        if unresolved_critical:
            print("\n[!] Exiting with code 2 due to unresolved CRITICAL finding(s) (--exit-on-critical).",
                  file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
