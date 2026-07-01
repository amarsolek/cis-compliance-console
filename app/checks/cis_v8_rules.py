"""
CIS Controls v8 rule engine for Cisco IOS / NX-OS switch configurations.

Each rule inspects raw `show running-config` text and returns a pass/fail
verdict plus evidence and a remediation snippet. Rules are intentionally
implemented with plain regex / line-scanning rather than a full config
parser, which keeps them transparent and easy to audit -- a deliberate
tradeoff documented in the README.

Each rule is tagged with the CIS Controls v8 Safeguard it maps to most
directly. Mappings reflect the spirit of the safeguard as applied to
network switch configuration; CIS v8 is platform-agnostic, so the
specific Cisco implementation is an interpretation, not an official
CIS publication.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class CheckResult:
    control_id: str
    title: str
    cis_safeguard: str
    severity: str  # "high" | "medium" | "low"
    passed: bool
    evidence: str
    remediation: str = ""


@dataclass
class Rule:
    control_id: str
    title: str
    cis_safeguard: str
    severity: str
    description: str
    check_fn: Callable[[str], CheckResult]


RULES: list[Rule] = []


def rule(control_id, title, cis_safeguard, severity, description):
    """Decorator that registers a check function as a Rule."""
    def decorator(fn):
        RULES.append(Rule(control_id, title, cis_safeguard, severity, description, fn))
        return fn
    return decorator


def _result(control_id, title, cis_safeguard, severity, passed, evidence, remediation=""):
    return CheckResult(control_id, title, cis_safeguard, severity, passed, evidence, remediation)


def _has_line(config: str, pattern: str, flags=re.MULTILINE | re.IGNORECASE) -> Optional[re.Match]:
    return re.search(pattern, config, flags)


def _lines(config: str):
    return [l.rstrip() for l in config.splitlines()]


# ---------------------------------------------------------------------------
# 1. Inventory & access boundary controls (CIS v8 Control 1, 4, 12)
# ---------------------------------------------------------------------------

@rule("CIS-1.1", "Device hostname is configured (not default)", "1.1", "low",
      "An unconfigured/default hostname makes asset inventory and incident response harder.")
def check_hostname(config):
    m = _has_line(config, r"^hostname\s+(\S+)")
    if m and m.group(1).lower() not in ("switch", "router"):
        return _result("CIS-1.1", "Hostname configured", "1.1", "low", True,
                        f"hostname {m.group(1)}")
    return _result("CIS-1.1", "Hostname configured", "1.1", "low", False,
                   "No custom hostname found",
                   "hostname <site>-<role>-<seq>  ! e.g. PHX-DC1-SW01")


@rule("CIS-4.1", "Enable secret uses strong hash (not weak type-7/plaintext)", "4.1", "high",
      "Type 7 is a reversible cipher; type 0 is plaintext. Only type 8/9 (SHA-256/scrypt) or type 5 (MD5, legacy) should be used.")
def check_enable_secret(config):
    weak = _has_line(config, r"^enable password\s")
    type7 = _has_line(config, r"^enable secret 0?7\s")
    strong = _has_line(config, r"^enable secret (8|9)\s") or _has_line(config, r"^enable secret 5\s")
    if weak or type7:
        return _result("CIS-4.1", "Enable secret strength", "4.1", "high", False,
                        "Found 'enable password' or type-7 'enable secret'",
                        "enable secret 9 <new-secret>  ! removes 'enable password'/type-7 lines")
    if strong:
        return _result("CIS-4.1", "Enable secret strength", "4.1", "high", True,
                        "Strong enable secret hash in use")
    return _result("CIS-4.1", "Enable secret strength", "4.1", "high", False,
                    "No 'enable secret' found",
                    "enable secret 9 <new-secret>")


@rule("CIS-4.2", "Local user passwords use strong hashing (secret, not password)", "4.1", "high",
      "Plaintext 'username ... password' lines store credentials insecurely.")
def check_local_user_secrets(config):
    # (?:\s+privilege\s+\d+)? -- an earlier version required "password"/"secret"
    # to immediately follow the username with no privilege clause in between,
    # so e.g. "username netadmin privilege 15 secret 9 ..." (a *correctly*
    # hashed account) was invisible to this check. Fixed alongside CIS-4.6
    # for the same reason: it undermines the auto-remediation before/after
    # story on the very account style the hardened baseline uses.
    plaintext_users = re.findall(r"^username\s+\S+(?:\s+privilege\s+\d+)?\s+password\s", config, re.MULTILINE | re.IGNORECASE)
    secret_users = re.findall(r"^username\s+\S+(?:\s+privilege\s+\d+)?\s+secret\s", config, re.MULTILINE | re.IGNORECASE)
    if plaintext_users:
        return _result("CIS-4.2", "Local user password hashing", "4.1", "high", False,
                        f"{len(plaintext_users)} user(s) using plaintext/weak 'password' keyword",
                        "username <user> privilege <n> secret 9 <new-secret>")
    if secret_users:
        return _result("CIS-4.2", "Local user password hashing", "4.1", "high", True,
                        f"{len(secret_users)} user(s) using 'secret' (hashed) keyword")
    return _result("CIS-4.2", "Local user password hashing", "4.1", "medium", False,
                    "No local user accounts found (may rely solely on AAA/TACACS+)",
                    "Confirm centralized AAA covers break-glass access; otherwise add a hashed local admin.")


@rule("CIS-5.1", "Default/well-known local accounts removed", "5.1", "high",
      "Default vendor or guessable usernames are a common credential-stuffing target.")
def check_default_accounts(config):
    bad_names = ["cisco", "admin", "test", "guest"]
    found = []
    for name in bad_names:
        if _has_line(config, rf"^username\s+{name}\b"):
            found.append(name)
    if found:
        return _result("CIS-5.1", "No default/weak usernames", "5.1", "high", False,
                        f"Found default-style account(s): {', '.join(found)}",
                        f"no username {found[0]}  ! repeat for each, replace with named individual or role accounts")
    return _result("CIS-5.1", "No default/weak usernames", "5.1", "high", True,
                   "No default-style usernames found")


@rule("CIS-5.2", "Privilege 15 limited to authorized admins only", "5.4", "medium",
      "Excessive privilege-15 local accounts widen the blast radius of credential compromise.")
def check_privilege_sprawl(config):
    priv15 = re.findall(r"^username\s+(\S+)\s+privilege\s+15\b", config, re.MULTILINE | re.IGNORECASE)
    if len(priv15) > 3:
        return _result("CIS-5.2", "Privilege 15 account sprawl", "5.4", "medium", False,
                        f"{len(priv15)} local accounts with privilege 15: {', '.join(priv15)}",
                        "Move bulk of admin access to AAA/TACACS+ with role-based privilege levels; keep local priv-15 to break-glass only.")
    return _result("CIS-5.2", "Privilege 15 account sprawl", "5.4", "medium", True,
                   f"{len(priv15)} local privilege-15 account(s) -- within reasonable bound")


# ---------------------------------------------------------------------------
# 2. Secure access / remote management (CIS v8 Control 4, 12)
# ---------------------------------------------------------------------------

@rule("CIS-4.3", "Telnet disabled on VTY lines (SSH only)", "4.4", "high",
      "Telnet transmits credentials and session data in cleartext.")
def check_telnet_disabled(config):
    vty_blocks = re.findall(r"line vty.*?(?=^line |\Z)", config, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if not vty_blocks:
        return _result("CIS-4.3", "Telnet disabled on VTY", "4.4", "high", False,
                        "No 'line vty' stanza found to evaluate",
                        "line vty 0 15\n transport input ssh")
    bad_blocks = []
    for block in vty_blocks:
        transport = re.search(r"transport input\s+(.+)", block, re.IGNORECASE)
        if not transport or "all" in transport.group(1).lower() or "telnet" in transport.group(1).lower():
            bad_blocks.append(block.splitlines()[0].strip())
    if bad_blocks:
        return _result("CIS-4.3", "Telnet disabled on VTY", "4.4", "high", False,
                        f"Telnet permitted on: {', '.join(bad_blocks)}",
                        "line vty 0 15\n transport input ssh")
    return _result("CIS-4.3", "Telnet disabled on VTY", "4.4", "high", True,
                   "All VTY lines restrict transport input to SSH")


@rule("CIS-4.4", "SSH version 2 enforced", "4.4", "high",
      "SSHv1 has known cryptographic weaknesses and should never be enabled.")
def check_ssh_v2(config):
    m = _has_line(config, r"^ip ssh version\s+(\d)")
    if m and m.group(1) == "2":
        return _result("CIS-4.4", "SSH version 2 enforced", "4.4", "high", True,
                        "ip ssh version 2")
    return _result("CIS-4.4", "SSH version 2 enforced", "4.4", "high", False,
                    "SSH version not explicitly pinned to 2",
                    "ip ssh version 2")


@rule("CIS-4.5", "VTY access restricted by ACL", "4.4", "high",
      "Management lines without an access-class are reachable from anywhere that can route to the device.")
def check_vty_acl(config):
    vty_blocks = re.findall(r"line vty.*?(?=^line |\Z)", config, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    missing = []
    for block in vty_blocks:
        if not re.search(r"access-class\s+\S+\s+in", block, re.IGNORECASE):
            missing.append(block.splitlines()[0].strip())
    if missing or not vty_blocks:
        return _result("CIS-4.5", "VTY access-class ACL applied", "4.4", "high", False,
                        f"Missing access-class on: {', '.join(missing) if missing else 'all vty lines'}",
                        "ip access-list standard MGMT-IN\n permit <mgmt-subnet>\nline vty 0 15\n access-class MGMT-IN in")
    return _result("CIS-4.5", "VTY access-class ACL applied", "4.4", "high", True,
                   "All VTY lines reference an inbound access-class")


@rule("CIS-4.6", "Exec timeout configured on management lines", "4.3", "medium",
      "Idle privileged sessions left open are a common pivot point for attackers with physical or session access.")
def check_exec_timeout(config):
    # NOTE: (?:...) here is deliberately non-capturing -- an earlier version
    # used a capturing group, which made re.findall() return just "vty"/"con"
    # instead of the full block text, so this check silently never found any
    # exec-timeout line and failed on every device, including fully hardened
    # ones. Fixed as part of the auto-remediation work since it directly
    # undermines that feature's before/after accuracy.
    vty_con_blocks = re.findall(r"^line (?:vty|con).*?(?=^line |\Z)", config, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    bad = []
    for block in vty_con_blocks:
        m = re.search(r"exec-timeout\s+(\d+)\s+(\d+)", block)
        header = block.splitlines()[0].strip()
        if not m or (int(m.group(1)) == 0 and int(m.group(2)) == 0) or int(m.group(1)) > 10:
            bad.append(header)
    if bad:
        return _result("CIS-4.6", "Exec timeout on mgmt lines", "4.3", "medium", False,
                        f"Missing or excessive exec-timeout on: {', '.join(bad)}",
                        "line vty 0 15\n exec-timeout 10 0")
    return _result("CIS-4.6", "Exec timeout on mgmt lines", "4.3", "medium", True,
                   "Reasonable exec-timeout set on management lines")


@rule("CIS-4.7", "HTTP server disabled (HTTPS only or fully disabled)", "4.4", "medium",
      "Plaintext HTTP management exposes session and credential data.")
def check_http_server(config):
    http_on = _has_line(config, r"^ip http server\b")
    https_on = _has_line(config, r"^ip http secure-server\b")
    if http_on:
        return _result("CIS-4.7", "HTTP server disabled", "4.4", "medium", False,
                        "ip http server is enabled (plaintext)",
                        "no ip http server\nip http secure-server  ! only if a web UI is required")
    return _result("CIS-4.7", "HTTP server disabled", "4.4", "medium", True,
                   "No plaintext HTTP server enabled" + (" (HTTPS enabled)" if https_on else ""))


# ---------------------------------------------------------------------------
# 3. AAA / centralized authentication (CIS v8 Control 6)
# ---------------------------------------------------------------------------

@rule("CIS-6.1", "AAA new-model enabled", "6.1", "high",
      "Without 'aaa new-model', the device cannot use centralized TACACS+/RADIUS authentication or accounting.")
def check_aaa_new_model(config):
    if _has_line(config, r"^aaa new-model\b"):
        return _result("CIS-6.1", "AAA new-model enabled", "6.1", "high", True, "aaa new-model")
    return _result("CIS-6.1", "AAA new-model enabled", "6.1", "high", False,
                    "'aaa new-model' not found",
                    "aaa new-model\naaa authentication login default group tacacs+ local")


@rule("CIS-6.2", "Centralized AAA server (TACACS+/RADIUS) configured", "6.1", "high",
      "Authentication should be centrally managed for fleet-wide credential rotation and audit logging.")
def check_aaa_server(config):
    has_tacacs = _has_line(config, r"^tacacs server\s|^tacacs-server host\s")
    has_radius = _has_line(config, r"^radius server\s|^radius-server host\s")
    if has_tacacs or has_radius:
        kind = "TACACS+" if has_tacacs else "RADIUS"
        return _result("CIS-6.2", "Centralized AAA server configured", "6.1", "high", True,
                        f"{kind} server definition found")
    return _result("CIS-6.2", "Centralized AAA server configured", "6.1", "high", False,
                    "No TACACS+ or RADIUS server defined",
                    "tacacs server PRIMARY-TACACS\n address ipv4 <ip>\n key <shared-secret>")


@rule("CIS-6.3", "AAA accounting enabled for command logging", "6.1", "medium",
      "Without command accounting, there is no audit trail of configuration changes made via CLI.")
def check_aaa_accounting(config):
    if _has_line(config, r"^aaa accounting commands\s"):
        return _result("CIS-6.3", "AAA command accounting enabled", "6.1", "medium", True,
                        "aaa accounting commands ... configured")
    return _result("CIS-6.3", "AAA command accounting enabled", "6.1", "medium", False,
                    "No 'aaa accounting commands' line found",
                    "aaa accounting commands 15 default start-stop group tacacs+")


@rule("CIS-6.4", "Login authentication failure lockout configured", "6.2", "medium",
      "Without a lockout policy, local accounts are vulnerable to unthrottled brute-force attempts.")
def check_login_lockout(config):
    if _has_line(config, r"^login block-for\s+\d+\s+attempts\s+\d+\s+within\s+\d+"):
        return _result("CIS-6.4", "Login failure lockout configured", "6.2", "medium", True,
                        "login block-for ... attempts ... within ... configured")
    return _result("CIS-6.4", "Login failure lockout configured", "6.2", "medium", False,
                    "No 'login block-for' throttling found",
                    "login block-for 120 attempts 5 within 60")


# ---------------------------------------------------------------------------
# 4. SNMP (CIS v8 Control 4, 12)
# ---------------------------------------------------------------------------

@rule("CIS-4.8", "SNMP community strings are not default ('public'/'private')", "4.1", "high",
      "Default SNMP community strings are one of the most commonly exploited network misconfigurations.")
def check_snmp_default_community(config):
    bad = re.findall(r"^snmp-server community\s+(public|private)\b", config, re.MULTILINE | re.IGNORECASE)
    if bad:
        return _result("CIS-4.8", "No default SNMP community strings", "4.1", "high", False,
                        f"Default community string(s) found: {', '.join(set(bad))}",
                        "no snmp-server community public\nno snmp-server community private\n! migrate to SNMPv3")
    return _result("CIS-4.8", "No default SNMP community strings", "4.1", "high", True,
                   "No default SNMP community strings found")


@rule("CIS-4.9", "SNMPv3 in use (not v1/v2c) where SNMP is enabled", "4.1", "medium",
      "SNMPv1/v2c send community strings and data in cleartext with no per-user authentication.")
def check_snmp_v3(config):
    has_v12c = _has_line(config, r"^snmp-server community\s")
    has_v3_user = _has_line(config, r"^snmp-server user\s")
    if not has_v12c and not has_v3_user:
        return _result("CIS-4.9", "SNMPv3 in use where SNMP enabled", "4.1", "low", True,
                        "SNMP not configured on this device")
    if has_v12c and not has_v3_user:
        return _result("CIS-4.9", "SNMPv3 in use where SNMP enabled", "4.1", "medium", False,
                        "SNMPv1/v2c community strings configured, no SNMPv3 users found",
                        "snmp-server group MONITORING v3 priv\nsnmp-server user <nms-svc> MONITORING v3 auth sha <auth-pass> priv aes 128 <priv-pass>")
    return _result("CIS-4.9", "SNMPv3 in use where SNMP enabled", "4.1", "medium", True,
                   "SNMPv3 user(s) configured")


@rule("CIS-4.10", "SNMP read-write access disabled or tightly scoped", "4.1", "high",
      "RW SNMP access allows configuration changes via SNMP, a high-impact and often-overlooked admin path.")
def check_snmp_rw(config):
    rw = re.findall(r"^snmp-server community\s+\S+\s+RW\b", config, re.MULTILINE | re.IGNORECASE)
    if rw:
        return _result("CIS-4.10", "SNMP RW access restricted", "4.1", "high", False,
                        f"{len(rw)} community string(s) with RW access",
                        "no snmp-server community <string> RW  ! use RO + SNMPv3 informs for any required write actions")
    return _result("CIS-4.10", "SNMP RW access restricted", "4.1", "high", True,
                   "No SNMP RW community strings found")


# ---------------------------------------------------------------------------
# 5. Logging & monitoring (CIS v8 Control 8)
# ---------------------------------------------------------------------------

@rule("CIS-8.1", "Centralized syslog server configured", "8.2", "high",
      "Logs retained only locally are lost on reload/compromise and can't support fleet-wide correlation.")
def check_syslog_server(config):
    if _has_line(config, r"^logging host\s|^logging\s+\d+\.\d+\.\d+\.\d+"):
        return _result("CIS-8.1", "Centralized syslog configured", "8.2", "high", True,
                        "logging host/server destination configured")
    return _result("CIS-8.1", "Centralized syslog configured", "8.2", "high", False,
                    "No remote syslog destination found",
                    "logging host <siem-or-syslog-ip>\nlogging trap informational")


@rule("CIS-8.2", "Logging timestamps include date/time with msec and timezone", "8.4", "low",
      "Untimestamped or low-precision logs make incident timeline reconstruction unreliable.")
def check_logging_timestamps(config):
    if _has_line(config, r"^service timestamps log datetime.*msec"):
        return _result("CIS-8.2", "Precise log timestamps enabled", "8.4", "low", True,
                        "service timestamps log datetime msec ...")
    return _result("CIS-8.2", "Precise log timestamps enabled", "8.4", "low", False,
                    "Millisecond datetime timestamps not confirmed",
                    "service timestamps log datetime msec localtime show-timezone")


@rule("CIS-8.3", "Logging buffer size is adequate", "8.3", "low",
      "An undersized local log buffer rolls over quickly during an incident, losing forensic data.")
def check_logging_buffer(config):
    m = _has_line(config, r"^logging buffered\s+(\d+)")
    if m and int(m.group(1)) >= 16384:
        return _result("CIS-8.3", "Adequate logging buffer size", "8.3", "low", True,
                        f"logging buffered {m.group(1)}")
    if m:
        return _result("CIS-8.3", "Adequate logging buffer size", "8.3", "low", False,
                        f"logging buffered {m.group(1)} (below recommended 16384 bytes)",
                        "logging buffered 16384")
    return _result("CIS-8.3", "Adequate logging buffer size", "8.3", "low", False,
                    "No local logging buffer size set",
                    "logging buffered 16384")


@rule("CIS-8.4", "NTP configured for accurate log/event timing", "8.4", "medium",
      "Without synchronized clocks, cross-device log correlation during an incident is unreliable.")
def check_ntp(config):
    if _has_line(config, r"^ntp server\s"):
        return _result("CIS-8.4", "NTP server configured", "8.4", "medium", True,
                        "ntp server ... configured")
    return _result("CIS-8.4", "NTP server configured", "8.4", "medium", False,
                    "No NTP server configured",
                    "ntp server <internal-ntp-ip> prefer")


# ---------------------------------------------------------------------------
# 6. Network segmentation / port security (CIS v8 Control 12, 13)
# ---------------------------------------------------------------------------

@rule("CIS-12.1", "Unused/access switchports have port security or are administratively shut", "12.5", "medium",
      "Unused live ports are a common foothold for unauthorized device connection (rogue AP, dropbox, etc.).")
def check_unused_ports(config):
    iface_blocks = re.findall(r"^interface (\S+).*?(?=^interface |\Z)", config, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    access_ports = re.findall(
        r"^interface (\S+)\n(?:(?!^interface).*\n)*?.*switchport mode access.*$"
        r"(?:\n(?!^interface).*)*",
        config, re.MULTILINE | re.IGNORECASE,
    )
    unsecured = []
    for block_match in re.finditer(r"^interface (\S+)((?:\n(?!^interface).*)*)", config, re.MULTILINE | re.IGNORECASE):
        name, body = block_match.group(1), block_match.group(2)
        if "switchport mode access" in body.lower():
            has_port_security = "switchport port-security" in body.lower()
            is_shutdown = re.search(r"^\s*shutdown\s*$", body, re.MULTILINE | re.IGNORECASE)
            if not has_port_security and not is_shutdown:
                unsecured.append(name)
    if unsecured:
        sample = ", ".join(unsecured[:5]) + (f" (+{len(unsecured)-5} more)" if len(unsecured) > 5 else "")
        return _result("CIS-12.1", "Access ports secured or shut", "12.5", "medium", False,
                        f"{len(unsecured)} access port(s) with neither port-security nor admin shutdown: {sample}",
                        "interface range <unused-ports>\n switchport port-security\n switchport port-security maximum 1\n switchport port-security violation restrict\n shutdown  ! if truly unused")
    return _result("CIS-12.1", "Access ports secured or shut", "12.5", "medium", True,
                   "All access ports have port-security or are administratively shut")


@rule("CIS-12.2", "Native VLAN changed from default (VLAN 1) on trunks", "12.2", "medium",
      "Leaving VLAN 1 as the native/trunk VLAN is a well-known VLAN-hopping risk.")
def check_native_vlan(config):
    trunk_blocks = re.finditer(r"^interface (\S+)((?:\n(?!^interface).*)*)", config, re.MULTILINE | re.IGNORECASE)
    bad = []
    for m in trunk_blocks:
        name, body = m.group(1), m.group(2)
        if "switchport mode trunk" in body.lower():
            native = re.search(r"switchport trunk native vlan\s+(\d+)", body, re.IGNORECASE)
            if not native or native.group(1) == "1":
                bad.append(name)
    if bad:
        return _result("CIS-12.2", "Native VLAN changed from default", "12.2", "medium", False,
                        f"Trunk(s) using default/native VLAN 1: {', '.join(bad)}",
                        "interface <trunk-if>\n switchport trunk native vlan 999  ! unused, non-routed VLAN")
    return _result("CIS-12.2", "Native VLAN changed from default", "12.2", "medium", True,
                   "No trunk ports found using default native VLAN 1")


@rule("CIS-12.3", "VLAN 1 not used for any active access port traffic", "12.2", "low",
      "VLAN 1 is the default VLAN for all switch ports out-of-box and is a common target for VLAN-hopping/ARP attacks.")
def check_vlan1_usage(config):
    vlan1_access = re.findall(
        r"^interface (\S+)((?:\n(?!^interface).*)*)", config, re.MULTILINE | re.IGNORECASE)
    found = [name for name, body in vlan1_access
             if "switchport mode access" in body.lower()
             and not re.search(r"switchport access vlan\s+\d+", body, re.IGNORECASE)]
    if found:
        sample = ", ".join(found[:5])
        return _result("CIS-12.3", "VLAN 1 unused on access ports", "12.2", "low", False,
                        f"Access port(s) with no explicit VLAN assigned (defaulting to VLAN 1): {sample}",
                        "interface range <ports>\n switchport access vlan <non-default-vlan>")
    return _result("CIS-12.3", "VLAN 1 unused on access ports", "12.2", "low", True,
                   "All access ports have an explicit non-default VLAN assigned")


@rule("CIS-13.1", "Spanning-tree BPDU Guard enabled on access/edge ports", "13.4", "medium",
      "Without BPDU Guard, a rogue switch plugged into an access port can manipulate STP topology.")
def check_bpdu_guard(config):
    if _has_line(config, r"^spanning-tree portfast bpduguard default\b"):
        return _result("CIS-13.1", "BPDU Guard enabled globally", "13.4", "medium", True,
                        "spanning-tree portfast bpduguard default")
    per_iface = len(re.findall(r"^\s*spanning-tree bpduguard enable\b", config, re.MULTILINE | re.IGNORECASE))
    if per_iface > 0:
        return _result("CIS-13.1", "BPDU Guard enabled globally", "13.4", "medium", True,
                        f"BPDU Guard enabled on {per_iface} interface(s) individually")
    return _result("CIS-13.1", "BPDU Guard enabled globally", "13.4", "medium", False,
                    "No global or per-interface BPDU Guard found",
                    "spanning-tree portfast bpduguard default")


@rule("CIS-13.2", "DHCP snooping enabled on access VLANs", "13.4", "medium",
      "Without DHCP snooping, rogue DHCP servers can intercept or disrupt client traffic.")
def check_dhcp_snooping(config):
    if _has_line(config, r"^ip dhcp snooping\b"):
        vlans = _has_line(config, r"^ip dhcp snooping vlan\s")
        return _result("CIS-13.2", "DHCP snooping enabled", "13.4", "medium", True,
                        "ip dhcp snooping enabled" + (" with VLAN scope" if vlans else ""))
    return _result("CIS-13.2", "DHCP snooping enabled", "13.4", "medium", False,
                    "DHCP snooping not enabled",
                    "ip dhcp snooping\nip dhcp snooping vlan <access-vlans>")


@rule("CIS-13.3", "Dynamic ARP Inspection (DAI) enabled where DHCP snooping is used", "13.4", "low",
      "DAI relies on the DHCP snooping binding table to block spoofed ARP replies (ARP cache poisoning).")
def check_dai(config):
    snooping = _has_line(config, r"^ip dhcp snooping\b")
    dai = _has_line(config, r"^ip arp inspection vlan\s")
    if not snooping:
        return _result("CIS-13.3", "Dynamic ARP Inspection enabled", "13.4", "low", True,
                        "DHCP snooping not in use; DAI not applicable")
    if dai:
        return _result("CIS-13.3", "Dynamic ARP Inspection enabled", "13.4", "low", True,
                        "ip arp inspection vlan ... configured")
    return _result("CIS-13.3", "Dynamic ARP Inspection enabled", "13.4", "low", False,
                    "DHCP snooping enabled but no Dynamic ARP Inspection found",
                    "ip arp inspection vlan <access-vlans>")


# ---------------------------------------------------------------------------
# 7. Protocol hardening (CIS v8 Control 4)
# ---------------------------------------------------------------------------

@rule("CIS-4.11", "CDP disabled on externally-facing / untrusted interfaces", "4.8", "low",
      "CDP broadcasts device model, IOS version, and IP info that aids reconnaissance if enabled on untrusted links.")
def check_cdp(config):
    global_cdp = _has_line(config, r"^no cdp run\b")
    if global_cdp:
        return _result("CIS-4.11", "CDP disabled on untrusted interfaces", "4.8", "low", True,
                        "CDP disabled globally (no cdp run)")
    return _result("CIS-4.11", "CDP disabled on untrusted interfaces", "4.8", "low", False,
                    "CDP appears enabled globally; verify it is disabled on WAN/untrusted/access interfaces",
                    "interface <untrusted-if>\n no cdp enable")


@rule("CIS-4.12", "Proxy ARP disabled on routed interfaces", "4.8", "low",
      "Proxy ARP can allow hosts on one segment to be tricked into routing through the switch unexpectedly.")
def check_proxy_arp(config):
    iface_blocks = re.finditer(r"^interface (\S+)((?:\n(?!^interface).*)*)", config, re.MULTILINE | re.IGNORECASE)
    enabled_on = [name for name, body in
                  ((m.group(1), m.group(2)) for m in iface_blocks)
                  if "ip address" in body.lower() and "no ip proxy-arp" not in body.lower()
                  and "ip proxy-arp" in body.lower()]
    if enabled_on:
        return _result("CIS-4.12", "Proxy ARP disabled", "4.8", "low", False,
                        f"Proxy ARP explicitly enabled on: {', '.join(enabled_on)}",
                        "interface <if>\n no ip proxy-arp")
    return _result("CIS-4.12", "Proxy ARP disabled", "4.8", "low", True,
                   "No interfaces found with explicit proxy-arp enabled")


@rule("CIS-4.13", "IP source routing disabled", "4.8", "low",
      "Source-routed packets can be used to bypass network path controls.")
def check_source_routing(config):
    if _has_line(config, r"^no ip source-route\b"):
        return _result("CIS-4.13", "IP source routing disabled", "4.8", "low", True,
                        "no ip source-route")
    return _result("CIS-4.13", "IP source routing disabled", "4.8", "low", False,
                    "'no ip source-route' not found",
                    "no ip source-route")


@rule("CIS-4.14", "Finger / small TCP-UDP servers disabled", "4.8", "low",
      "Legacy diagnostic services (finger, chargen, echo) increase attack surface with no operational benefit.")
def check_small_servers(config):
    enabled = []
    if _has_line(config, r"^service finger\b") or _has_line(config, r"^ip finger\b"):
        enabled.append("finger")
    if _has_line(config, r"^service tcp-small-servers\b"):
        enabled.append("tcp-small-servers")
    if _has_line(config, r"^service udp-small-servers\b"):
        enabled.append("udp-small-servers")
    if enabled:
        return _result("CIS-4.14", "Legacy small servers disabled", "4.8", "low", False,
                        f"Enabled: {', '.join(enabled)}",
                        "no service finger\nno service tcp-small-servers\nno service udp-small-servers")
    return _result("CIS-4.14", "Legacy small servers disabled", "4.8", "low", True,
                   "No legacy small-server services enabled")


@rule("CIS-4.15", "Password encryption service enabled for any remaining type-7", "3.11", "low",
      "Even as a stopgap before full secret migration, 'service password-encryption' avoids storing any cleartext passwords in the config.")
def check_password_encryption_service(config):
    if _has_line(config, r"^service password-encryption\b"):
        return _result("CIS-4.15", "Password encryption service enabled", "3.11", "low", True,
                        "service password-encryption")
    return _result("CIS-4.15", "Password encryption service enabled", "3.11", "low", False,
                    "'service password-encryption' not found",
                    "service password-encryption")


# ---------------------------------------------------------------------------
# 8. Banner / legal notice (CIS v8 Control 14 - awareness, often paired w/ legal)
# ---------------------------------------------------------------------------

@rule("CIS-14.1", "Legal/login banner (MOTD) configured", "14.1", "low",
      "An authorized-use banner supports legal action against unauthorized access and signals a managed environment.")
def check_banner(config):
    if _has_line(config, r"^banner (motd|login)\s"):
        return _result("CIS-14.1", "Login banner configured", "14.1", "low", True,
                        "banner motd/login present")
    return _result("CIS-14.1", "Login banner configured", "14.1", "low", False,
                    "No banner motd/login found",
                    'banner motd ^C\nAuthorized access only. All activity may be monitored and reported.\n^C')


def run_all_checks(config_text: str) -> list[CheckResult]:
    """Run every registered rule against a single device's config text."""
    return [r.check_fn(config_text) for r in RULES]


def control_count() -> int:
    return len(RULES)
