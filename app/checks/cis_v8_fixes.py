"""
Auto-remediation "fixers" for the CIS v8 rule engine.

Each entry in FIXES maps a control_id to a function that takes the current
`show running-config` text and returns a new config text with that specific
finding corrected -- the config-text equivalent of the CLI shown in that
rule's `remediation` field in cis_v8_rules.py.

Not every control is safe to fix automatically. A control only gets an
entry here if the correct fix is fully determined by the config itself
(e.g. "delete the plaintext password line", "add a line that has no
site-specific value"). Controls whose correct fix requires information
this tool doesn't have -- a real TACACS+/syslog/NTP IP, a real management
subnet, real SNMPv3 credentials, or human judgment about which interfaces
are "trusted" -- are deliberately left out of FIXES. app/remediation.py
routes those to a ServiceNow change request for a human instead of
guessing at a value that could break connectivity or create a false
sense of security. See MANUAL_REVIEW_REASON below for why each one is
excluded.

After every fix is applied, app/remediation.py re-runs the rule engine
against the patched config and only reports a control as remediated if
it actually now passes -- so this module never has to be trusted blindly.
"""

import re

_PLACEHOLDER_SECRET = "AUTO-REMEDIATED-ROTATE-ME"


# ---------------------------------------------------------------------------
# Generic text-editing helpers
# ---------------------------------------------------------------------------

def _insert_line(config: str, new_line: str, after_patterns=(r"^hostname\s+\S+",)) -> str:
    """Insert new_line right after the first line matching any anchor pattern
    (tried in order); falls back to the top of the file if none match."""
    lines = config.splitlines()
    for pat in after_patterns:
        for i, l in enumerate(lines):
            if re.match(pat, l, re.IGNORECASE):
                lines.insert(i + 1, new_line)
                return "\n".join(lines)
    lines.insert(0, new_line)
    return "\n".join(lines)


def _strip_lines(config: str, *patterns) -> str:
    """Remove any line matching any of the given regex patterns (line-anchored)."""
    lines = config.splitlines()
    lines = [l for l in lines if not any(re.match(p, l, re.IGNORECASE) for p in patterns)]
    return "\n".join(lines)


def _is_stanza_boundary(line: str) -> bool:
    """True for any line that ends a `line ...`/`interface ...` body: the next
    stanza header, or a `!` separator (bare or a trailing comment)."""
    return (
        re.match(r"^line\s", line, re.IGNORECASE) is not None
        or re.match(r"^interface\s", line, re.IGNORECASE) is not None
        or line.lstrip().startswith("!")
    )


def _process_line_stanzas(config: str, header_pred, edit_fn) -> str:
    """
    Walk `line <type> ...` stanzas. header_pred(header_line) -> bool selects
    which stanzas to rewrite; edit_fn(header, body_lines) -> new_body_lines
    returns the replacement sub-command lines for a selected stanza.
    """
    lines = config.splitlines()
    out, i, n = [], 0, len(lines)
    while i < n:
        line = lines[i]
        if re.match(r"^line\s", line, re.IGNORECASE):
            out.append(line)
            i += 1
            body = []
            while i < n and not _is_stanza_boundary(lines[i]):
                body.append(lines[i])
                i += 1
            out.extend(edit_fn(line, body) if header_pred(line) else body)
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def _process_interface_blocks(config: str, header_pred, edit_fn) -> str:
    """Same idea as _process_line_stanzas but for `interface <name> ...` blocks."""
    lines = config.splitlines()
    out, i, n = [], 0, len(lines)
    while i < n:
        line = lines[i]
        if re.match(r"^interface\s", line, re.IGNORECASE):
            out.append(line)
            i += 1
            body = []
            while i < n and not _is_stanza_boundary(lines[i]):
                body.append(lines[i])
                i += 1
            out.extend(edit_fn(line, body) if header_pred(line, body) else body)
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Fixers -- one per auto-remediable control_id
# ---------------------------------------------------------------------------

def fix_enable_secret(config):
    config = _strip_lines(config, r"^enable password\s", r"^enable secret 0?7\s")
    if not re.search(r"^enable secret (8|9|5)\s", config, re.MULTILINE | re.IGNORECASE):
        config = _insert_line(config, f"enable secret 9 {_PLACEHOLDER_SECRET}")
    return config


def fix_local_user_secrets(config):
    return re.sub(
        r"^(username\s+\S+(?:\s+privilege\s+\d+)?)\s+password\s+\S+(?:\s+\S+)?$",
        rf"\1 secret 9 {_PLACEHOLDER_SECRET}",
        config, flags=re.MULTILINE | re.IGNORECASE,
    )


def fix_default_accounts(config):
    return _strip_lines(config, r"^username\s+(cisco|admin|test|guest)\b")


def fix_telnet_disabled(config):
    def ensure_ssh_only(_header, body):
        body = [l for l in body if not re.match(r"^\s*transport input\s", l, re.IGNORECASE)]
        body.append(" transport input ssh")
        return body
    return _process_line_stanzas(config, lambda h: re.match(r"^line vty", h, re.IGNORECASE), ensure_ssh_only)


def fix_ssh_v2(config):
    if re.search(r"^ip ssh version\s+2\b", config, re.MULTILINE | re.IGNORECASE):
        return config
    if re.search(r"^ip ssh version\s+\d\b", config, re.MULTILINE | re.IGNORECASE):
        return re.sub(r"^ip ssh version\s+\d\b", "ip ssh version 2", config, flags=re.MULTILINE | re.IGNORECASE)
    return _insert_line(config, "ip ssh version 2")


def fix_exec_timeout(config):
    def ensure_timeout(_header, body):
        body = [l for l in body if not re.match(r"^\s*exec-timeout\s", l, re.IGNORECASE)]
        body.append(" exec-timeout 10 0")
        return body
    return _process_line_stanzas(config, lambda h: re.match(r"^line (vty|con)", h, re.IGNORECASE), ensure_timeout)


def fix_http_server(config):
    config = _strip_lines(config, r"^ip http server\b")
    if not re.search(r"^no ip http server\b", config, re.MULTILINE | re.IGNORECASE):
        config = _insert_line(config, "no ip http server")
    return config


def fix_aaa_new_model(config):
    if re.search(r"^aaa new-model\b", config, re.MULTILINE | re.IGNORECASE):
        return config
    return _insert_line(config, "aaa new-model")


def fix_aaa_accounting(config):
    if re.search(r"^aaa accounting commands\s", config, re.MULTILINE | re.IGNORECASE):
        return config
    return _insert_line(
        config, "aaa accounting commands 15 default start-stop group tacacs+",
        after_patterns=(r"^aaa new-model\b", r"^hostname\s+\S+"),
    )


def fix_login_lockout(config):
    if re.search(r"^login block-for\s+\d+\s+attempts\s+\d+\s+within\s+\d+", config, re.MULTILINE | re.IGNORECASE):
        return config
    return _insert_line(config, "login block-for 120 attempts 5 within 60")


def fix_snmp_default_community(config):
    return _strip_lines(config, r"^snmp-server community\s+(public|private)\b")


def fix_snmp_rw(config):
    return _strip_lines(config, r"^snmp-server community\s+\S+\s+RW\b")


def fix_logging_timestamps(config):
    config = _strip_lines(config, r"^service timestamps log\s")
    return _insert_line(config, "service timestamps log datetime msec localtime show-timezone")


def fix_logging_buffer(config):
    if re.search(r"^logging buffered\s+(\d+)", config, re.MULTILINE | re.IGNORECASE):
        def repl(m):
            return m.group(0) if int(m.group(1)) >= 16384 else "logging buffered 16384"
        return re.sub(r"^logging buffered\s+(\d+)", repl, config, flags=re.MULTILINE | re.IGNORECASE)
    return _insert_line(config, "logging buffered 16384")


def fix_unused_ports(config):
    def needs_fix(_header, body):
        text = "\n".join(body).lower()
        already_secure = "switchport port-security" in text
        is_shutdown = re.search(r"^\s*shutdown\s*$", "\n".join(body), re.MULTILINE | re.IGNORECASE)
        return "switchport mode access" in text and not already_secure and not is_shutdown

    def add_port_security(_header, body):
        return body + [
            " switchport port-security",
            " switchport port-security maximum 1",
            " switchport port-security violation restrict",
        ]
    return _process_interface_blocks(config, needs_fix, add_port_security)


def fix_native_vlan(config):
    def needs_fix(_header, body):
        text = "\n".join(body).lower()
        if "switchport mode trunk" not in text:
            return False
        m = re.search(r"switchport trunk native vlan\s+(\d+)", text)
        return (not m) or m.group(1) == "1"

    def set_native_vlan(_header, body):
        body = [l for l in body if not re.match(r"^\s*switchport trunk native vlan\s+\d+", l, re.IGNORECASE)]
        body.append(" switchport trunk native vlan 999")
        return body
    return _process_interface_blocks(config, needs_fix, set_native_vlan)


def fix_bpdu_guard(config):
    if re.search(r"^spanning-tree portfast bpduguard default\b", config, re.MULTILINE | re.IGNORECASE):
        return config
    return _insert_line(config, "spanning-tree portfast bpduguard default",
                         after_patterns=(r"^spanning-tree mode\s+\S+", r"^hostname\s+\S+"))


def fix_dhcp_snooping(config):
    if re.search(r"^ip dhcp snooping\b", config, re.MULTILINE | re.IGNORECASE):
        return config
    return _insert_line(config, "ip dhcp snooping")


def fix_proxy_arp(config):
    def needs_fix(_header, body):
        text = "\n".join(body).lower()
        return "ip address" in text and "ip proxy-arp" in text and "no ip proxy-arp" not in text

    def disable_proxy_arp(_header, body):
        return body + [" no ip proxy-arp"]
    return _process_interface_blocks(config, needs_fix, disable_proxy_arp)


def fix_source_routing(config):
    if re.search(r"^no ip source-route\b", config, re.MULTILINE | re.IGNORECASE):
        return config
    return _insert_line(config, "no ip source-route")


def fix_small_servers(config):
    return _strip_lines(
        config,
        r"^service finger\b", r"^ip finger\b",
        r"^service tcp-small-servers\b", r"^service udp-small-servers\b",
    )


def fix_password_encryption_service(config):
    if re.search(r"^service password-encryption\b", config, re.MULTILINE | re.IGNORECASE):
        return config
    return _insert_line(config, "service password-encryption")


def fix_banner(config):
    if re.search(r"^banner (motd|login)\s", config, re.MULTILINE | re.IGNORECASE):
        return config
    banner = ("banner motd ^C\n"
              "Authorized access only. All activity may be monitored and reported.\n"
              "^C")
    return _insert_line(config, banner)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FIXES = {
    "CIS-4.1": fix_enable_secret,
    "CIS-4.2": fix_local_user_secrets,
    "CIS-5.1": fix_default_accounts,
    "CIS-4.3": fix_telnet_disabled,
    "CIS-4.4": fix_ssh_v2,
    "CIS-4.6": fix_exec_timeout,
    "CIS-4.7": fix_http_server,
    "CIS-6.1": fix_aaa_new_model,
    "CIS-6.3": fix_aaa_accounting,
    "CIS-6.4": fix_login_lockout,
    "CIS-4.8": fix_snmp_default_community,
    "CIS-4.10": fix_snmp_rw,
    "CIS-8.2": fix_logging_timestamps,
    "CIS-8.3": fix_logging_buffer,
    "CIS-12.1": fix_unused_ports,
    "CIS-12.2": fix_native_vlan,
    "CIS-13.1": fix_bpdu_guard,
    "CIS-13.2": fix_dhcp_snooping,
    "CIS-4.12": fix_proxy_arp,
    "CIS-4.13": fix_source_routing,
    "CIS-4.14": fix_small_servers,
    "CIS-4.15": fix_password_encryption_service,
    "CIS-14.1": fix_banner,
}

AUTO_REMEDIABLE = frozenset(FIXES.keys())

# Explains, per non-auto-fixable control, *why* it needs a human -- shown on
# the ServiceNow change request and in the dashboard so "manual review" never
# reads as "nothing happened."
MANUAL_REVIEW_REASON = {
    "CIS-1.1": "Hostname needs a real site/role naming convention -- a placeholder would hurt inventory more than it helps.",
    "CIS-5.2": "Reducing local privilege-15 sprawl is an access decision (who keeps break-glass access), not a config toggle.",
    "CIS-4.5": "VTY ACL needs the real management-subnet CIDR; a placeholder ACL would either lock out admins or block nothing.",
    "CIS-6.2": "Centralized AAA needs a real TACACS+/RADIUS server IP and shared secret this tool doesn't have.",
    "CIS-4.9": "SNMPv3 needs real auth/priv passphrases; auto-generating and storing them here would be its own security issue.",
    "CIS-8.1": "Centralized syslog needs the real SIEM/syslog collector IP.",
    "CIS-8.4": "NTP needs the real internal NTP server IP for this site.",
    "CIS-12.3": "Assigning access ports off VLAN 1 needs the site's real VLAN plan; guessing a VLAN ID could break connected hosts.",
    "CIS-13.3": "Dynamic ARP Inspection needs the real access-VLAN list already used for DHCP snooping scoping.",
    "CIS-4.11": "Deciding which interfaces are 'untrusted' for CDP is a topology judgment call, not something derivable from the config alone.",
}


def is_auto_remediable(control_id: str) -> bool:    return control_id in AUTO_REMEDIABLE


def get_fix_fn(control_id: str):
    return FIXES.get(control_id)


def manual_review_reason(control_id: str) -> str:
    return MANUAL_REVIEW_REASON.get(
        control_id,
        "Requires a network engineer's judgment or site-specific information this tool doesn't have.",
    )
