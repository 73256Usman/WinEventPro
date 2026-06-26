"""
WinEvent Pro — Threat Engine
Evaluates EventRecord objects against detection rules and returns ThreatAlert objects.
Each handler extracts specific field data from the event to produce plain-English
descriptions that a non-technical user can understand.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from collections import defaultdict

from event_reader import EventRecord


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ThreatAlert:
    severity:    str
    rule_name:   str
    description: str
    event_id:    int
    channel:     str
    timestamp:   datetime
    computer:    str
    user:        Optional[str]
    record_id:   int
    mitre:       str = ""


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_BRUTE_FORCE_THRESHOLD   = 5
_BRUTE_FORCE_WINDOW_SECS = 120

_SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe",
    "pwdump.exe", "gsecdump.exe", "nc.exe", "ncat.exe",
    "netcat.exe", "psexec.exe", "psexecsvc.exe", "meterpreter.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe", "cmstp.exe",
    "installutil.exe", "regsvcs.exe", "regasm.exe",
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ThreatEngine:

    def __init__(self):
        self._failure_windows: Dict[str, List[datetime]] = defaultdict(list)

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, record: EventRecord) -> Optional[ThreatAlert]:
        eid = record.event_id
        handlers = {
            4625: self._check_brute_force,
            4688: self._check_suspicious_process,
            7045: self._check_new_service,
            6416: self._check_device_connected,
            1102: self._alert_1102,
            4719: self._alert_4719,
            4698: self._alert_4698,
            4699: self._alert_4699,
            4700: self._alert_4700,
            4720: self._alert_4720,
            4728: self._alert_group_member,
            4732: self._alert_group_member,
            4756: self._alert_group_member,
            4648: self._alert_4648,
            4672: self._alert_4672,
            4724: self._alert_4724,
            4725: self._alert_account_change,
            4726: self._alert_account_change,
            4771: self._alert_4771,
            7034: self._alert_7034,
        }
        handler = handlers.get(eid)
        return handler(record) if handler else None

    def analyze_batch(self, records: List[EventRecord]) -> List[ThreatAlert]:
        self.reset_windows()
        alerts: List[ThreatAlert] = []
        for record in sorted(records, key=lambda r: r.timestamp):
            alert = self.analyze(record)
            if alert:
                alerts.append(alert)
        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)

    def reset_windows(self):
        self._failure_windows.clear()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _f(strings: List[str], idx: int, default: str = "unknown") -> str:
        """
        Extract a string field by index.
        Skips Windows SIDs (S-1-...), empty values, placeholder dashes, and
        locale-reference strings (%%NNNN) that Windows uses before message DLLs
        are resolved.
        """
        if idx < len(strings):
            val = (strings[idx] or "").strip()
            if val and not val.startswith("S-1-") and not val.startswith("%%") \
                    and val not in ("-", "{00000000-0000-0000-0000-000000000000}"):
                return val
        return default

    def _make(self, record: EventRecord, severity: str,
              rule_name: str, description: str, mitre: str = "",
              extracted_user: Optional[str] = None) -> ThreatAlert:
        """
        Build a ThreatAlert.  Pass extracted_user when the handler has already
        pulled the relevant account name out of record.strings — this is almost
        always a real human account, whereas record.user comes from the raw event
        SID which is typically SYSTEM or NETWORK SERVICE for security events.
        """
        user = extracted_user if extracted_user and extracted_user != "unknown" \
               else record.user
        return ThreatAlert(
            severity=severity,
            rule_name=rule_name,
            description=description,
            event_id=record.event_id,
            channel=record.channel,
            timestamp=record.timestamp,
            computer=record.computer,
            user=user,
            record_id=record.record_id,
            mitre=mitre,
        )

    # ── Pattern-based rules ───────────────────────────────────────────────────

    def _check_brute_force(self, record: EventRecord) -> Optional[ThreatAlert]:
        key    = record.computer or "unknown"
        now    = record.timestamp
        cutoff = now - timedelta(seconds=_BRUTE_FORCE_WINDOW_SECS)

        self._failure_windows[key] = [
            t for t in self._failure_windows[key] if t >= cutoff
        ]
        self._failure_windows[key].append(now)
        count = len(self._failure_windows[key])
        if count < _BRUTE_FORCE_THRESHOLD:
            return None

        # strings[5] is the target account name in 4625 events
        account = self._f(record.strings, 5, record.user or "an unknown account")
        return self._make(record, "CRITICAL", "Brute Force Attack Detected",
            f"{count} failed login attempts were recorded for '{account}' on computer "
            f"'{key}' within {_BRUTE_FORCE_WINDOW_SECS // 60} minutes. "
            f"This pattern strongly suggests someone is repeatedly trying to guess a "
            f"password. The account may be locked out automatically if an account lockout "
            f"policy is configured. Investigate who is attempting access.",
            "T1110.001",
            extracted_user=account)

    def _check_suspicious_process(self, record: EventRecord) -> Optional[ThreatAlert]:
        # strings[5] is the new process name (full path), strings[1] is who launched it
        process_path = self._f(record.strings, 5, "")
        process_name = process_path.lower().split("\\")[-1] if process_path else ""

        if not process_name and record.description:
            for line in record.description.splitlines():
                if "new process name" in line.lower():
                    raw = line.split(":")[-1].strip()
                    process_path = raw
                    process_name = raw.lower().split("\\")[-1]
                    break

        if process_name not in _SUSPICIOUS_PROCESSES:
            return None

        # strings[1] is the subject account name (who launched the process)
        who = self._f(record.strings, 1, record.user or "an unknown user")
        path_line = f"\nFull path: {process_path}" if process_path else ""
        return self._make(record, "HIGH", "Suspicious Tool Launched",
            f"A program known to be used by hackers was started by '{who}': {process_name}."
            f"{path_line}\n"
            f"This tool is commonly used for stealing passwords, gaining remote access, or "
            f"taking control of other machines on the network. "
            f"Stop this process immediately and investigate how it got onto the system.",
            "T1059",
            extracted_user=who)

    def _check_new_service(self, record: EventRecord) -> Optional[ThreatAlert]:
        service_name = self._f(record.strings, 0, "unknown service")
        service_path = self._f(record.strings, 1, "")

        if not service_path and record.description:
            for line in record.description.splitlines():
                low = line.lower()
                if "service file name" in low or "image path" in low:
                    service_path = line.split(":", 1)[-1].strip()
                    break

        suspicious_paths = [
            "\\temp\\", "\\tmp\\", "\\appdata\\",
            "\\users\\public\\", "\\desktop\\",
            "\\downloads\\", "\\roaming\\",
        ]
        is_suspicious = any(p in service_path.lower() for p in suspicious_paths)

        path_display = service_path if service_path else "path not recorded"

        if is_suspicious:
            return self._make(record, "HIGH", "Service Installed from Suspicious Path",
                f"A Windows service named '{service_name}' was installed from a suspicious "
                f"location: {path_display}. "
                f"Legitimate software always installs services under Program Files or "
                f"System32. When a service installs from Temp, AppData, Desktop, or "
                f"Downloads, it is a strong indicator of malware trying to automatically "
                f"restart itself after every reboot.",
                "T1543.003")

        return self._make(record, "MEDIUM", "New Windows Service Installed",
            f"A new Windows service named '{service_name}' was installed. "
            f"Path: {path_display}. "
            f"New services are normal when installing software. However, if you did not "
            f"recently install anything, an unexpected new service may be running "
            f"a background program without your knowledge.",
            "T1543.003")

    def _check_device_connected(self, record: EventRecord) -> Optional[ThreatAlert]:
        # strings[5] is DeviceDescription, strings[7] is ClassName
        device_desc = self._f(record.strings, 5, "")
        class_name  = self._f(record.strings, 7, "")

        if not device_desc and record.description:
            for line in record.description.splitlines():
                if "device description" in line.lower():
                    device_desc = line.split(":", 1)[-1].strip()
                    break

        label = device_desc or "Unknown Device"
        if class_name and class_name.lower() not in label.lower():
            label = f"{label} ({class_name})"

        return self._make(record, "INFO", "External Device Connected",
            f"A new external device was connected to this computer: {label}. "
            f"This is typically a USB drive, keyboard, mouse, or phone. "
            f"If you did not plug anything in, verify that no unauthorized hardware "
            f"has been physically connected — attackers sometimes use malicious USB "
            f"devices to install software or steal data.",
            "T1200")

    # ── Individual event handlers ─────────────────────────────────────────────

    def _alert_1102(self, record: EventRecord) -> ThreatAlert:
        # strings[1] is the account that cleared the log
        who = self._f(record.strings, 1, record.user or "an unknown user")
        return self._make(record, "CRITICAL", "Security Event Log Cleared",
            f"The entire Windows Security event log was erased by '{who}'. "
            f"This log is the primary record of all security activity on this computer — "
            f"logins, account changes, policy changes, and detected threats. "
            f"Wiping this log destroys all historical evidence. "
            f"This action is almost never done in normal operations and is a "
            f"strong indicator that someone is hiding what they have been doing on the system.",
            "T1070.001",
            extracted_user=who)

    def _alert_4719(self, record: EventRecord) -> ThreatAlert:
        # strings[1] is the account that made the change
        who = self._f(record.strings, 1, record.user or "an unknown user")
        return self._make(record, "CRITICAL", "Windows Auditing Settings Changed",
            f"The Windows security auditing policy was modified by '{who}'. "
            f"Auditing settings control which activities Windows records in the Security log. "
            f"Attackers change these settings specifically to prevent their future actions "
            f"from being logged, making it much harder to detect or investigate a breach. "
            f"Review what was changed and verify it was authorized.",
            "T1562.002",
            extracted_user=who)

    def _alert_4698(self, record: EventRecord) -> ThreatAlert:
        # strings[1] = who created it, strings[4] = task name
        who  = self._f(record.strings, 1, record.user or "an unknown user")
        task = self._f(record.strings, 4, "an unnamed task")
        return self._make(record, "HIGH", "Scheduled Task Created",
            f"A new scheduled task named '{task}' was created by '{who}'. "
            f"Scheduled tasks run programs automatically at set times or when the "
            f"computer starts up. Attackers create scheduled tasks so their malware "
            f"automatically restarts after a reboot or login, even if it is removed "
            f"from the startup folder. Verify this task is expected and check what "
            f"program it is set to run.",
            "T1053.005",
            extracted_user=who)

    def _alert_4699(self, record: EventRecord) -> ThreatAlert:
        # strings[1] = who deleted it, strings[4] = task name
        who  = self._f(record.strings, 1, record.user or "an unknown user")
        task = self._f(record.strings, 4, "an unknown task")
        return self._make(record, "MEDIUM", "Scheduled Task Deleted",
            f"The scheduled task '{task}' was deleted by '{who}'. "
            f"If this task was recently created, the deletion could mean an attacker "
            f"is removing a persistence mechanism after their goal was achieved or "
            f"to cover their tracks. Check whether this task was legitimate.",
            "T1053.005",
            extracted_user=who)

    def _alert_4700(self, record: EventRecord) -> ThreatAlert:
        # strings[1] = who re-enabled it, strings[4] = task name
        who  = self._f(record.strings, 1, record.user or "an unknown user")
        task = self._f(record.strings, 4, "an unknown task")
        return self._make(record, "LOW", "Scheduled Task Re-enabled",
            f"The previously disabled scheduled task '{task}' was turned back on by '{who}'. "
            f"If you did not intentionally re-enable this task, it should be investigated. "
            f"Attackers sometimes re-enable tasks that were disabled by administrators "
            f"as part of reinstating their persistence on the system.",
            "T1053.005",
            extracted_user=who)

    def _alert_4720(self, record: EventRecord) -> ThreatAlert:
        # strings[1] = who created the account, strings[4] = new account name
        who     = self._f(record.strings, 1, record.user or "an unknown user")
        new_acc = self._f(record.strings, 4, "an unnamed account")
        return self._make(record, "HIGH", "New User Account Created",
            f"A new Windows user account named '{new_acc}' was created by '{who}'. "
            f"Creating new user accounts is a common way attackers maintain access to "
            f"a system even after the original password is changed or the initial "
            f"vulnerability is patched. Verify this account was intentionally created "
            f"and is known to your organization.",
            "T1136.001",
            extracted_user=who)

    def _alert_group_member(self, record: EventRecord) -> ThreatAlert:
        eid = record.event_id
        kind = {
            4728: "global security group",
            4732: "local security group",
            4756: "universal security group",
        }.get(eid, "security group")

        # strings[1] = who made the change, strings[4] = member added (CN=... format),
        # strings[6] = group name
        who    = self._f(record.strings, 1, record.user or "an unknown user")
        member = self._f(record.strings, 4, "an unknown user")
        group  = self._f(record.strings, 6, "an unknown group")

        # Strip Active Directory distinguished name prefix (CN=John,OU=Users,...)
        if "cn=" in member.lower():
            member = member.split(",")[0]
            member = member.replace("CN=", "").replace("cn=", "").strip()

        admin_note = ""
        if any(kw in group.lower() for kw in ("admin", "administrator", "domain admin")):
            admin_note = (
                f" This group has administrative privileges — membership gives "
                f"full control over the system or entire domain."
            )

        return self._make(record, "HIGH", "User Added to Security Group",
            f"'{member}' was added to the {kind} '{group}' by '{who}'.{admin_note} "
            f"Adding users to privileged groups is one of the most common ways attackers "
            f"escalate their level of access. Verify this change was authorized.",
            "T1098",
            extracted_user=who)

    def _alert_4648(self, record: EventRecord) -> ThreatAlert:
        # strings[1] = who is sending credentials (the subject)
        # strings[5] = the account being used to log in
        # strings[7] = the target server/computer
        who    = self._f(record.strings, 1, record.user or "an unknown user")
        as_acc = self._f(record.strings, 5, "an unknown account")
        target = self._f(record.strings, 7, "an unknown system")
        return self._make(record, "HIGH", "Login Using Stored Credentials",
            f"'{who}' logged into '{target}' using explicitly provided credentials "
            f"for the account '{as_acc}'. "
            f"Using one account's credentials to authenticate as a different account "
            f"on another system is the defining behavior of lateral movement — "
            f"an attacker using stolen passwords to jump between machines on the network.",
            "T1550.002",
            extracted_user=who)

    def _alert_4672(self, record: EventRecord) -> ThreatAlert:
        # strings[1] is the account name that received special privileges
        who = self._f(record.strings, 1, record.user or "an unknown user")
        return self._make(record, "MEDIUM", "Admin-Level Privileges Assigned at Login",
            f"Administrator-equivalent privileges were assigned to the account '{who}' "
            f"at the time of their login. "
            f"This is expected for accounts in the Administrators group and is not "
            f"automatically suspicious. However, if '{who}' is not an administrator "
            f"or should not have elevated access, this warrants immediate investigation.",
            "T1078",
            extracted_user=who)

    def _alert_4724(self, record: EventRecord) -> ThreatAlert:
        # strings[1] = who performed the reset, strings[4] = whose password was reset
        who    = self._f(record.strings, 1, record.user or "an unknown user")
        target = self._f(record.strings, 4, "an unknown account")
        return self._make(record, "MEDIUM", "Account Password Reset",
            f"The password for the account '{target}' was reset by '{who}'. "
            f"If the account owner did not request this reset, it may mean that an "
            f"attacker with admin access is taking over accounts — either to lock "
            f"legitimate users out or to use the account themselves.",
            "T1098",
            extracted_user=who)

    def _alert_account_change(self, record: EventRecord) -> ThreatAlert:
        # strings[1] = who made the change, strings[4] = the affected account
        eid    = record.event_id
        who    = self._f(record.strings, 1, record.user or "an unknown user")
        target = self._f(record.strings, 4, "an unknown account")

        if eid == 4725:
            return self._make(record, "MEDIUM", "User Account Disabled",
                f"The user account '{target}' was disabled by '{who}'. "
                f"A disabled account cannot log in. While this is routine IT administration, "
                f"attackers disable accounts to lock out administrators while keeping "
                f"their own access through a separate backdoor account.",
                "T1531",
                extracted_user=who)

        return self._make(record, "MEDIUM", "User Account Permanently Deleted",
            f"The user account '{target}' was permanently deleted by '{who}'. "
            f"Deleting an account removes it completely from the system and can be "
            f"used to erase traces of a backdoor account after an attacker is finished, "
            f"or to disrupt legitimate users' ability to log in.",
            "T1531",
            extracted_user=who)

    def _alert_4771(self, record: EventRecord) -> ThreatAlert:
        # strings[0] is the target account name that failed Kerberos pre-auth
        target = self._f(record.strings, 0, "an unknown account")
        return self._make(record, "MEDIUM", "Domain Login Failed (Kerberos)",
            f"A login attempt to the domain failed for the account '{target}'. "
            f"The password provided was incorrect. A single failure is usually just "
            f"a mistyped password. However, many failures across multiple accounts in "
            f"a short time period indicate a password spray attack — where an attacker "
            f"tries one common password against many accounts to avoid triggering "
            f"account lockout policies.",
            "T1110",
            extracted_user=target)

    def _alert_7034(self, record: EventRecord) -> ThreatAlert:
        # strings[0] is the service display name; no user context for service crashes
        service = self._f(record.strings, 0, "an unknown service")
        return self._make(record, "LOW", "Windows Service Crashed",
            f"The Windows service '{service}' stopped running unexpectedly. "
            f"A single crash is usually a software bug or resource issue. "
            f"If you see this repeatedly for the same service, it may mean "
            f"malware is disrupting the service, or that someone is actively "
            f"trying to exploit a vulnerability within it.",
            "")
