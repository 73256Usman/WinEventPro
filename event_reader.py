"""
WinEvent Pro — Event Reader
Reads and normalizes events from Windows Event Log channels via pywin32.
The Security channel requires the process to run as Administrator.
"""

import win32evtlog
import win32evtlogutil
import win32con
import win32security
import pywintypes
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable
import threading


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EventRecord:
    """A normalized Windows event, channel-agnostic."""
    record_id:   int
    event_id:    int
    channel:     str
    source:      str
    timestamp:   datetime
    level:       str
    computer:    str
    user:        Optional[str]
    description: str
    strings:     List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHANNELS = ["Security", "System", "Application"]

MONITORED_IDS: Dict[int, str] = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Account Logoff",
    4647: "User Initiated Logoff",
    4648: "Logon with Explicit Credentials",
    4771: "Kerberos Pre-auth Failed",
    4776: "NTLM Credential Validation",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4723: "Password Change Attempt",
    4724: "Password Reset",
    4725: "User Account Disabled",
    4726: "User Account Deleted",
    4728: "Member Added to Global Security Group",
    4732: "Member Added to Local Security Group",
    4756: "Member Added to Universal Security Group",
    4672: "Special Privileges Assigned",
    4673: "Privileged Service Called",
    4674: "Privileged Object Operation",
    4688: "New Process Created",
    4689: "Process Terminated",
    7045: "New Service Installed",
    7034: "Service Crashed Unexpectedly",
    4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",
    4700: "Scheduled Task Enabled",
    1102: "Audit Log Cleared",
    4719: "System Audit Policy Changed",
}

_LEVEL_MAP = {
    win32con.EVENTLOG_ERROR_TYPE:       "Error",
    win32con.EVENTLOG_WARNING_TYPE:     "Warning",
    win32con.EVENTLOG_INFORMATION_TYPE: "Information",
    win32con.EVENTLOG_AUDIT_SUCCESS:    "Audit Success",
    win32con.EVENTLOG_AUDIT_FAILURE:    "Audit Failure",
}


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

class EventReader:

    def __init__(self):
        self._stop_event = threading.Event()

    # ── Public API ──────────────────────────────────────────────────────────

    def read_channel(
        self,
        channel: str,
        hours_back: int = 24,
        max_events: int = 2000,
        event_ids: Optional[List[int]] = None,
    ) -> List[EventRecord]:
        """
        Return up to max_events records from channel going back hours_back hours.
        Results are sorted newest-first.
        """
        cutoff  = datetime.now() - timedelta(hours=hours_back)
        records: List[EventRecord] = []

        handle = self._open(channel)
        try:
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            while len(records) < max_events:
                try:
                    raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
                except pywintypes.error:
                    break
                if not raw_events:
                    break

                for raw in raw_events:
                    ts = self._parse_timestamp(raw)
                    if ts is None:
                        continue
                    if ts < cutoff:
                        return records

                    eid = raw.EventID & 0xFFFF
                    if event_ids and eid not in event_ids:
                        continue

                    rec = self._normalize(raw, channel, ts)
                    if rec:
                        records.append(rec)

                    if len(records) >= max_events:
                        return records
        finally:
            win32evtlog.CloseEventLog(handle)

        return records

    def start_live_monitor(
        self,
        channels: List[str],
        callback: Callable[[List[EventRecord]], None],
        poll_interval: float = 4.0,
    ) -> threading.Thread:
        """
        Spawn a daemon thread that polls each channel for new events and
        calls callback(batch) once per poll cycle with a list of new records.

        Watermarks are seeded from the true last record number so no existing
        events are replayed when monitoring starts. Windows record numbers are
        persistent sequential IDs — they are NOT the same as the event count,
        which was the root cause of the 31k event replay bug.
        """
        self._stop_event.clear()

        watermarks: Dict[str, int] = {}
        for ch in channels:
            watermarks[ch] = self._get_last_record_number(ch)

        def _poll():
            while not self._stop_event.is_set():
                batch: List[EventRecord] = []
                for ch in channels:
                    try:
                        new = self._fetch_after(ch, watermarks.get(ch, 0))
                        if new:
                            batch.extend(new)
                            watermarks[ch] = new[-1].record_id
                    except Exception:
                        pass
                if batch:
                    # Hard cap: never send more than 200 events per poll cycle
                    callback(batch[:200])
                self._stop_event.wait(poll_interval)

        t = threading.Thread(
            target=_poll, daemon=True, name="WinEventPro-Monitor")
        t.start()
        return t

    def stop_live_monitor(self):
        self._stop_event.set()

    # ── Internals ───────────────────────────────────────────────────────────

    def _open(self, channel: str):
        try:
            return win32evtlog.OpenEventLog(None, channel)
        except pywintypes.error as e:
            if e.winerror == 5:
                raise PermissionError(
                    f"Access denied reading '{channel}' log. "
                    "Run WinEvent Pro as Administrator."
                )
            raise RuntimeError(f"Could not open '{channel}' log: {e}")

    def _get_last_record_number(self, channel: str) -> int:
        """
        Return the RecordNumber of the most recently written event.

        The formula is: oldest_record_number + count - 1.

        This is necessary because Windows event log record numbers are
        persistent sequential IDs that survive log rotation and reboots.
        GetNumberOfEventLogRecords returns the COUNT of records, which is
        completely different from the last record's NUMBER. Using the count
        as a watermark causes all existing events to appear new because
        their actual record numbers are much higher than the count.
        """
        try:
            handle = self._open(channel)
            try:
                oldest = win32evtlog.GetOldestEventLogRecord(handle)
                count  = win32evtlog.GetNumberOfEventLogRecords(handle)
                return (oldest + count - 1) if count > 0 else 0
            finally:
                win32evtlog.CloseEventLog(handle)
        except Exception:
            return 0

    def _parse_timestamp(self, raw) -> Optional[datetime]:
        try:
            t = raw.TimeGenerated
            return datetime(t.year, t.month, t.day, t.hour, t.minute, t.second)
        except Exception:
            return None

    def _resolve_user(self, raw) -> Optional[str]:
        if not raw.Sid:
            return None
        try:
            name, domain, _ = win32security.LookupAccountSid(None, raw.Sid)
            return f"{domain}\\{name}" if domain else name
        except Exception:
            return None

    def _normalize(self, raw, channel: str, ts: datetime) -> Optional[EventRecord]:
        try:
            eid = raw.EventID & 0xFFFF
            try:
                desc = win32evtlogutil.SafeFormatMessage(raw, channel)
                desc = (desc or "").strip() or f"Event ID {eid}"
            except Exception:
                desc = f"Event ID {eid}"
            strings = list(raw.StringInserts) if raw.StringInserts else []
            return EventRecord(
                record_id=raw.RecordNumber,
                event_id=eid,
                channel=channel,
                source=raw.SourceName or "",
                timestamp=ts,
                level=_LEVEL_MAP.get(raw.EventType, "Unknown"),
                computer=raw.ComputerName or "",
                user=self._resolve_user(raw),
                description=desc,
                strings=strings,
            )
        except Exception:
            return None
        
        # Event IDs too noisy to surface in the live monitor.
    # These are legitimate Windows events that fire dozens of times
    # per user action and add no security value to the live feed.
    _NOISE_IDS = {
        5379,   # Credential Manager credentials were read (fires per credential)
        5381,   # Vault credentials were read
        5382,   # Vault credentials were read
        4634,   # Account logoff (extremely frequent, low value)
        4689,   # Process terminated (too frequent)
        4658,   # Handle to object closed (extremely frequent)
        4656,   # Handle to object requested (extremely frequent)
        4663,   # Object access attempt (extremely frequent)
    }

    def _fetch_after(self, channel: str, after_record: int) -> List[EventRecord]:
        """
        Return events with RecordNumber > after_record, sorted oldest-first.

        Reads backwards (newest first) and stops as soon as it hits the
        watermark. This is far more efficient than reading the entire log
        forwards because for the common case of a few new events per poll,
        it only reads those few events and stops immediately.
        """
        records: List[EventRecord] = []
        try:
            handle = self._open(channel)
        except Exception:
            return records

        try:
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            done = False
            while not done:
                try:
                    raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
                except Exception:
                    break
                if not raw_events:
                    break
                for raw in raw_events:
                    if raw.RecordNumber <= after_record:
                        done = True
                        break
                    ts = self._parse_timestamp(raw)
                    if ts is None:
                        continue
                    eid = raw.EventID & 0xFFFF
                    if eid in self._NOISE_IDS:
                        continue
                    rec = self._normalize(raw, channel, ts)
                    if rec:
                        records.append(rec)
                    if len(records) >= 200:
                        done = True
                        break
        finally:
            win32evtlog.CloseEventLog(handle)

        records.reverse()  # Return oldest-first for correct analysis order
        return records