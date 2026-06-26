# WinEvent Pro

A Windows Event Log monitor built for blue teamers, sysadmins, and anyone who wants to know what's actually happening on their machine in real time.

<img width="1297" height="844" alt="image" src="https://github.com/user-attachments/assets/8384a015-2149-405a-8c72-686be55c85d0" />

It watches your Windows Security, System, and Application logs live, flags suspicious activity with plain-English descriptions, and gives you the context to actually investigate — not just a raw event ID and a wall of text.

---

## Features

**Live Monitoring**
- Watches Security, System, and Application logs in real time
- Every event is colour-coded by severity: Critical / High / Medium / Low / Info
- Descriptions are written in plain English — no need to look up event IDs
- Flashing live indicator so you always know monitoring is active

**Threat Detection**
- Automatically flags suspicious events like new user accounts, failed logins, service installs, scheduled tasks, privilege escalation, and more
- Each alert maps to a MITRE ATT&CK technique where relevant
- Brute force detection built in (configurable threshold and time window)

**Dashboard**
- Live breakdown of events by severity
- Alerts by channel chart
- Session alert feed updates automatically while monitoring

**Investigation**
- Double-click any alert to investigate it
- Opens the file path in Explorer if one is found
- Links directly to the relevant Windows tool (Event Viewer, Task Scheduler, Services, User Management)
- One-click MITRE ATT&CK lookup in your browser

**Historical Scan**
- Scan the last N hours of logs without live monitoring
- Configurable from 1 to 168 hours

**PDF Export**
- Export any session as a formatted threat report
- Includes severity breakdown, full alert list, and descriptions

**Settings**
- Choose which channels to monitor
- Adjust poll interval, brute force threshold, scan depth
- 12 or 24 hour clock toggle
- Auto-start monitoring on launch

---

## Installation

1. Go to the [Releases](../../releases) page
2. Download `WinEventPro_Setup_v1.0.0.exe`
3. Run the installer and follow the steps
4. Launch from your desktop or Start Menu

Requires Windows 10 or later. The app will ask for administrator permission on launch — this is needed to read the Security event log.

> **Note:** Some antivirus tools may flag this as suspicious due to its use of Windows Event Log APIs. The full source is not published but the tool is safe. If your AV blocks it, add an exception or check the releases page for notes.

---

## Screenshots

<img width="1297" height="844" alt="image" src="https://github.com/user-attachments/assets/97d9aa9c-a261-423e-9e7a-be1cfdf2debb" />

<img width="1296" height="842" alt="image" src="https://github.com/user-attachments/assets/b492652a-768c-4eea-abb8-fc942088651e" />

<img width="1294" height="842" alt="image" src="https://github.com/user-attachments/assets/2b5e0657-9280-4be2-92e8-d2dee3913d50" />

<img width="1294" height="842" alt="image" src="https://github.com/user-attachments/assets/d055c8cb-a9fa-4662-b737-39e726e6edc1" />

<img width="1294" height="846" alt="image" src="https://github.com/user-attachments/assets/a2496a90-d236-41c0-97e8-b9627ffa0fd0" />




