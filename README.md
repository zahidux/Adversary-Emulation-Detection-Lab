Aewdversary Emulation & Detection Lab Report

---

## Project Overview

This project demonstrates the deployment of a Security Operations Center (SOC) lab environment built with the following stack:

- Kali Linux – serving as the SIEM server
- Splunk Enterprise – for centralized log collection and analysis
- Windows Server 2019 – as the target endpoint environment
- Sysmon – for detailed Windows event logging
- Splunk Universal Forwarder – for log forwarding from endpoints
- Atomic Red Team–to simulate adversary behaviors based on the MITRE ATT & CK framework


The objective was to capture comprehensive Windows endpoint telemetry, forward it to Splunk Enterprise, execute MITRE ATT&CK-aligned adversary simulations with Atomic Red Team, and validate detection coverage using Sysmon-generated events and custom SPL queries.

## Lab Environment Setup 

![Network Diagram](Lab%20Screenshot/Screenshot%202026-06-12%20013019.png)


The lab runs entirely on an isolated, host-only VM network. Kali Linux acts as the control and SIEM node (Splunk indexer/search head + Atomic Red Team attacker), while the Windows Server 2019 VM is the victim/telemetry endpoint running Sysmon and the Splunk Universal Forwarder, sending logs back to the indexer over port 9997.

### Kali Linux VM Configuration

The Kali Linux VM was configured in VMware Workstation Pro with 4 GB RAM, 2 CPU cores, and a NAT network adapter to allow internet access while remaining isolated from the host network.

![Network Diagram](Lab%20Screenshot/kali%20vmware%20config.png)

### Splunk Enterprise Deployment

Splunk Enterprise version 10.4.0 was downloaded from the official Splunk website and installed on the Kali Linux VM.

![Splunk Enterprise Login](Lab%20Screenshot/splunkstrat.png)

### Splunk Search Page 

![Splunk Receiving Configuration](Lab%20Screenshot/splunksearchboard.png)

### Receiving Port Configured 

Splunk was configured to receive log data from the Windows Server forwarder by navigating to Settings > Forwarding and Receiving and adding a new receiving port. Port 9997 was configured as the listening port.

![Splunk Receiving Configuration](Lab%20Screenshot/splunk%20recevingport.png)

### Windows Server 2019 Preparation

The Windows Server 2019 VM was set up in VMware Workstation with 4 GB RAM, 2 CPU cores, 60 GB disk space, and NAT networking to match the Kali VM's network segment.

![Windows Server 2019 VM Configuration](Lab%20Screenshot/windows%20server%20config.png)

### Sysmon Configuration and Installation

Sysmon was downloaded from the Microsoft Sysinternals website and installed on the Windows Server 2019 VM using the command Sysmon64.exe -accepteula -i sysmonconfig.xml with a custom configuration file from SwiftOnSecurity. 

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```
![Sysmon Configuration and Installation](Lab%20Screenshot/sysmonconfig.png)


### Sysmon Start

![Sysmon Start](Lab%20Screenshot/Sysmonstart.png)

### Sysmon Event Viewer log Check

Event Viewer was used to confirm Sysmon was actively logging operational events (process creation, network connections, file creation, etc.):

![Sysmon Event Viewer Log Check](Lab%20Screenshot/SysmonEventViewerlogcheck.png)

### Splunk Universal Forwarder Setup

Splunk Universal Forwarder version 10.4.0 was downloaded from the Splunk website and installed on the Windows Server 2019 VM to forward Sysmon logs to the Kali Linux SIEM. 

![Splunk Universal Forwarder Download](Lab%20Screenshot/splunkforwader.png)


### Atomic Red Team Setup

Atomic Red Team was installed on the Windows Server 2019 VM by running the PowerShell installer script with Set-ExecutionPolicy Bypass, followed by Install-AtomicRedTeam and Import-Module Invoke-AtomicRedTeam.


Set-ExecutionPolicy Bypass
Install-AtomicRedTeam
Import-Module Invoke-AtomicRedTeam

![AtomicTest](Lab%20Screenshot/AtomicTest.png)

## Attack Simulation and Detection (Red Team / Blue Team)

Five MITRE ATT&CK techniques were emulated with Atomic Red Team, then hunted for in Splunk using Sysmon telemetry.

### Attack 1 — T1053.005 (Persistence) | Scheduled Task

`Invoke-AtomicTest T1053.005` created several malicious scheduled tasks (`T1053_005_OnLogon`, `T1053_005_OnStartup`) via `schtasks.exe`.

![Scheduled Task Execution](screenshots/11-attack-t1053-execution.png)

**Detection:** Scheduled task creation behavior was hunted in Sysmon logs by searching for `schtasks.exe`, Task Scheduler, `Schedule.Service`, and hidden scheduled task activity — common persistence indicators.

```spl
index=main sourcetype="WinEventLog"
EventCode=1
Image="*\\schtasks.exe"
CommandLine="*/create*"
| table _time, Image, CommandLine, User, ComputerName
| sort -_time
```

### Attack 2 — T1218.005 (Defense Evasion) | MSHTA

`Invoke-AtomicTest T1218.005` launched `mshta.exe` to execute malicious HTA (HTML Application) files and remote scripts via JavaScript/VBScript engines.

![Scheduled Task Cleanup Commands](screenshots/12-attack-t1053-cleanup.png)

**Detection:** Hunted for suspicious `mshta.exe` execution, HTA file launches, and script-related command-line activity.

```spl
index=main sourcetype="WinEventLog"
EventCode=1
Image="*\\mshta.exe"
| table _time, Image, CommandLine, ParentImage, User, ComputerName
| sort -_time
```

### Attack 3 — T1003.001 (Credential Access) | LSASS Dumping

Simulated credential dumping by accessing LSASS (Local Security Authority Subsystem Service) process memory, using tools such as Mimikatz/ProcDump — a common technique since LSASS stores authentication material in memory.

![MSHTA / HTA Execution](screenshots/13-attack-t1218-mshta.png)

**Detection:** Searched for process-access events targeting `lsass.exe`.

```spl
index=main sourcetype="WinEventLog"
EventCode=10
TargetImage="*\\lsass.exe"
| table _time, SourceImage, TargetImage, GrantedAccess, CallTrace, User, ComputerName
| sort -_time
```

### Attack 4 — T1059.001 (Execution) | PowerShell Download

Simulated a PowerShell-based download-and-execute attack, fetching and running remote scripts via `Invoke-WebRequest`, `DownloadString`, and `IEX`.

![Atomic Red Team Prerequisites](screenshots/14-attack-t1003-prereqs.png)

**Detection:** Hunted for PowerShell command-line activity involving remote content retrieval and in-memory script execution.

```spl
index=main sourcetype="WinEventLog"
EventCode=1
Image="*\\powershell.exe"
(CommandLine="*DownloadString*" OR CommandLine="*IEX*"
 OR CommandLine="*WebClient*" OR CommandLine="*DownloadFile*")
| table _time, Image, CommandLine, ParentImage, User, ComputerName
| sort -_time
```

### Attack 5 — T1112 (Defense Evasion) | Registry Modification

Simulated registry modification attacks where Windows Defender and other security configurations were disabled via `reg.exe` and PowerShell registry edits.

![Registry Modification Test](screenshots/15-attack-t1112-registry.png)

**Detection:** Hunted for registry value changes related to Windows Defender — notification settings and tamper-protection-style modifications — from Sysmon Event ID 13 (RegistryEvent: value set).

![T1112 Detection in Splunk](screenshots/16-blueteam-t1112-detection.png)

```spl
index=main sourcetype="WinEventLog"
EventCode=13
TargetObject="*\\Windows Defender*"
(TargetObject="*DisableAntiSpyware*"
 OR TargetObject="*DisableRealtimeMonitoring*"
 OR TargetObject="*DisableBehaviorMonitoring*")
| table _time, Image, TargetObject, Details, User, ComputerName
| sort -_time
```

---

## Conclusion

This lab successfully demonstrated the deployment and operation of a Security Operations Center (SOC) monitoring environment using Splunk Enterprise, Sysmon, Splunk Universal Forwarder, and Atomic Red Team.

The exercise provided hands-on experience in adversary emulation, security log analysis, SPL query writing, and building detection rules in a real SIEM environment — closely reflecting the skills required in a professional SOC analyst role.

## Repository Structure

```
.
├── README.md
└── screenshots/
    ├── 01-lab-architecture.png
    ├── 02-kali-vm-config.png
    ├── 03-splunk-enterprise-install.png
    ├── 04-splunk-search-page.png
    ├── 05-splunk-receiving-port.png
    ├── 06-winserver-vm-config.png
    ├── 07-sysmon-files.png
    ├── 08-sysmon-install-start.png
    ├── 09-sysmon-eventviewer.png
    ├── 10-splunk-uf-download.png
    ├── 11-attack-t1053-execution.png
    ├── 12-attack-t1053-cleanup.png
    ├── 13-attack-t1218-mshta.png
    ├── 14-attack-t1003-prereqs.png
    ├── 15-attack-t1112-registry.png
    └── 16-blueteam-t1112-detection.png
```
