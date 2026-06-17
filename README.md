# Aewdversary Emulation & Detection Lab 

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



## Attack Simulation (Red Team)

Five MITRE ATT&CK techniques were emulated with Atomic Red Team, then hunted for in Splunk using Sysmon telemetry.

### Attack 1 — T1053.005 (Persistence) | Scheduled Task

The Atomic Red Team test for T1053.005 was executed using the command Invoke-AtomicTest T1053.005, which created several malicious scheduled tasks including T1053_005_OnLogon and T1053_005_OnStartup using schtasks.exe. 

![Scheduled Task Execution](Lab%20Screenshot/T1053.005%20Persistence%20Scheduled%20Task.png)


### Attack 2 — T1218.005 (Defense Evasion) | MSHTA

The T1218.005 atomic test was executed using Invoke-AtomicTest T1218.005, which launched mshta.exe to execute malicious HTA (HTML Application) files and remote scripts via JavaScript and VBScript engines. 

![Scheduled Task Cleanup Commands](Lab%20Screenshot/T1218.005%20(Defense%20Evasion).png)


### Attack 3 — T1003.001 (Credential Access) | LSASS Dumping

The T1003.001 atomic test was executed to simulate credential dumping by accessing the LSASS (Local Security Authority Subsystem Service) process memory using tools such as Mimikatz. 

![MSHTA / HTA Execution](Lab%20Screenshot/T1003.001%20(Credential%20Access).png)


### Attack 4 — T1059.001 (Execution) | PowerShell Download

The T1059.001 atomic test simulated a PowerShell-based download and execution attack where PowerShell was used to fetch and run scripts from remote sources using Invoke-WebRequest, DownloadString, and IEX commands.

![Atomic Red Team Prerequisites](Lab%20Screenshot/T1059001%20Execution%20PowerShell%20Download.png)


### Attack 5 — T1112 (Defense Evasion) | Registry Modification

The T1112 atomic test simulated registry modification attacks where Windows Defender and other security configurations were disabled by modifying registry keys using reg.exe and PowerShell. 

![Registry Modification Test](Lab%20Screenshot/T1112%20Defense%20Evasion%20Registry%20Modification.png)



## Detection  (Blue Team)

Detection 1: T1053.005 (Persistence) | Scheduled Task
After executing the Atomic Red Team test for T1053.005, I started the blue team detection phase in Splunk. The goal of this detection was to identify scheduled task creation behavior from Windows Sysmon logs.
This attack was detected by searching for Task Scheduler-related activity, especially schtasks.exe, Task Scheduler, Schedule.Service, and hidden scheduled task behavior. These indicators are useful because attackers commonly use scheduled tasks to maintain persistence on a compromised Windows system.

SPL Query

![T1053.005 (Persistence) ](Lab%20Screenshot/1.png)


Detection 2: T1218.005 (Defense Evasion) | MSHTA
After executing the Atomic Red Team test for T1218.005, I searched Splunk for suspicious MSHTA execution. The detection focused on mshta.exe, HTA file execution, and script-related command-line activity.

SPL Query

![T1218.005 (Defense Evasion) ](Lab%20Screenshot/2.png)


3: T1003.001 (Credential Access) | LSASS Dumping
After executing the Atomic Red Team test for T1003.001, I searched Splunk for LSASS dumping behavior. This test used ProcDump to dump the memory of lsass.exe. Since LSASS stores authentication-related information in memory, attackers commonly target it for credential access.

SPL Query

![T1003.001 (Credential Access) ](Lab%20Screenshot/3.png)

4: T1059.001 (Execution) | PowerShell
After executing the Atomic Red Team test for T1059.001, I searched Splunk for suspicious PowerShell execution. The goal of this detection was to identify PowerShell command-line activity involving MSXML, remote content retrieval, and script execution.

SPL Query

![T1059.001 (Execution) ](Lab%20Screenshot/4.png)

5: T1112 (Defense Evasion) | Registry Modification
After executing the Atomic Red Team tests for T1112, I searched Splunk for registry modification and Windows Defender related configuration changes. The goal of this detection was to identify registry value changes, Defender notification changes, and tamper protection modification attempts from Sysmon logs.

SPL Query

![ T1112 (Defense Evasion) ](Lab%20Screenshot/5.png)


### Key Skills Demonstrated
This project demonstrates practical hands-on experience in both red team emulation and blue team detection engineering. The lab covered the complete workflow of building a small SOC-style detection environment, generating realistic attacker-like activity, collecting endpoint telemetry, and writing SPL queries to identify suspicious behavior.

Key skills demonstrated in this project include:

- Kali Linux based Splunk Enterprise deployment
- Windows Server 2019 security monitoring
- Splunk Universal Forwarder configuration
- Sysmon installation and event collection
- Windows Event Log forwarding
- Custom Splunk index creation
- Atomic Red Team adversary emulation
- MITRE ATT&CK technique mapping
- SPL query writing and field extraction
- Detection of process creation, process access, registry modification, and suspicious command-line activity

## Conclusion

This lab successfully demonstrated the deployment and operation of a Security Operations Center (SOC) monitoring environment using Splunk Enterprise, Sysmon, Splunk Universal Forwarder, and Atomic Red Team.

The exercise provided hands-on experience in adversary emulation, security log analysis, SPL query writing, and building detection rules in a real SIEM environment closely reflecting the skills required in a professional SOC analyst role.
