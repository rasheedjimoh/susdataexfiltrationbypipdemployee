# Suspected Data Exfiltration from PIPd Employee

## Timeline Summary and Findings

### Identifying Archive Activity
Using Microsoft Defender for Endpoint (MDE), we searched `DeviceFileEvents` for activities involving zipped files. We identified frequent archiving activities where files were moved to a "backup" folder. The following KQL query was used:

```kql
DeviceFileEvents
| where DeviceName == "aarrjlab-vm" and FileName endswith ".zip"
| order by Timestamp desc
```

### Process Analysis
We copied the timestamp (`2025-02-11T17:29:01.8636349Z`) of one such archive creation and examined `DeviceProcessEvents` within a four-minute window (two minutes before and after). This revealed that a PowerShell script silently installed 7-Zip and used it to create an archive of "employee data."

**Relevant Findings:**
- **ProcessCommandLine:** `"7z2408-x64.exe" /S` (Silent installation of 7-Zip)
- **InitiatingProcessCommandLine:** `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1`
- **ProcessCommandLine:** `"7z.exe" a C:\ProgramData\employee-data-20250211173031.zip C:\ProgramData\employee-data-temp20250211173031.csv`

#### KQL Query:
```kql
// 2025-02-11T17:29:01.8636349Z
let specificTime = datetime(2025-02-11T17:29:01.8636349Z);
let VMName = "aarrjlab-vm";
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

---
## Network Activity Analysis
We checked for network activity during the same timeframe to look for signs of data exfiltration. No direct evidence of exfiltration was found. However, we discovered that `powershell_ise.exe` connected to `raw.githubusercontent.com` over port 443.

#### KQL Query:
```kql
let specificTime = datetime(2025-02-11T17:29:01.8636349Z);
let VMName = "aarrjlab-vm";
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m)) and RemoteUrl != ""
| where DeviceName == VMName
| order by Timestamp desc
```

---
## Detecting Silent Process Executions
To identify silently running processes, we executed the following KQL query:

### Query to List Most Silent Processes:
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (" /quiet", " /silent", " /hidden", " /passive", " /S", "start /b", "start /min", "-windowstyle hidden", "-NoProfile", "-ExecutionPolicy Bypass")
| where not(ProcessCommandLine has_any ("cmd.exe", "powershell.exe", "explorer.exe")) // Exclude common interactive processes
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
```

### Query to List All Silent Executions:
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (" /quiet", " /silent", " /hidden", " /passive", " /S", "start /b", "start /min", "-windowstyle hidden", "-NoProfile", "-ExecutionPolicy Bypass")
| where ProcessCommandLine has_any ("cmd.exe", "powershell.exe", "explorer.exe") // Exclude common interactive processes
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
```

---
## Incident Response Actions
- **System Isolation:** Immediately isolated the affected system upon discovering suspicious archiving activities.
- **Detection Rule Creation:** Implemented a detection rule to alert on similar activities and automatically isolate affected devices.
- **Investigation Summary:**
  - Confirmed that an employee archived files using 7-Zip.
  - Identified that the archive was created via a PowerShell script.
  - No confirmed exfiltration activity detected, but potential risks noted.
  - Reported findings to the employee’s manager for further action.
  - Awaiting further instructions from the management team.

---
## MITRE ATT&CK Framework TTPs
### **Identified Techniques:**
- **T1059.001 - Command and Scripting Interpreter: PowerShell**
  - PowerShell was used with `-ExecutionPolicy Bypass` to execute a script.
- **T1560.001 - Archive Collected Data: Archive via Utility**
  - 7-Zip was installed and used to archive data.
- **T1036.005 - Masquerading: Match Legitimate Name or Location**
  - The script was executed from `C:\ProgramData`, a common directory used to evade detection.
- **T1105 - Ingress Tool Transfer**
  - `powershell_ise.exe` connected to `raw.githubusercontent.com`, possibly to download additional tools or scripts.
- **T1071.001 - Application Layer Protocol: Web Protocols**
  - Network activity observed on port 443 to `raw.githubusercontent.com`.
- **T1027 - Obfuscated Files or Information**
  - The script attempted to execute actions in a stealthy manner, likely avoiding detection.
- **T1204.002 - User Execution: Malicious File**
  - A PowerShell script executed an installer (`7z2408-x64.exe`), which may indicate an attempt to introduce a malicious file.
- **T1074.001 - Data Staged: Local Data Staging**
  - Data was archived into a `.zip` file in `C:\ProgramData\`.
- **T1070.004 - Indicator Removal on Host: File Deletion**
  - Possible file manipulation or cleanup might be occurring to remove traces.
- **T1041 - Exfiltration Over C2 Channel (Potential)**
  - While no direct exfiltration was observed, the script's behavior and network activity suggest the potential for data exfiltration.
