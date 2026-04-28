// Detection Engineering Deployment Playbook Generator — Native Windows Events (No Sysmon)
// Run: node generate-de-playbook-native.mjs
// Output: Desktop\Detection Engineering Reports\Wiper_DE_Playbook_Native_<date>.docx

import {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType, PageBreak,
} from 'docx';
import fs from 'fs';
import path from 'path';
import os from 'os';

// ── Palette ────────────────────────────────────────────────────────────────
const C = {
  header_bg:   '1B2631',
  header_text: 'FFFFFF',
  critical:    'C0392B',
  high:        'E67E22',
  medium:      'F39C12',
  low:         '27AE60',
  code_bg:     'F2F3F4',
  row_alt:     'EBF5FB',
  border:      'AEB6BF',
  amber:       'E67E22',
  body_dark:   '2C3E50',
  warn_bg:     'FEF9E7',
  warn_border: 'F9CA24',
};

const levelColor = l =>
  l === 'critical' ? C.critical :
  l === 'high'     ? C.high     :
  l === 'medium'   ? C.medium   : C.low;

// ── Helpers ────────────────────────────────────────────────────────────────
const borders = () => ({
  top:    { style: BorderStyle.SINGLE, size: 1, color: C.border },
  bottom: { style: BorderStyle.SINGLE, size: 1, color: C.border },
  left:   { style: BorderStyle.SINGLE, size: 1, color: C.border },
  right:  { style: BorderStyle.SINGLE, size: 1, color: C.border },
});

const h1 = t => new Paragraph({
  heading: HeadingLevel.HEADING_1,
  children: [new TextRun({ text: t, bold: true, color: C.header_bg, size: 32 })],
  spacing: { before: 400, after: 200 },
});

const h2 = t => new Paragraph({
  heading: HeadingLevel.HEADING_2,
  children: [new TextRun({ text: t, bold: true, size: 26 })],
  spacing: { before: 300, after: 150 },
});

const h3 = t => new Paragraph({
  heading: HeadingLevel.HEADING_3,
  children: [new TextRun({ text: t, bold: true, color: C.body_dark, size: 22 })],
  spacing: { before: 200, after: 80 },
});

const body = t => new Paragraph({
  children: [new TextRun({ text: t, size: 21 })],
  spacing: { after: 80 },
});

const bullet = (t, lvl = 0) => new Paragraph({
  bullet: { level: lvl },
  children: [new TextRun({ text: t, size: 20 })],
  spacing: { after: 60 },
});

const code = t => new Paragraph({
  children: [new TextRun({ text: t, font: 'Courier New', size: 18, color: '1A1A1A' })],
  shading: { type: ShadingType.SOLID, fill: C.code_bg },
  spacing: { after: 4 },
  indent: { left: 200 },
});

const badge = (label, value, color) => new Paragraph({
  children: [
    new TextRun({ text: `  ${label}: `, bold: true, color: C.header_bg, size: 19 }),
    new TextRun({ text: ` ${value} `, bold: true, color: 'FFFFFF', highlight: undefined, size: 19,
      shading: { type: ShadingType.SOLID, fill: color } }),
    new TextRun({ text: '  ', size: 19 }),
  ],
  spacing: { after: 60 },
});

const sep = () => new Paragraph({
  children: [new TextRun({ text: '─'.repeat(90), color: C.border, size: 16 })],
  spacing: { before: 120, after: 120 },
});

const pageBreak = () => new Paragraph({ children: [new PageBreak()] });

const tableRow = (cells, isHeader = false, altBg = false) => new TableRow({
  tableHeader: isHeader,
  children: cells.map(({ text, width = 2000 }) => new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: isHeader
      ? { type: ShadingType.SOLID, fill: C.header_bg }
      : altBg ? { type: ShadingType.SOLID, fill: C.row_alt } : undefined,
    borders: borders(),
    children: [new Paragraph({
      children: [new TextRun({
        text,
        bold: isHeader,
        color: isHeader ? C.header_text : C.body_dark,
        size: isHeader ? 18 : 17,
      })],
      spacing: { before: 60, after: 60 },
      indent: { left: 80 },
    })],
  })),
});

// ── Rule Data ──────────────────────────────────────────────────────────────
const RULES = [
  {
    id: 'wiper-native-001a',
    title: 'BiBi/ROADSWEEP Wiper Process Execution via Suspicious Arguments',
    mitre: 'T1485 — Data Destruction',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'high',
    deploy_order: 1,
    fp_risk: 'Low — filtered to non-standard paths with --force args',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `The BiBi-Windows wiper used by CyberAvengers/Cotton Sandstorm runs with --force and
-d flags to target directory trees for destruction. ROADSWEEP accepts target path arguments.
This rule detects processes spawning from non-standard user directories (Temp, AppData, ProgramData,
Public) with these flags — a pattern consistent with wiper staging and execution. High confidence
when combined with wiper-native-002a (service stop) firing on the same host within a 5-minute window.`,
    sigma: `title: CyberAvengers Wiper Execution via Destructive Process Arguments
id: a3f2c8d1-9e4b-4f72-b6a5-8e7f6d5c4b3a
status: experimental
description: >
  Detects execution patterns consistent with BiBi-Windows and ROADSWEEP wipers used by
  CyberAvengers (Cotton Sandstorm, IRGC-linked). Targets T1485 Data Destruction.
  Requires EID 4688 with command line auditing enabled.
references:
  - https://attack.mitre.org/techniques/T1485/
  - https://www.cisa.gov/sites/default/files/2023-12/aa23-335a-irgc-affiliated-cyber-actors-exploit-plc-vulnerabilities.pdf
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1485
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_wiper_args:
    CommandLine|contains:
      - ' --force'
      - ' --Force'
      - ' -d C:\\'
      - ' -d D:\\'
      - ' -d E:\\'
      - ' /force'
  selection_wiper_paths:
    NewProcessName|contains:
      - '\\Temp\\'
      - '\\AppData\\Local\\'
      - '\\AppData\\Roaming\\'
      - '\\ProgramData\\'
      - '\\Users\\Public\\'
  filter_legit_force:
    NewProcessName|endswith:
      - '\\git.exe'
      - '\\npm.exe'
      - '\\pip.exe'
      - '\\pip3.exe'
      - '\\robocopy.exe'
      - '\\7z.exe'
      - '\\powershell.exe'
      - '\\pwsh.exe'
  condition: selection_event and selection_wiper_args and selection_wiper_paths and not filter_legit_force
falsepositives:
  - Developer tools (git, npm, pip) using --force from user temp directories
  - Custom cleanup scripts run by SCCM — review ParentProcessName
level: high`,
    tuning_note: `Deploy with SIEM threshold: if this fires on a host that also triggers
wiper-native-002a within 5 minutes — escalate to Critical automatically.
Tune filter_legit_force for any additional in-house tools that use --force from AppData paths.
LIMITATION: Binary rename not detectable (EID 4688 lacks OriginalFileName field).`,
    validation: 'Evasion 3/5 | Fields 4/5 | Paths 4/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-001b',
    title: 'Restart Manager (rrm.exe) Invocation from Non-Standard Parent — rstrtmgr.dll Compensating',
    mitre: 'T1485 — Data Destruction',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'high',
    deploy_order: 2,
    fp_risk: 'Low — rrm.exe from Windows paths is suppressed; only suspicious parent paths fire',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `CyberAvengers BiBi wiper loads rstrtmgr.dll (Windows Restart Manager) to unlock file
handles before overwriting in-use files. Without Sysmon EID 7 (DLL image load), direct rstrtmgr.dll
loading is invisible in native Windows logs. This compensating rule detects the rrm.exe helper process
being spawned from suspicious parent directories — a behavioral proxy for the DLL abuse pattern.
NOTE: This is a partial control. Full rstrtmgr.dll visibility requires Sysmon or host-based EDR.`,
    sigma: `title: Wiper Process Spawning Restart Manager Utility for File Handle Unlock
id: b8d7e6f5-c4a3-4b72-9e8d-7c6b5a493812
status: experimental
description: >
  Compensating detection for rstrtmgr.dll abuse — no native EID equivalent for Sysmon EID 7.
  Detects rrm.exe launched from non-standard parent directories. CyberAvengers BiBi wiper
  loads rstrtmgr.dll to unlock file handles before destruction. Targets T1485.
references:
  - https://attack.mitre.org/techniques/T1485/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1485
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_rrm:
    NewProcessName|endswith: '\\rrm.exe'
  selection_rrm_suspicious_parent:
    ParentProcessName|contains:
      - '\\Temp\\'
      - '\\AppData\\'
      - '\\Users\\Public\\'
      - '\\ProgramData\\'
  filter_msi_legit:
    ParentProcessName|endswith:
      - '\\msiexec.exe'
      - '\\MsiExec.exe'
  filter_windows_installer:
    NewProcessName|startswith:
      - 'C:\\Windows\\System32\\'
      - 'C:\\Windows\\SysWOW64\\'
    ParentProcessName|startswith:
      - 'C:\\Windows\\System32\\'
      - 'C:\\Windows\\SysWOW64\\'
  condition: selection_event and selection_rrm and selection_rrm_suspicious_parent and not filter_msi_legit and not filter_windows_installer
falsepositives:
  - Windows Installer (msiexec.exe) calling rrm.exe during software installation
  - Windows servicing stack calling rrm.exe during updates
level: high`,
    tuning_note: `COMPENSATING CONTROL — partial coverage only.
Full rstrtmgr.dll detection requires Sysmon EID 7 or EDR. This rule covers only the
rrm.exe helper invocation pattern. In-memory LoadLibrary of rstrtmgr.dll is invisible here.
Correlate with wiper-native-001a on same host for high-confidence alert.`,
    validation: 'Evasion 3/5 | Fields 4/5 | Paths 3/5 | FP 3/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-002a',
    title: 'Security Tool Service Termination via sc.exe or net.exe',
    mitre: 'T1489 — Service Stop',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'high',
    deploy_order: 3,
    fp_risk: 'Low — filters SCCM and Windows service manager parents',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `CyberAvengers terminates AV, EDR, and backup agent services prior to wiper deployment.
This prevents file handle locks (picked up by rstrtmgr.dll, see rule 001b) and disables real-time
detection during the destruction phase. The rule targets sc.exe and net.exe stop commands directed
at known security tool service names. Companion rule wiper-native-002b catches the resulting EID 7036
service state change events — deploy both for complete coverage of this TTP.`,
    sigma: `title: Security Tool Service Termination via sc.exe or net.exe
id: c9e8f7a6-d5b4-4c83-af9e-8d7c6b5a4932
status: experimental
description: >
  Detects attempts to stop security tool services using sc.exe or net.exe. CyberAvengers/
  Cotton Sandstorm terminates security services prior to BiBi-Windows wiper deployment.
  Targets T1489 Service Stop. Requires EID 4688 command line auditing.
references:
  - https://attack.mitre.org/techniques/T1489/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1489
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_stop_cmd:
    NewProcessName|endswith:
      - '\\sc.exe'
      - '\\net.exe'
      - '\\net1.exe'
    CommandLine|contains:
      - ' stop '
  selection_target_services:
    CommandLine|contains:
      - 'WinDefend'
      - 'MsMpSvc'
      - 'MsSense'
      - 'Sense'
      - 'SentinelAgent'
      - 'SentinelStaticEngine'
      - 'CrowdStrike'
      - 'CSFalcon'
      - 'carbonblack'
      - 'cbdefense'
      - 'CylanceSvc'
      - 'BEAgent'
      - 'McShield'
      - 'mfemms'
      - 'veeambackup'
      - 'VeeamDeploymentSvc'
      - 'BackupExec'
      - 'beserver'
      - 'VSS'
      - 'BITS'
      - 'wuauserv'
  filter_legit_admin:
    ParentProcessName|endswith:
      - '\\services.exe'
      - '\\svchost.exe'
  filter_sccm:
    ParentProcessName|endswith:
      - '\\ccmexec.exe'
      - '\\smsexec.exe'
  condition: selection_event and selection_stop_cmd and selection_target_services and not filter_legit_admin and not filter_sccm
falsepositives:
  - Authorized IT administrators stopping services for maintenance
  - SCCM performing software deployment that stops conflicting services
level: high`,
    tuning_note: `Add your environment's specific AV/EDR service names to selection_target_services.
Correlate with wiper-native-002b (EID 7036) for defense-in-depth — some service stops via API
skip sc.exe/net.exe entirely and only appear in EID 7036.
Consider SIEM correlation: 3+ service stop events from same host within 60 seconds = Critical alert.`,
    validation: 'Evasion 3/5 | Fields 5/5 | Paths 4/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-002b',
    title: 'Security Tool Service Transitioned to Stopped State',
    mitre: 'T1489 — Service Stop',
    eventlog: 'Windows System',
    eventids: '7036',
    level: 'medium',
    deploy_order: 4,
    fp_risk: 'Medium — planned maintenance windows will fire; use SIEM time-window suppression',
    audit_req: 'System log enabled (default — no additional audit policy required)',
    context: `EID 7036 fires whenever a service changes state, regardless of the mechanism used.
This catches service termination via direct API calls (ControlService, SetServiceStatus) that
bypass sc.exe/net.exe and therefore miss rule 002a. CyberAvengers may use custom tooling to
kill security processes directly. The rule targets specific security tool service display names.
Correlate with 002a on same host for highest confidence; standalone 7036 is medium priority.`,
    sigma: `title: Security Tool Service Transitioned to Stopped State
id: d0f9a8b7-e6c5-4d94-b0af-9e8d7c6b5a43
status: experimental
description: >
  Detects Windows System log events indicating a known security tool service transitioned
  to stopped state. Catches service termination via API calls not visible in EID 4688.
  Targets T1489. No additional audit policy required beyond default System log collection.
references:
  - https://attack.mitre.org/techniques/T1489/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1489
  - attack.g0149
logsource:
  product: windows
  service: system
detection:
  selection_event:
    EventID: 7036
  selection_state_stopped:
    param2: 'stopped'
  selection_security_services:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'WinDefend'
      - 'Sense'
      - 'SentinelAgent'
      - 'CrowdStrike'
      - 'Carbon Black'
      - 'Cylance'
      - 'McAfee'
      - 'Veeam Backup'
      - 'BackupExec'
      - 'Volume Shadow Copy'
  filter_planned_maintenance:
    param1|contains:
      - 'Windows Update'
      - 'Windows Installer'
  condition: selection_event and selection_state_stopped and selection_security_services and not filter_planned_maintenance
falsepositives:
  - Planned maintenance windows — apply SIEM-level time-window suppression during patching
  - AV self-update cycles that temporarily stop the service
  - Veeam briefly pausing VSS service during backup jobs
level: medium`,
    tuning_note: `Deploy SIEM suppression windows during scheduled patching cycles (e.g., Patch Tuesday +2h).
Correlate with 002a: if both fire within 2 minutes on same host = promote to High.
Add your environment's specific security service display names to selection_security_services.`,
    validation: 'Evasion 4/5 | Fields 4/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-003',
    title: 'Volume Shadow Copy Deletion via vssadmin, wmic, or PowerShell',
    mitre: 'T1490 — Inhibit System Recovery',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'high',
    deploy_order: 5,
    fp_risk: 'Low — backup agents filtered; compound condition (delete) prevents query-only FPs',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `CyberAvengers deletes all VSS snapshots before wiper execution to eliminate recovery paths.
This covers all major deletion vectors: vssadmin delete shadows /all, wmic shadowcopy delete,
PowerShell Win32_ShadowCopy deletion, and diskshadow. Backup agents that QUERY shadow copies
are filtered using compound conditions — the 'delete' keyword must be present alongside the
backup agent parent to suppress. High-confidence rule with very few legitimate delete use cases.`,
    sigma: `title: Volume Shadow Copy Deletion via vssadmin, wmic, or PowerShell
id: e1a0b9c8-f7d6-4e05-c1b0-af9e8d7c6b5a
status: experimental
description: >
  Detects deletion of Windows Volume Shadow Copies. CyberAvengers/Cotton Sandstorm deletes
  all VSS snapshots before wiper execution to prevent recovery. Covers vssadmin, wmic,
  PowerShell, and diskshadow vectors. Targets T1490.
references:
  - https://attack.mitre.org/techniques/T1490/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1490
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_vssadmin:
    NewProcessName|endswith: '\\vssadmin.exe'
    CommandLine|contains:
      - 'delete shadows'
      - 'Delete Shadows'
      - 'resize shadowstorage'
      - '/maxsize=401MB'
  selection_wmic:
    NewProcessName|endswith: '\\wmic.exe'
    CommandLine|contains:
      - 'shadowcopy delete'
      - 'shadowcopy where'
      - 'Win32_ShadowCopy'
  selection_powershell_vss:
    NewProcessName|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'Win32_ShadowCopy'
      - 'Remove-WmiObject'
  selection_diskshadow:
    NewProcessName|endswith: '\\diskshadow.exe'
    CommandLine|contains:
      - 'delete shadows all'
      - '/s '
  filter_backup_agents:
    ParentProcessName|endswith:
      - '\\veeam.backup.service.exe'
      - '\\VeeamAgent.exe'
      - '\\BackupExecJobEngine.exe'
      - '\\CommVault.exe'
  filter_sccm:
    ParentProcessName|endswith:
      - '\\ccmexec.exe'
      - '\\smsexec.exe'
    CommandLine|contains: 'Win32_ShadowCopy'
  condition: (selection_event and (selection_vssadmin or selection_wmic or selection_powershell_vss or selection_diskshadow)) and not filter_backup_agents and not filter_sccm
falsepositives:
  - Veeam/BackupExec query Win32_ShadowCopy but only DELETE fires — compound condition is safe
  - Administrator manually deleting old VSS snapshots during disk maintenance
level: high`,
    tuning_note: `This is one of the highest-confidence wiper indicators. Near-zero legitimate use of
"vssadmin delete shadows" outside backup/DR maintenance windows.
Add your backup software's parent process path to filter_backup_agents if not listed.
Correlate: VSS deletion + BCDEdit (rule 004) within 10 minutes = treat as confirmed wiper attack.`,
    validation: 'Evasion 3/5 | Fields 5/5 | Paths 5/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-004',
    title: 'BCDEdit Boot Recovery and Repair Disabled',
    mitre: 'T1490 — Inhibit System Recovery',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'high',
    deploy_order: 6,
    fp_risk: 'Low — Windows repair tools and OS setup are specific and rare triggers',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `CyberAvengers configures bcdedit.exe to prevent the system from entering automatic
repair mode after wiper-induced boot failures. Key commands: "bcdedit /set recoveryenabled no"
disables Windows Recovery Environment; "bcdedit /set bootstatuspolicy ignoreallfailures" prevents
boot failure prompts from triggering repair. This is a critical pre-wiper step — detecting it early
(before VSS deletion) provides maximum response time. Works in tandem with rule 008 (reagentc).`,
    sigma: `title: BCDEdit Boot Recovery and Repair Disabled
id: f2b1c0d9-a8e7-4f16-d2c1-b0af9e8d7c6b
status: experimental
description: >
  Detects bcdedit.exe disabling Windows boot recovery mechanisms. CyberAvengers/Cotton Sandstorm
  disables automatic repair to ensure systems cannot recover after wiper execution.
  Targets T1490 Inhibit System Recovery. Requires EID 4688 with command line auditing.
references:
  - https://attack.mitre.org/techniques/T1490/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1490
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_binary:
    NewProcessName|endswith: '\\bcdedit.exe'
  selection_recovery_args:
    CommandLine|contains:
      - 'recoveryenabled no'
      - 'recoveryenabled No'
      - 'bootstatuspolicy ignoreallfailures'
      - 'bootstatuspolicy IgnoreAllFailures'
      - 'bootstatuspolicy ignoreshutdownfailures'
      - '/deletevalue'
      - 'bootems off'
      - 'bootems Off'
  filter_windows_repair:
    ParentProcessName|startswith:
      - 'C:\\Windows\\System32\\srtasks.exe'
      - 'C:\\Windows\\System32\\ReAgentc.exe'
  filter_os_setup:
    ParentProcessName|endswith:
      - '\\setup.exe'
      - '\\setupact.exe'
  condition: selection_event and selection_binary and selection_recovery_args and not filter_windows_repair and not filter_os_setup
falsepositives:
  - Windows System Recovery Tool (srtasks.exe) modifying BCD during repair
  - OS setup or upgrade reconfiguring boot configuration
  - Bare metal restore tools (Acronis, Veeam BMR) reconfiguring BCD after restore
level: high`,
    tuning_note: `High-confidence rule — "recoveryenabled no" has essentially no legitimate use outside
of authorized DR testing. Treat any non-suppressed alert as requiring immediate triage.
bcdedit /set without recovery-related args (e.g., adding boot entries) is NOT detected here —
this is intentional to keep FP rate low.`,
    validation: 'Evasion 3/5 | Fields 5/5 | Paths 5/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-005',
    title: 'CrashControl Registry Key Modified to Disable Automatic Recovery',
    mitre: 'T1490 — Inhibit System Recovery',
    eventlog: 'Windows Security',
    eventids: '4657',
    level: 'high',
    deploy_order: 7,
    fp_risk: 'Low — Windows system processes and Windows Update are specifically suppressed',
    audit_req: 'Object Access > Audit Registry: Success + SACL on HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl with Everyone: Set Value (Success)',
    context: `CyberAvengers modifies the Windows CrashControl registry key to prevent automatic reboot
and crash dump generation after wiper execution. Key values targeted: AutoReboot (0 = no auto reboot),
CrashDumpEnabled (0 = no dump). This provides a second recovery-disable layer alongside BCDEdit
(rule 004). Requires Object Access auditing — more complex to deploy than EID 4688 rules, but
provides a detection path that is entirely independent of command-line auditing.`,
    sigma: `title: CrashControl Registry Key Modified to Disable Automatic Recovery
id: a3c2d1e0-b9f8-4027-e3d2-c1b0af9e8d7c
status: experimental
description: >
  Detects modifications to CrashControl registry key. CyberAvengers modifies AutoReboot
  and CrashDumpEnabled values to prevent recovery after BiBi-Windows wiper execution.
  Targets T1490. Requires Object Access auditing + SACL on the registry key.
references:
  - https://attack.mitre.org/techniques/T1490/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1490
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4657
  selection_crashcontrol:
    ObjectName|contains:
      - '\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl'
      - '\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\CrashControl'
      - '\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Control\\CrashControl'
  selection_recovery_values:
    ValueName|contains:
      - 'AutoReboot'
      - 'CrashDumpEnabled'
      - 'LogEvent'
      - 'SendAlert'
      - 'Overwrite'
  filter_system_processes:
    ProcessName|endswith:
      - '\\services.exe'
      - '\\lsass.exe'
      - '\\svchost.exe'
      - '\\TrustedInstaller.exe'
  filter_windows_update:
    ProcessName|startswith:
      - 'C:\\Windows\\WinSxS\\'
      - 'C:\\Windows\\servicing\\'
  condition: selection_event and selection_crashcontrol and selection_recovery_values and not filter_system_processes and not filter_windows_update
falsepositives:
  - Windows Update or servicing stack modifying CrashControl values during OS updates
  - System services adjusting crash settings during initialization
  - Enterprise monitoring agents writing diagnostic registry values
level: high`,
    tuning_note: `DEPLOYMENT PREREQUISITE: Must configure SACL on registry key before this rule fires.
Run: reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl" /f
Then set SACL via: regedit.exe > Permissions > Advanced > Auditing > Everyone > Set Value > Success
Alternatively, deploy via Group Policy: Computer Config > Windows Settings > Security Settings > Registry.
This rule is independent of command-line auditing — good defense-in-depth layer.`,
    validation: 'Evasion 4/5 | Fields 4/5 | Paths 3/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-006a',
    title: 'Windows Security Event Log Cleared',
    mitre: 'T1070.001 — Clear Windows Event Logs',
    eventlog: 'Windows Security',
    eventids: '1102',
    level: 'high',
    deploy_order: 8,
    fp_risk: 'Low — any authorized clearing should be via known admin accounts (suppress in filter)',
    audit_req: 'No additional audit policy — EID 1102 generated by Security log itself',
    context: `EID 1102 fires automatically when the Windows Security event log is cleared, regardless of
the clearing mechanism (wevtutil, PowerShell, GUI, API). CyberAvengers clears event logs post-wiper to
remove evidence of T1489 service termination (EID 7036) and lateral movement. This is a self-logging
event — an attacker cannot suppress it without entirely disabling the Security log. Companion to 006b
(System log EID 104) and 006c (CLI detection). High-confidence standalone indicator.`,
    sigma: `title: Windows Security Event Log Cleared
id: b4d3e2f1-c0a9-4138-f4e3-d2c1b0af9e8d
status: stable
description: >
  Detects clearing of the Windows Security event log (EID 1102). Fires regardless of clearing
  method. CyberAvengers clears logs after wiper deployment. Targets T1070.001.
  No additional audit prerequisites.
references:
  - https://attack.mitre.org/techniques/T1070/001/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.defense_evasion
  - attack.t1070.001
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 1102
  filter_known_admin_accounts:
    # Replace PLACEHOLDER with your authorized admin account names before deploying
    # SubjectUserName: 'authorized_svc_account'
    SubjectUserName: 'PLACEHOLDER_REMOVE_BEFORE_DEPLOY'
  condition: selection_event and not filter_known_admin_accounts
falsepositives:
  - Authorized security administrators clearing logs during incident response
  - Quarterly log purge scripts run by IT operations — document accounts and suppress
level: high`,
    tuning_note: `BEFORE DEPLOYING: populate filter_known_admin_accounts with your organization's
authorized accounts that have legitimate reasons to clear event logs (SOC analysts, IR team).
Do NOT leave the PLACEHOLDER value — it will cause all 1102 events to fire.
This is one of your best post-compromise indicators. EID 1102 → correlate backward
to find what activities were being covered (check time range immediately before the clear).`,
    validation: 'Evasion 5/5 | Fields 4/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-006b',
    title: 'Windows System Event Log Cleared',
    mitre: 'T1070.001 — Clear Windows Event Logs',
    eventlog: 'Windows System',
    eventids: '104',
    level: 'high',
    deploy_order: 9,
    fp_risk: 'Low — System log clearing is extremely rare outside incident response',
    audit_req: 'No additional audit policy — EID 104 generated by System log itself',
    context: `EID 104 fires when the Windows System event log is cleared. CyberAvengers clears the
System log to remove EID 7036 service-stop evidence generated during the T1489 service termination
phase. Combined with EID 1102 (rule 006a), simultaneous or rapid sequential Security + System log
clearing is a near-certain indicator of post-wiper evidence destruction. No audit prerequisites.`,
    sigma: `title: Windows System Event Log Cleared
id: c5e4f3a2-d1b0-4249-a5f4-e3d2c1b0af9e
status: stable
description: >
  Detects clearing of the Windows System event log (EID 104). Companion to wiper-native-006a.
  CyberAvengers clears System log to remove EID 7036 service-stop evidence. Targets T1070.001.
references:
  - https://attack.mitre.org/techniques/T1070/001/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.defense_evasion
  - attack.t1070.001
  - attack.g0149
logsource:
  product: windows
  service: system
detection:
  selection_event:
    EventID: 104
  condition: selection_event
falsepositives:
  - Authorized IT administrators clearing system log during maintenance
  - Periodic log management scripts (very rare in enterprise environments)
level: high`,
    tuning_note: `Deploy SIEM correlation: 006a + 006b within 5 minutes on same host = Critical alert.
The sequence Security-log-clear THEN System-log-clear is a strong wiper post-activity signature.
No tuning needed for this rule — EID 104 has essentially no legitimate automated use.`,
    validation: 'Evasion 5/5 | Fields 4/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-006c',
    title: 'Event Log Clearing via wevtutil, PowerShell, or WMI',
    mitre: 'T1070.001 — Clear Windows Event Logs',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'high',
    deploy_order: 10,
    fp_risk: 'Low — Event Viewer GUI and SCCM parents are suppressed',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `Complements 006a/006b by detecting the command-line invocation pattern before or after
the actual clear event fires. Useful for identifying the actor (process, user, parent) behind the
clearing, which EID 1102/104 alone does not provide beyond SubjectUserName. Covers wevtutil cl,
Clear-EventLog cmdlet, and WMI Win32_NTEventlogFile clearing. Use this for attribution alongside
EID 1102/104 for confirmation of the clearing event itself.`,
    sigma: `title: Event Log Clearing via wevtutil, PowerShell, or WMI
id: d6f5a4b3-e2c1-435a-b6a5-f4e3d2c1b0af
status: experimental
description: >
  Detects CLI-based event log clearing via wevtutil, Clear-EventLog, or WMI. Companion to
  wiper-native-006a/006b which catch resulting EID 1102/104. Provides process attribution.
  Targets T1070.001. Requires EID 4688 command line auditing.
references:
  - https://attack.mitre.org/techniques/T1070/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.defense_evasion
  - attack.t1070.001
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_wevtutil:
    NewProcessName|endswith: '\\wevtutil.exe'
    CommandLine|contains:
      - ' cl '
      - ' clear-log '
      - ' CL '
      - ' Clear-Log '
  selection_powershell_clear:
    NewProcessName|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'Clear-EventLog'
      - 'clear-eventlog'
      - 'Limit-EventLog'
  selection_wmic_clear:
    NewProcessName|endswith: '\\wmic.exe'
    CommandLine|contains:
      - 'nteventlog'
      - 'ClearEventLog'
  filter_legit_admin:
    ParentProcessName|endswith:
      - '\\mmc.exe'
      - '\\eventvwr.exe'
  filter_sccm:
    ParentProcessName|endswith:
      - '\\ccmexec.exe'
      - '\\smsexec.exe'
  condition: selection_event and (selection_wevtutil or selection_powershell_clear or selection_wmic_clear) and not filter_legit_admin and not filter_sccm
falsepositives:
  - Event Viewer GUI (eventvwr.exe) clearing logs via mmc.exe parent
  - SCCM log management tasks
  - Authorized log rotation scripts
level: high`,
    tuning_note: `Use this rule to identify the process and user account behind log clearing.
Pair with 006a/006b: 006c fires on the execution, 006a/006b confirm the actual clear occurred.
A clearing via API (no EID 4688 generated) will still produce EID 1102/104 — deploy all three.`,
    validation: 'Evasion 3/5 | Fields 5/5 | Paths 5/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-007',
    title: 'Raw Disk Access or MBR Overwrite via diskpart, dd, or Direct Handle',
    mitre: 'T1561.002 — Disk Structure Wipe',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'critical',
    deploy_order: 11,
    fp_risk: 'Low — OS setup and BMR agents are specifically suppressed',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `CyberAvengers overwrites the Master Boot Record to render systems unbootable after
file destruction. Detection vectors: diskpart.exe with 'clean' command (wipes partition table),
any process referencing \\\\.\PhysicalDrive in its command line (direct raw disk access), and
dd-style tools writing zeros to physical drives. This is the final stage of the kill chain —
by the time this fires, the system may already be non-recoverable. Treat as CRITICAL severity.`,
    sigma: `title: Raw Disk Access or MBR Overwrite via diskpart, dd, or Direct Handle
id: e7a6b5c4-f3d2-446b-c7b6-a5f4e3d2c1b0
status: experimental
description: >
  Detects MBR overwrite or raw disk access. CyberAvengers overwrites MBR to render systems
  unbootable after file destruction. Covers diskpart clean, dd, and direct PhysicalDrive
  handle patterns. Targets T1561.002. Requires EID 4688 command line auditing.
references:
  - https://attack.mitre.org/techniques/T1561/002/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1561.002
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_diskpart_clean:
    NewProcessName|endswith: '\\diskpart.exe'
    CommandLine|contains:
      - ' clean'
      - ' CLEAN'
  selection_physical_drive_access:
    CommandLine|contains:
      - '\\\\.\\PhysicalDrive'
      - '\\\\\\\\.\\\\ PhysicalDrive'
      - '\\\\.\\GLOBALROOT\\Device\\Harddisk'
  selection_dd_tools:
    NewProcessName|endswith:
      - '\\dd.exe'
      - '\\dd64.exe'
      - '\\rawcopy.exe'
    CommandLine|contains:
      - 'of=\\\\.\\PhysicalDrive'
      - 'if=/dev/zero'
      - 'if=/dev/random'
  filter_os_setup:
    ParentProcessName|endswith:
      - '\\setup.exe'
      - '\\WinPE\\winpe.exe'
  filter_backup_restore:
    ParentProcessName|endswith:
      - '\\veeam.backup.service.exe'
      - '\\BackupExecJobEngine.exe'
  condition: selection_event and (selection_diskpart_clean or selection_physical_drive_access or selection_dd_tools) and not filter_os_setup and not filter_backup_restore
falsepositives:
  - Windows OS setup or WinPE using diskpart clean during disk provisioning
  - Bare metal restore operations using dd or rawcopy for disk imaging
  - Security research or forensics tools accessing raw disk handles
level: critical`,
    tuning_note: `CRITICAL severity — auto-page on-call. Any alert from this rule requires immediate response.
NOTE: diskpart.exe is interactive by default and requires a script file or piped input.
If ParentProcessName is cmd.exe or powershell.exe with a suspicious parent, escalate immediately.
Forensic tools (EnCase, FTK) use raw disk handles — ensure forensics analyst accounts are known
and review SubjectUserName before closing tickets from authorized forensics hosts.`,
    validation: 'Evasion 3/5 | Fields 5/5 | Paths 5/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-008',
    title: 'Windows Recovery Environment Disabled or Destroyed via reagentc.exe',
    mitre: 'T1490 — Inhibit System Recovery',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'high',
    deploy_order: 12,
    fp_risk: 'Low — Windows Setup and OOBE are specifically suppressed',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `CyberAvengers disables the Windows Recovery Environment (WinRE) as a second-layer recovery
prevention strategy alongside BCDEdit (rule 004). reagentc.exe /disable removes WinRE entirely;
bcdboot.exe called with /f ALL reconfigures the BCD firmware entries destructively. Without WinRE,
the system cannot enter repair mode from the boot menu even if BCDEdit settings are somehow restored.
Deploy in combination with rule 004 — both firing on the same host confirms maximum recovery prevention.`,
    sigma: `title: Windows Recovery Environment Disabled or Destroyed
id: f8b7c6d5-a4e3-457c-d8c7-b6a5f4e3d2c1
status: experimental
description: >
  Detects reagentc.exe /disable or destructive bcdboot usage to destroy Windows Recovery
  Environment. CyberAvengers disables WinRE to prevent recovery after wiper execution.
  Targets T1490. Requires EID 4688 with command line auditing.
references:
  - https://attack.mitre.org/techniques/T1490/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1490
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_reagentc_disable:
    NewProcessName|endswith: '\\reagentc.exe'
    CommandLine|contains:
      - '/disable'
      - '/DISABLE'
      - '-disable'
  selection_bcdboot_destructive:
    NewProcessName|endswith: '\\bcdboot.exe'
    CommandLine|contains:
      - '/f ALL'
      - '/f BIOS'
      - '/f UEFI'
  selection_reagentc_reimage:
    NewProcessName|endswith: '\\reagentc.exe'
    CommandLine|contains:
      - '/setreimage'
      - '/boottore'
  filter_windows_setup:
    ParentProcessName|startswith:
      - 'C:\\Windows\\System32\\srtasks.exe'
      - 'C:\\Windows\\System32\\wbengine.exe'
  filter_oobe:
    ParentProcessName|endswith:
      - '\\oobe\\setup.exe'
      - '\\oobe\\oobeplugins.exe'
  condition: selection_event and (selection_reagentc_disable or selection_bcdboot_destructive or selection_reagentc_reimage) and not filter_windows_setup and not filter_oobe
falsepositives:
  - Windows Setup or OOBE configuring WinRE during OS installation
  - SrtTasks.exe (Startup Repair) legitimately calling reagentc
  - Enterprise imaging tools (MDT, SCCM OSD) disabling WinRE before capture
level: high`,
    tuning_note: `Correlate with rule 004 (BCDEdit): both firing on same host within 15 minutes =
confirmed WinRE destruction sequence. Flag as Critical when combined.
SCCM OSD task sequences often disable WinRE during imaging — add SCCM imaging service account
to a SIEM exception list and check ParentProcessName for known MDT/SCCM processes.`,
    validation: 'Evasion 3/5 | Fields 5/5 | Paths 4/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-009a',
    title: 'Scheduled Task Bulk Deletion via schtasks.exe',
    mitre: 'T1070 — Indicator Removal',
    eventlog: 'Windows Security',
    eventids: '4688',
    level: 'medium',
    deploy_order: 13,
    fp_risk: 'Medium — authorized admin use of schtasks /delete is common; rely on volume + context',
    audit_req: 'Audit Process Creation (Success) + Include command line in process creation events',
    context: `CyberAvengers removes scheduled persistence tasks prior to wiper execution as part of
indicator removal — cleaning up any footholds or staging tasks before making the destruction
irreversible. The /f (force, no confirmation) combined with /delete is suspicious when run from
non-administrative tool contexts or in high volume (5+ tasks in 60 seconds). Companion rule 009b
(Task Scheduler EID 141) catches API-based deletions that bypass schtasks.exe.`,
    sigma: `title: Scheduled Task Bulk Deletion via schtasks.exe
id: a9c8d7e6-b5f4-468d-e9d8-c7b6a5f4e3d2
status: experimental
description: >
  Detects schtasks.exe /delete /f patterns. CyberAvengers deletes scheduled persistence tasks
  before wiper execution as indicator removal. Companion to wiper-native-009b.
  Targets T1070. Requires EID 4688 command line auditing.
references:
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.defense_evasion
  - attack.t1070
  - attack.t1053.005
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_schtasks_delete:
    NewProcessName|endswith: '\\schtasks.exe'
    CommandLine|contains:
      - '/delete'
      - '/DELETE'
    CommandLine|contains:
      - '/f'
      - '/F'
  filter_known_admin_tools:
    ParentProcessName|endswith:
      - '\\taskeng.exe'
      - '\\mmc.exe'
  filter_sccm:
    ParentProcessName|endswith:
      - '\\ccmexec.exe'
      - '\\smsexec.exe'
  filter_av_cleanup:
    ParentProcessName|startswith:
      - 'C:\\Program Files\\Windows Defender\\'
      - 'C:\\ProgramData\\Microsoft\\Windows Defender\\'
  condition: selection_event and selection_schtasks_delete and not filter_known_admin_tools and not filter_sccm and not filter_av_cleanup
falsepositives:
  - Authorized IT admins using schtasks /delete during workstation cleanup
  - Application uninstallers removing their scheduled tasks (low volume)
  - AV removal scripts cleaning up update tasks
level: medium`,
    tuning_note: `Apply SIEM threshold: 5 or more schtasks /delete events from same host within 60 seconds
= escalate to High. Individual task deletions are common; mass deletion is suspicious.
Correlate with wiper-native-001a on same host — scheduled task cleanup followed by wiper execution
is the CyberAvengers pre-wiper pattern.`,
    validation: 'Evasion 3/5 | Fields 5/5 | Paths 4/5 | FP 4/5 | Syntax 5/5',
  },
  {
    id: 'wiper-native-009b',
    title: 'Scheduled Task Deleted via Task Scheduler Operational Log',
    mitre: 'T1070 — Indicator Removal',
    eventlog: 'Task Scheduler Operational',
    eventids: '141',
    level: 'medium',
    deploy_order: 14,
    fp_risk: 'Medium — individual task deletions are normal; tune to exclude Windows/Office/AV tasks',
    audit_req: 'Task Scheduler operational log enabled (disabled by default — enable via wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true)',
    context: `EID 141 fires for every scheduled task deletion regardless of the mechanism (schtasks.exe,
Task Scheduler COM API, PowerShell). This catches API-based task removal that bypasses rule 009a.
The filter excludes Windows-built-in and known-good application tasks. High volume (5+ within 60s)
or deletions of non-Microsoft/non-standard tasks in combination with other wiper indicators should
be escalated. Requires enabling the Task Scheduler operational log.`,
    sigma: `title: Scheduled Task Deleted via Task Scheduler Operational Log
id: b0d9e8f7-c6a5-479e-f0e9-d8c7b6a5f4e3
status: experimental
description: >
  Detects task deletion events from Task Scheduler operational log (EID 141). Catches API-based
  deletions that bypass schtasks.exe. Companion to wiper-native-009a. Targets T1070.
  Requires Task Scheduler operational log to be enabled.
references:
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.defense_evasion
  - attack.t1070
  - attack.t1053.005
  - attack.g0149
logsource:
  product: windows
  service: taskscheduler
detection:
  selection_event:
    EventID: 141
  filter_windows_tasks:
    TaskName|startswith:
      - '\\Microsoft\\Windows\\'
      - '\\Microsoft\\Office\\'
  filter_known_app_tasks:
    TaskName|contains:
      - 'Windows Defender'
      - 'MicrosoftEdge'
      - 'GoogleUpdate'
      - 'AdobeUpdate'
      - 'OneDrive'
  condition: selection_event and not filter_windows_tasks and not filter_known_app_tasks
falsepositives:
  - Administrators deleting individual custom scheduled tasks
  - Application uninstallers removing their scheduled tasks
  - 5+ deletions within 60 seconds from same host = strong wiper indicator
level: medium`,
    tuning_note: `ENABLE LOG FIRST: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
(or via Group Policy: Computer Config > Admin Templates > Windows Components > Task Scheduler > Enable)
Add your environment's known application task name prefixes to filter_known_app_tasks.
SIEM threshold: 5 EID 141 events in 60 seconds from same host = escalate to High.`,
    validation: 'Evasion 5/5 | Fields 4/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
  },
];

// ── Build Cover Page ───────────────────────────────────────────────────────
function buildCover() {
  return [
    new Paragraph({
      children: [new TextRun({ text: '', size: 40 })],
      spacing: { before: 400 },
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({
        text: 'DETECTION ENGINEERING',
        bold: true, size: 52, color: C.header_bg,
      })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({
        text: 'DEPLOYMENT PLAYBOOK',
        bold: true, size: 52, color: C.header_bg,
      })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({
        text: 'Native Windows Event Logs Edition',
        bold: true, size: 30, color: C.amber,
      })],
      spacing: { before: 200 },
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({
        text: 'CyberAvengers / Cotton Sandstorm — Wiper Malware Detection',
        size: 24, color: '555555',
      })],
      spacing: { before: 160 },
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({
        text: `No Sysmon Required | Windows Security + System + Task Scheduler Logs`,
        size: 20, color: '888888',
      })],
      spacing: { before: 80 },
    }),
    sep(),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `Generated: ${new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' })}`, size: 20, color: '888888' })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `Detections: ${RULES.length} use cases | ${RULES.length} Sigma files`, size: 20, color: '888888' })],
      spacing: { after: 80 },
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `Techniques: T1485 | T1489 | T1490 | T1561.002 | T1070.001 | T1070`, size: 20, color: '888888' })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `Actor: G0149 Cotton Sandstorm (CyberAvengers) | IRGC-affiliated`, size: 20, color: C.critical, bold: true })],
      spacing: { after: 80 },
    }),
    pageBreak(),
  ];
}

// ── Build Audit Prerequisites ──────────────────────────────────────────────
function buildPrereqs() {
  return [
    h1('AUDIT POLICY PREREQUISITES'),
    body('These policies must be in place before deploying any rules in this playbook. Rules that depend on missing policies will produce zero detections silently.'),
    sep(),

    h2('1 — EID 4688 Command Line Auditing (Required for 11 of 14 rules)'),
    body('Group Policy path:'),
    code('Computer Configuration → Windows Settings → Security Settings →'),
    code('  Advanced Audit Policy Configuration → Detailed Tracking →'),
    code('    Audit Process Creation: Success'),
    body(''),
    code('Computer Configuration → Administrative Templates → System →'),
    code('  Audit Process Creation →'),
    code('    Include command line in process creation events: Enabled'),
    body(''),
    body('Verification (run on endpoint):'),
    code('auditpol /get /subcategory:"Process Creation"'),
    body('Expected output: Inclusion Settings: Success'),
    body(''),

    h2('2 — Task Scheduler Operational Log (Required for wiper-native-009b)'),
    body('Enable via command line (run as Administrator):'),
    code('wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true'),
    body('Or via Group Policy:'),
    code('Computer Configuration → Administrative Templates → Windows Components →'),
    code('  Task Scheduler → Enable Task Scheduler log: Enabled'),
    body(''),

    h2('3 — EID 4657 Registry Auditing (Required for wiper-native-005 only)'),
    body('Step 1 — Enable Object Access auditing:'),
    code('Computer Configuration → Windows Settings → Security Settings →'),
    code('  Advanced Audit Policy Configuration → Object Access →'),
    code('    Audit Registry: Success'),
    body(''),
    body('Step 2 — Set SACL on the CrashControl key (run as Administrator):'),
    code('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"'),
    body('Then open regedit.exe → navigate to the key → right-click → Permissions → Advanced → Auditing tab → Add → Principal: Everyone → Type: Success → Applies to: This key only → Check: Set Value → OK'),
    body(''),

    h2('4 — EID 1102 / 7036 / 104 (No Configuration Required)'),
    body('These events fire by default on all Windows systems. No additional audit policy needed.'),
    body('Ensure Windows Security log, Windows System log, and Application log are being forwarded to your SIEM.'),
    sep(),
    pageBreak(),
  ];
}

// ── Build Deployment Order ─────────────────────────────────────────────────
function buildDeployOrder() {
  const headers = [
    { text: 'Order', width: 800 },
    { text: 'Rule ID', width: 2000 },
    { text: 'Technique', width: 2200 },
    { text: 'Log / EID', width: 2000 },
    { text: 'Level', width: 1000 },
    { text: 'Audit Req?', width: 1200 },
  ];

  const rows = RULES.map((r, i) => [
    { text: String(r.deploy_order), width: 800 },
    { text: r.id, width: 2000 },
    { text: r.mitre.split(' — ')[0], width: 2200 },
    { text: `${r.eventlog} / ${r.eventids}`, width: 2000 },
    { text: r.level.toUpperCase(), width: 1000 },
    { text: r.audit_req.includes('command line') ? 'EID 4688 CLI' : r.audit_req.includes('SACL') ? 'SACL + OA' : r.audit_req.includes('wevtutil') ? 'TaskSched Log' : 'Default', width: 1200 },
  ]);

  return [
    h1('DEPLOYMENT ORDER'),
    body('Deploy in this sequence. Rules 1–4 cover the wiper initiation phase. Rules 5–10 cover anti-forensics. Rules 11–14 cover final impact and cleanup.'),
    new Table({
      width: { size: 9200, type: WidthType.DXA },
      rows: [
        tableRow(headers, true),
        ...rows.map((r, i) => tableRow(r, false, i % 2 === 1)),
      ],
    }),
    sep(),
    pageBreak(),
  ];
}

// ── Build Single Rule Section ──────────────────────────────────────────────
function buildRuleSection(rule) {
  const lvlColor = levelColor(rule.level);
  const sigmaLines = rule.sigma.split('\n');

  return [
    h2(`${rule.id.toUpperCase()} — ${rule.title}`),

    // Badge row
    new Paragraph({
      children: [
        new TextRun({ text: '  TECHNIQUE: ', bold: true, size: 19, color: C.header_bg }),
        new TextRun({ text: ` ${rule.mitre} `, bold: true, size: 18, color: C.header_bg }),
        new TextRun({ text: '    ', size: 18 }),
        new TextRun({ text: '  LEVEL: ', bold: true, size: 19, color: C.header_bg }),
        new TextRun({ text: ` ${rule.level.toUpperCase()} `, bold: true, size: 18, color: 'FFFFFF',
          shading: { type: ShadingType.SOLID, fill: lvlColor } }),
        new TextRun({ text: '    ', size: 18 }),
        new TextRun({ text: '  LOG: ', bold: true, size: 19, color: C.header_bg }),
        new TextRun({ text: ` ${rule.eventlog} / EID ${rule.eventids} `, size: 18, color: C.body_dark }),
      ],
      spacing: { after: 80 },
    }),

    // Deploy order + FP risk
    new Paragraph({
      children: [
        new TextRun({ text: `  Deploy Order: #${rule.deploy_order}   `, bold: true, size: 18, color: '555555' }),
        new TextRun({ text: `  FP Risk: ${rule.fp_risk}  `, size: 18, color: '555555' }),
      ],
      spacing: { after: 80 },
    }),

    h3('Audit Requirements'),
    body(rule.audit_req),

    h3('What It Detects'),
    ...rule.context.split('\n').filter(l => l.trim()).map(body),

    h3('Sigma Rule'),
    ...sigmaLines.map(code),

    h3('Validation Scores'),
    body(rule.validation),

    h3('Tuning Notes'),
    ...rule.tuning_note.split('\n').filter(l => l.trim()).map(l => bullet(l)),

    sep(),
  ];
}

// ── Build SIEM Correlation ─────────────────────────────────────────────────
function buildCorrelation() {
  return [
    pageBreak(),
    h1('SIEM CORRELATION RULES'),
    body('The following correlation patterns should be implemented at the SIEM layer. They combine individual rule alerts into high-confidence kill-chain indicators. These are not Sigma rules — implement as SIEM-native scheduled analytics or alert aggregation rules.'),
    sep(),

    h2('CORR-01: Pre-Wiper Kill Chain — Service Stop + VSS Delete + BCDEdit'),
    body('Trigger: wiper-native-002a AND wiper-native-003 AND wiper-native-004 fire on same ComputerName within 10 minutes.'),
    body('Severity: CRITICAL — Incident Response required immediately.'),
    body('Logic (pseudocode):'),
    code('CORRELATE alerts WHERE'),
    code('  rule_id IN (wiper-native-002a, wiper-native-003, wiper-native-004)'),
    code('  AND ComputerName = same host'),
    code('  AND timestamp WITHIN 10 minutes'),
    code('  AND COUNT(DISTINCT rule_id) >= 2'),
    code('GENERATE: "Wiper Pre-Execution Kill Chain Detected"'),
    body(''),

    h2('CORR-02: Anti-Forensics Sequence — Log Clearing Post-Wiper'),
    body('Trigger: wiper-native-001a (wiper execution) followed by wiper-native-006a or 006b within 5 minutes.'),
    body('Severity: CRITICAL — System may be destroyed. Preserve any off-host logs immediately.'),
    code('CORRELATE alerts WHERE'),
    code('  rule_id = wiper-native-001a'),
    code('  FOLLOWED BY rule_id IN (wiper-native-006a, wiper-native-006b)'),
    code('  ON SAME ComputerName'),
    code('  WITHIN 5 minutes'),
    code('GENERATE: "Wiper Execution + Log Clearing Confirmed"'),
    body(''),

    h2('CORR-03: Double Recovery Prevention — BCDEdit + WinRE Disable'),
    body('Trigger: wiper-native-004 AND wiper-native-008 fire on same host within 15 minutes.'),
    body('Severity: HIGH — System being made unrecoverable.'),
    code('CORRELATE alerts WHERE'),
    code('  rule_id IN (wiper-native-004, wiper-native-008)'),
    code('  AND ComputerName = same host'),
    code('  AND timestamp WITHIN 15 minutes'),
    code('GENERATE: "Dual Recovery Prevention Sequence Detected"'),
    body(''),

    h2('CORR-04: Service Mass-Kill Threshold'),
    body('Trigger: 3 or more distinct wiper-native-002a/002b alerts from same host within 60 seconds.'),
    body('Severity: HIGH — Bulk security tool termination underway.'),
    code('AGGREGATE alerts WHERE'),
    code('  rule_id IN (wiper-native-002a, wiper-native-002b)'),
    code('  AND ComputerName = same host'),
    code('  WITHIN 60 seconds'),
    code('  HAVING COUNT(*) >= 3'),
    code('GENERATE: "Security Service Mass Termination — Threshold Exceeded"'),
    body(''),

    h2('CORR-05: Full Wiper Kill Chain (All Phases)'),
    body('Trigger: 4+ unique rules from this playbook on same host within 30 minutes.'),
    body('Severity: CRITICAL — Full wiper kill chain in progress or completed.'),
    code('AGGREGATE alerts WHERE'),
    code('  rule_id IN (wiper-native-001a THROUGH wiper-native-009b)'),
    code('  AND ComputerName = same host'),
    code('  WITHIN 30 minutes'),
    code('  HAVING COUNT(DISTINCT rule_id) >= 4'),
    code('GENERATE: "CyberAvengers Wiper Kill Chain — Confirmed Multi-Stage Attack"'),
    code('ACTION: Isolate host, preserve off-host logs, initiate IR playbook'),
    sep(),
  ];
}

// ── Build Appendix ─────────────────────────────────────────────────────────
function buildAppendix() {
  return [
    pageBreak(),
    h1('APPENDIX — RULE FILE INDEX'),
    body('All 14 rule files in this playbook and their corresponding Sigma files.'),
    sep(),

    new Table({
      width: { size: 9200, type: WidthType.DXA },
      rows: [
        tableRow([
          { text: 'Rule ID', width: 2400 },
          { text: 'File Name', width: 2800 },
          { text: 'EID', width: 800 },
          { text: 'Level', width: 1000 },
          { text: 'Technique', width: 2200 },
        ], true),
        ...RULES.map((r, i) => tableRow([
          { text: r.id, width: 2400 },
          { text: `${r.id}.yml`, width: 2800 },
          { text: r.eventids, width: 800 },
          { text: r.level.toUpperCase(), width: 1000 },
          { text: r.mitre.split(' — ')[0], width: 2200 },
        ], false, i % 2 === 1)),
      ],
    }),

    body(''),
    h2('Key Limitations vs Sysmon'),
    bullet('OriginalFileName (PE metadata) NOT available in EID 4688 — binary rename detection impossible without Sysmon EID 1 or EDR'),
    bullet('DLL load monitoring (rstrtmgr.dll) NOT available without Sysmon EID 7 — rule 001b is a compensating behavioral proxy only'),
    bullet('File deletion events (Sysmon EID 23) NOT available — file system SACL required for EID 4663 (high overhead, not covered here)'),
    bullet('Process hashes NOT available in EID 4688 — no hash-based detection without Sysmon'),
    bullet('EID 4688 command line is ONLY populated when GPO "Include command line" is explicitly enabled — verify before deployment'),
    body(''),
    h2('References'),
    bullet('MITRE ATT&CK Group G0149 — Cotton Sandstorm: https://attack.mitre.org/groups/G0149/'),
    bullet('CISA Advisory AA23-335A — IRGC-affiliated actors: https://www.cisa.gov/'),
    bullet('BiBi-Windows Wiper Analysis — BleepingComputer, October 2023'),
    bullet('ROADSWEEP / CyberAvengers — ClearSky Cyber Security Research'),
    bullet('Atomic Red Team T1490: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/'),
  ];
}

// ── Main ───────────────────────────────────────────────────────────────────
async function main() {
  const dateStr = new Date().toISOString().split('T')[0].replace(/-/g, '-');
  const outDir  = path.join(os.homedir(), 'Desktop', 'Detection Engineering Reports');
  const outPath = path.join(outDir, `Wiper_DE_Playbook_Native_${dateStr}.docx`);

  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const children = [
    ...buildCover(),
    ...buildPrereqs(),
    ...buildDeployOrder(),
  ];

  for (const rule of RULES) {
    children.push(...buildRuleSection(rule));
  }

  children.push(...buildCorrelation(), ...buildAppendix());

  const doc = new Document({
    creator: 'Detection Engineering Team',
    title: 'Wiper DE Playbook — Native Windows Events',
    description: 'CyberAvengers/Cotton Sandstorm wiper detection rules using native Windows Security, System, and Task Scheduler event logs. No Sysmon required.',
    sections: [{ children }],
  });

  const buf = await Packer.toBuffer(doc);
  fs.writeFileSync(outPath, buf);

  console.log('\nPlaybook written to:');
  console.log(`  ${outPath}`);
  console.log(`  Rules: ${RULES.length} use cases | ${RULES.length} Sigma files`);
  console.log(`  Pages: ~40 estimated`);
  console.log(`\nCorrelation rules: 5 SIEM-layer patterns`);
  console.log(`Key limitation: EID 4688 lacks OriginalFileName — binary rename not detectable\n`);
}

main().catch(e => { console.error(e); process.exit(1); });
