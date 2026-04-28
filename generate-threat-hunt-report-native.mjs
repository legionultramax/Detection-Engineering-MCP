// Threat Hunt Report Generator — CyberAvengers / Cotton Sandstorm (Native Windows Events)
// Run: node generate-threat-hunt-report-native.mjs
// Output: Desktop\Detection Engineering Reports\ThreatHunt_CyberAvengers_Native_<date>.docx

import {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType, PageBreak,
} from 'docx';
import fs from 'fs';
import path from 'path';
import os from 'os';

// ── Colour Palette ─────────────────────────────────────────────────────────
const C = {
  navy:        '1B2631',   // main heading colour
  white:       'FFFFFF',
  critical_bg: 'C0392B',   // red
  high_bg:     'E67E22',   // orange
  medium_bg:   'F39C12',   // amber
  low_bg:      '27AE60',   // green
  covered_bg:  '1E8449',   // dark green
  partial_bg:  'D4AC0D',   // gold
  gap_bg:      'C0392B',   // red
  code_bg:     'F4F6F7',   // very light grey  ← code blocks (was black in md viewer)
  code_text:   '1C2833',   // near-black text on code blocks
  alt_row:     'EAF2FF',   // light blue alt row
  header_row:  '1B2631',   // table header bg
  border_col:  'AEB6BF',   // table border
  body:        '2C3E50',   // body text
  muted:       '717D7E',   // secondary text
  accent:      '2980B9',   // blue accent
  warn_bg:     'FEF9E7',   // warning box bg
};

const levelColor = l =>
  l === 'critical' ? C.critical_bg :
  l === 'high'     ? C.high_bg     :
  l === 'medium'   ? C.medium_bg   : C.low_bg;

const coverageColor = s =>
  s === 'COVERED'  ? C.covered_bg  :
  s === 'PARTIAL'  ? C.partial_bg  : C.gap_bg;

// ── Core Helpers ───────────────────────────────────────────────────────────
const cellBorders = () => ({
  top:    { style: BorderStyle.SINGLE, size: 4, color: C.border_col },
  bottom: { style: BorderStyle.SINGLE, size: 4, color: C.border_col },
  left:   { style: BorderStyle.SINGLE, size: 4, color: C.border_col },
  right:  { style: BorderStyle.SINGLE, size: 4, color: C.border_col },
});

// Headings
const h1 = txt => new Paragraph({
  heading: HeadingLevel.HEADING_1,
  spacing: { before: 480, after: 160 },
  children: [new TextRun({ text: txt, bold: true, color: C.navy, size: 34 })],
});

const h2 = txt => new Paragraph({
  heading: HeadingLevel.HEADING_2,
  spacing: { before: 360, after: 120 },
  children: [new TextRun({ text: txt, bold: true, color: C.navy, size: 28 })],
});

const h3 = txt => new Paragraph({
  heading: HeadingLevel.HEADING_3,
  spacing: { before: 240, after: 80 },
  children: [new TextRun({ text: txt, bold: true, color: C.body, size: 22 })],
});

// Body text
const body = txt => new Paragraph({
  spacing: { after: 100 },
  children: [new TextRun({ text: txt, size: 21, color: C.body })],
});

const bodyBold = txt => new Paragraph({
  spacing: { after: 80 },
  children: [new TextRun({ text: txt, bold: true, size: 21, color: C.body })],
});

const bullet = (txt, level = 0) => new Paragraph({
  bullet: { level },
  spacing: { after: 60 },
  children: [new TextRun({ text: txt, size: 20, color: C.body })],
});

// Code block — light grey background, dark mono text, NO black bg
const codeLine = txt => new Paragraph({
  spacing: { before: 0, after: 0 },
  indent: { left: 240 },
  shading: { type: ShadingType.SOLID, color: C.code_bg, fill: C.code_bg },
  children: [new TextRun({
    text: txt === '' ? ' ' : txt,   // blank lines need a space to hold height
    font: 'Courier New',
    size: 17,
    color: C.code_text,
  })],
});

// Wrap a multi-line string as code block with top/bottom padding lines
const codeBlock = yaml => {
  const lines = yaml.split('\n');
  return [
    codeLine(''),
    ...lines.map(codeLine),
    codeLine(''),
  ];
};

// Horizontal rule
const hr = () => new Paragraph({
  spacing: { before: 160, after: 160 },
  children: [new TextRun({ text: '─'.repeat(100), color: C.border_col, size: 14 })],
});

const pageBreak = () => new Paragraph({ children: [new PageBreak()] });

// Empty spacer
const spacer = () => new Paragraph({ children: [new TextRun({ text: '' })], spacing: { after: 80 } });

// Coloured badge inline paragraph
const badge = (label, value, bgColor) => new Paragraph({
  spacing: { after: 80 },
  children: [
    new TextRun({ text: `${label}: `, bold: true, size: 19, color: C.body }),
    new TextRun({
      text: ` ${value} `,
      bold: true, size: 18, color: C.white,
      shading: { type: ShadingType.SOLID, color: bgColor, fill: bgColor },
    }),
    new TextRun({ text: '   ', size: 18 }),
  ],
});

// Note/callout box (light yellow bg)
const noteBox = lines => lines.map(txt => new Paragraph({
  spacing: { after: 60 },
  indent: { left: 300, right: 300 },
  shading: { type: ShadingType.SOLID, color: C.warn_bg, fill: C.warn_bg },
  children: [new TextRun({ text: txt, size: 19, color: C.body, italics: true })],
}));

// ── Table Builder ──────────────────────────────────────────────────────────
function buildTable(headers, rows) {
  const totalWidth = headers.reduce((s, h) => s + h.width, 0);

  const headerRow = new TableRow({
    tableHeader: true,
    children: headers.map(h => new TableCell({
      width: { size: h.width, type: WidthType.DXA },
      shading: { type: ShadingType.SOLID, color: C.header_row, fill: C.header_row },
      borders: cellBorders(),
      children: [new Paragraph({
        spacing: { before: 80, after: 80 },
        indent: { left: 100 },
        children: [new TextRun({ text: h.text, bold: true, color: C.white, size: 18 })],
      })],
    })),
  });

  const dataRows = rows.map((row, ri) => new TableRow({
    children: row.map((cell, ci) => {
      const bg = cell.bg || (ri % 2 === 1 ? C.alt_row : C.white);
      return new TableCell({
        width: { size: headers[ci].width, type: WidthType.DXA },
        shading: { type: ShadingType.SOLID, color: bg, fill: bg },
        borders: cellBorders(),
        children: [new Paragraph({
          spacing: { before: 60, after: 60 },
          indent: { left: 100 },
          children: [new TextRun({
            text: cell.text || cell,
            bold: cell.bold || false,
            color: cell.color || C.body,
            size: 17,
          })],
        })],
      });
    }),
  }));

  return new Table({
    width: { size: totalWidth, type: WidthType.DXA },
    rows: [headerRow, ...dataRows],
  });
}

// ── SIGMA RULE DATA ────────────────────────────────────────────────────────
// Full Sigma YAML for all 14 rules + 2 gap rules
const SIGMA_RULES = {
  '001a': `title: CyberAvengers Wiper Execution via Destructive Process Arguments
id: a3f2c8d1-9e4b-4f72-b6a5-8e7f6d5c4b3a
status: experimental
description: >
  Detects BiBi-Windows and ROADSWEEP wiper execution patterns (--force / -d flags)
  from non-standard staging directories. Targets T1485 Data Destruction.
  Requires EID 4688 with command line auditing.
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
      - '\\robocopy.exe'
      - '\\7z.exe'
      - '\\powershell.exe'
      - '\\pwsh.exe'
  condition: >
    selection_event and selection_wiper_args
    and selection_wiper_paths
    and not filter_legit_force
falsepositives:
  - Developer tools using --force from user temp directories
  - Custom cleanup scripts run via SCCM (review ParentProcessName)
level: high`,

  '001b': `title: Wiper rstrtmgr.dll Abuse — Compensating Detection via rrm.exe
id: b8d7e6f5-c4a3-4b72-9e8d-7c6b5a493812
status: experimental
description: >
  Compensating detection for Sysmon EID 7 (image_load) gap. BiBi wiper loads
  rstrtmgr.dll to unlock file handles. Detects rrm.exe helper spawned from
  non-standard parent directories. Targets T1485. PARTIAL control only.
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
  selection_suspicious_parent:
    ParentProcessName|contains:
      - '\\Temp\\'
      - '\\AppData\\'
      - '\\Users\\Public\\'
      - '\\ProgramData\\'
  filter_msi:
    ParentProcessName|endswith:
      - '\\msiexec.exe'
      - '\\MsiExec.exe'
  filter_windows_paths:
    NewProcessName|startswith:
      - 'C:\\Windows\\System32\\'
      - 'C:\\Windows\\SysWOW64\\'
    ParentProcessName|startswith:
      - 'C:\\Windows\\System32\\'
      - 'C:\\Windows\\SysWOW64\\'
  condition: >
    selection_event and selection_rrm
    and selection_suspicious_parent
    and not filter_msi
    and not filter_windows_paths
falsepositives:
  - Windows Installer (msiexec.exe) calling rrm.exe during software installation
  - Windows servicing stack calling rrm.exe during OS updates
level: high`,

  '002a': `title: Security Tool Service Termination via sc.exe or net.exe
id: c9e8f7a6-d5b4-4c83-af9e-8d7c6b5a4932
status: experimental
description: >
  Detects sc.exe or net.exe stop commands targeting AV, EDR, and backup agent
  service names. CyberAvengers kills security services before deploying BiBi wiper.
  Targets T1489 Service Stop. Requires EID 4688 with command line auditing.
references:
  - https://attack.mitre.org/techniques/T1489/
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
  selection_stop_binary:
    NewProcessName|endswith:
      - '\\sc.exe'
      - '\\net.exe'
      - '\\net1.exe'
    CommandLine|contains: ' stop '
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
  condition: >
    selection_event and selection_stop_binary
    and selection_target_services
    and not filter_legit_admin
    and not filter_sccm
falsepositives:
  - IT administrators stopping services for planned maintenance
  - SCCM software deployments stopping conflicting services
level: high`,

  '002b': `title: Security Tool Service Transitioned to Stopped State
id: d0f9a8b7-e6c5-4d94-b0af-9e8d7c6b5a43
status: experimental
description: >
  Detects EID 7036 service state change events for known security tool services
  transitioning to stopped. Catches API-based termination that bypasses sc.exe.
  Targets T1489. No additional audit policy required.
references:
  - https://attack.mitre.org/techniques/T1489/
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
  selection_stopped:
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
  filter_maintenance:
    param1|contains:
      - 'Windows Update'
      - 'Windows Installer'
  condition: >
    selection_event and selection_stopped
    and selection_security_services
    and not filter_maintenance
falsepositives:
  - Planned patching windows — apply SIEM time-window suppression
  - AV self-update cycles that temporarily stop the service
  - Veeam briefly pausing VSS during backup jobs
level: medium`,

  '003': `title: Volume Shadow Copy Deletion via vssadmin, wmic, or PowerShell
id: e1a0b9c8-f7d6-4e05-c1b0-af9e8d7c6b5a
status: experimental
description: >
  Detects VSS snapshot deletion via vssadmin, wmic, PowerShell, or diskshadow.
  CyberAvengers deletes all snapshots before wiper to eliminate recovery paths.
  Targets T1490 Inhibit System Recovery. Requires EID 4688 with command line auditing.
references:
  - https://attack.mitre.org/techniques/T1490/
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
      - 'Win32_ShadowCopy'
  selection_powershell:
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
  condition: >
    selection_event
    and (selection_vssadmin or selection_wmic
         or selection_powershell or selection_diskshadow)
    and not filter_backup_agents
    and not filter_sccm
falsepositives:
  - Backup agents querying shadow copies (delete keyword ensures only deletions fire)
  - Administrator deleting old snapshots during disk maintenance
level: high`,

  '004': `title: BCDEdit Boot Recovery and Repair Disabled
id: f2b1c0d9-a8e7-4f16-d2c1-b0af9e8d7c6b
status: experimental
description: >
  Detects bcdedit.exe disabling automatic recovery, boot status policy, and WinRE.
  CyberAvengers sets recoveryenabled=no and bootstatuspolicy=ignoreallfailures
  to ensure systems cannot recover after wiper execution. Targets T1490.
references:
  - https://attack.mitre.org/techniques/T1490/
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
  condition: >
    selection_event and selection_binary
    and selection_recovery_args
    and not filter_windows_repair
    and not filter_os_setup
falsepositives:
  - Windows System Recovery Tool (srtasks.exe) during repair
  - OS upgrade reconfiguring boot configuration
  - Bare metal restore tools (Acronis, Veeam BMR) after restore
level: high`,

  '005': `title: CrashControl Registry Key Modified to Disable Automatic Recovery
id: a3c2d1e0-b9f8-4027-e3d2-c1b0af9e8d7c
status: experimental
description: >
  Detects modifications to HKLM CrashControl registry key values. CyberAvengers
  sets AutoReboot=0 and CrashDumpEnabled=0 to prevent recovery. Targets T1490.
  Requires Object Access auditing AND SACL set on the CrashControl key.
references:
  - https://attack.mitre.org/techniques/T1490/
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
  filter_system_procs:
    ProcessName|endswith:
      - '\\services.exe'
      - '\\lsass.exe'
      - '\\svchost.exe'
      - '\\TrustedInstaller.exe'
  filter_windows_update:
    ProcessName|startswith:
      - 'C:\\Windows\\WinSxS\\'
      - 'C:\\Windows\\servicing\\'
  condition: >
    selection_event and selection_crashcontrol
    and selection_recovery_values
    and not filter_system_procs
    and not filter_windows_update
falsepositives:
  - Windows Update modifying CrashControl values during OS patching
  - Enterprise monitoring agents writing diagnostic registry values
level: high`,

  '006a': `title: Windows Security Event Log Cleared
id: b4d3e2f1-c0a9-4138-f4e3-d2c1b0af9e8d
status: stable
description: >
  Detects clearing of the Windows Security event log (EID 1102). Fires regardless
  of clearing method — wevtutil, PowerShell, GUI, or API. Cannot be suppressed
  without disabling the Security log entirely. Targets T1070.001.
references:
  - https://attack.mitre.org/techniques/T1070/001/
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
  filter_authorized_admins:
    # Populate with your authorized admin accounts before deploying.
    # Example: SubjectUserName|endswith: '_svc'
    SubjectUserName: 'PLACEHOLDER_REPLACE_BEFORE_DEPLOY'
  condition: selection_event and not filter_authorized_admins
falsepositives:
  - Authorized SOC/IR administrators clearing logs during incident response
  - Quarterly log purge scripts run by documented IT operations accounts
level: high`,

  '006b': `title: Windows System Event Log Cleared
id: c5e4f3a2-d1b0-4249-a5f4-e3d2c1b0af9e
status: stable
description: >
  Detects clearing of the Windows System event log (EID 104). Companion to
  006a (Security log). CyberAvengers clears System log to remove EID 7036
  service-stop evidence. Targets T1070.001.
references:
  - https://attack.mitre.org/techniques/T1070/001/
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
  - Authorized IT administrators clearing system log during maintenance (very rare)
level: high`,

  '006c': `title: Event Log Clearing via wevtutil, PowerShell, or WMI
id: d6f5a4b3-e2c1-435a-b6a5-f4e3d2c1b0af
status: experimental
description: >
  Detects CLI-initiated event log clearing via wevtutil, Clear-EventLog, or WMI.
  Provides process and user attribution that EID 1102/104 alone cannot supply.
  Targets T1070.001. Requires EID 4688 with command line auditing.
references:
  - https://attack.mitre.org/techniques/T1070/001/
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
  selection_powershell:
    NewProcessName|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'Clear-EventLog'
      - 'clear-eventlog'
      - 'Limit-EventLog'
  selection_wmic:
    NewProcessName|endswith: '\\wmic.exe'
    CommandLine|contains:
      - 'nteventlog'
      - 'ClearEventLog'
  filter_admin_gui:
    ParentProcessName|endswith:
      - '\\mmc.exe'
      - '\\eventvwr.exe'
  filter_sccm:
    ParentProcessName|endswith:
      - '\\ccmexec.exe'
      - '\\smsexec.exe'
  condition: >
    selection_event
    and (selection_wevtutil or selection_powershell or selection_wmic)
    and not filter_admin_gui
    and not filter_sccm
falsepositives:
  - Event Viewer GUI clearing logs (eventvwr via mmc parent — suppressed)
  - SCCM log management tasks (suppressed)
level: high`,

  '007': `title: Raw Disk Access or MBR Overwrite via diskpart, dd, or Direct Handle
id: e7a6b5c4-f3d2-446b-c7b6-a5f4e3d2c1b0
status: experimental
description: >
  Detects MBR/disk overwrite via diskpart clean, dd-style tools, or any process
  referencing \\.\PhysicalDrive in its command line. CyberAvengers overwrites the
  MBR to render systems unbootable after file destruction. Targets T1561.002.
references:
  - https://attack.mitre.org/techniques/T1561/002/
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
  selection_diskpart:
    NewProcessName|endswith: '\\diskpart.exe'
    CommandLine|contains:
      - ' clean'
      - ' CLEAN'
  selection_physicaldrive:
    CommandLine|contains:
      - '\\\\.\\PhysicalDrive'
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
  filter_bmr:
    ParentProcessName|endswith:
      - '\\veeam.backup.service.exe'
      - '\\BackupExecJobEngine.exe'
  condition: >
    selection_event
    and (selection_diskpart or selection_physicaldrive or selection_dd_tools)
    and not filter_os_setup
    and not filter_bmr
falsepositives:
  - Windows OS setup or WinPE using diskpart during provisioning
  - Bare metal restore operations (Veeam, BackupExec)
  - Security/forensics tools accessing raw disk handles
level: critical`,

  '008': `title: Windows Recovery Environment Disabled or Destroyed via reagentc.exe
id: f8b7c6d5-a4e3-457c-d8c7-b6a5f4e3d2c1
status: experimental
description: >
  Detects reagentc.exe /disable or bcdboot with destructive firmware flags to
  destroy the Windows Recovery Environment. CyberAvengers disables WinRE as a
  second recovery-prevention layer alongside BCDEdit. Targets T1490.
references:
  - https://attack.mitre.org/techniques/T1490/
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
  selection_reagentc:
    NewProcessName|endswith: '\\reagentc.exe'
    CommandLine|contains:
      - '/disable'
      - '/DISABLE'
      - '-disable'
      - '/setreimage'
      - '/boottore'
  selection_bcdboot_destructive:
    NewProcessName|endswith: '\\bcdboot.exe'
    CommandLine|contains:
      - '/f ALL'
      - '/f BIOS'
      - '/f UEFI'
  filter_windows_setup:
    ParentProcessName|startswith:
      - 'C:\\Windows\\System32\\srtasks.exe'
      - 'C:\\Windows\\System32\\wbengine.exe'
  filter_oobe:
    ParentProcessName|endswith:
      - '\\oobe\\setup.exe'
      - '\\oobe\\oobeplugins.exe'
  condition: >
    selection_event
    and (selection_reagentc or selection_bcdboot_destructive)
    and not filter_windows_setup
    and not filter_oobe
falsepositives:
  - Windows Setup or OOBE configuring WinRE during OS installation
  - SrtTasks.exe during Startup Repair calling reagentc
  - MDT/SCCM OSD task sequences disabling WinRE before capture
level: high`,

  '009a': `title: Scheduled Task Bulk Deletion via schtasks.exe
id: a9c8d7e6-b5f4-468d-e9d8-c7b6a5f4e3d2
status: experimental
description: >
  Detects schtasks.exe /delete /f patterns. CyberAvengers removes scheduled
  persistence tasks before wiper execution as pre-impact indicator removal.
  Targets T1070 Indicator Removal. Requires EID 4688 with command line auditing.
references:
  - https://attack.mitre.org/techniques/T1070/
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
  selection_schtasks:
    NewProcessName|endswith: '\\schtasks.exe'
    CommandLine|contains:
      - '/delete'
      - '/DELETE'
    CommandLine|contains:
      - '/f'
      - '/F'
  filter_admin_tools:
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
  condition: >
    selection_event and selection_schtasks
    and not filter_admin_tools
    and not filter_sccm
    and not filter_av_cleanup
falsepositives:
  - Authorized IT admins deleting tasks during workstation cleanup
  - Application uninstallers removing their scheduled tasks (low volume)
level: medium`,

  '009b': `title: Scheduled Task Deleted via Task Scheduler Operational Log
id: b0d9e8f7-c6a5-479e-f0e9-d8c7b6a5f4e3
status: experimental
description: >
  Detects task deletion events (EID 141) in Task Scheduler operational log.
  Catches API-based deletions bypassing schtasks.exe. Companion to 009a.
  Targets T1070. Requires Task Scheduler operational log to be enabled.
references:
  - https://attack.mitre.org/techniques/T1070/
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
  filter_known_apps:
    TaskName|contains:
      - 'Windows Defender'
      - 'MicrosoftEdge'
      - 'GoogleUpdate'
      - 'AdobeUpdate'
      - 'OneDrive'
  condition: selection_event and not filter_windows_tasks and not filter_known_apps
falsepositives:
  - Administrators deleting individual custom tasks (low volume, expected)
  - Application uninstallers removing their scheduled tasks
level: medium`,

  // Gap rules
  'smb': `title: SMB Lateral Movement — NTLM Type 3 Logon
id: e4f9c2b1-8a7d-4e23-b5c6-9f1a2e3d4b5c
status: experimental
description: >
  Detects NTLM-based SMB lateral movement via EID 4624 Type 3 logons. CyberAvengers
  propagates wiper across SMB shares post-initial access. Targets T1021.002.
  Complements the wiper-phase rules as a lateral movement context signal.
references:
  - https://attack.mitre.org/techniques/T1021/002/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.g0149
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4624
  selection_smb_ntlm:
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
  selection_suspicious:
    SubjectUserName|contains:
      - 'ANONYMOUS'
      - 'ANONYMOUS LOGON'
  filter_domain_controllers:
    SubjectDomainName: 'NT AUTHORITY'
  condition: >
    selection_event and selection_smb_ntlm
    and selection_suspicious
    and not filter_domain_controllers
falsepositives:
  - Legitimate NTLM authentication in workgroup environments (no Kerberos)
  - Network scanners using null sessions for host discovery
level: medium`,

  'ps4104': `title: PowerShell ScriptBlock — Wiper Staging and Pre-Destruction Patterns
id: f5a0d3c2-9b8e-4f34-c6d7-a0b1c2d3e4f5
status: experimental
description: >
  Detects PowerShell ScriptBlock log entries containing wiper staging patterns:
  VSS deletion, service termination, BCDEdit, or event log clearing via PS cmdlets.
  CyberAvengers uses PowerShell for pre-wiper preparation. Targets T1059.001.
  Requires PowerShell ScriptBlock logging (EID 4104) to be enabled.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.execution
  - attack.t1059.001
  - attack.g0149
logsource:
  product: windows
  service: powershell
detection:
  selection_event:
    EventID: 4104
  selection_wiper_patterns:
    ScriptBlockText|contains:
      - 'Win32_ShadowCopy'
      - 'Remove-WmiObject'
      - 'Stop-Service'
      - 'vssadmin delete'
      - 'bcdedit'
      - 'wevtutil cl'
      - 'Clear-EventLog'
      - 'schtasks /delete'
      - 'reagentc /disable'
  filter_monitoring_agents:
    Path|startswith:
      - 'C:\\Program Files\\Microsoft Monitoring Agent\\'
      - 'C:\\Program Files (x86)\\Microsoft Monitoring Agent\\'
  condition: selection_event and selection_wiper_patterns and not filter_monitoring_agents
falsepositives:
  - Legitimate backup scripts querying Win32_ShadowCopy
  - Authorized service management scripts using Stop-Service
level: high`,
};

// Sigma correlation rule text
const CORRELATION_SIGMA = `title: CyberAvengers Wiper Full Kill Chain Correlation
id: 99f0a1b2-c3d4-4e5f-a6b7-c8d9e0f1a2b3
type: correlation
status: experimental
description: >
  Correlates multiple wiper kill-chain alerts across the same host within 30 minutes.
  Fires when 4 or more distinct wiper-phase rules trigger on the same ComputerName.
  High-confidence multi-phase indicator for CyberAvengers BiBi-Windows wiper deployment.
  Covers T1485 + T1489 + T1490 + T1561.002 + T1070.001.
references:
  - https://attack.mitre.org/groups/G0149/
author: Detection Engineering Team
date: 2026-03-15
tags:
  - attack.impact
  - attack.t1485
  - attack.t1489
  - attack.t1490
  - attack.t1561.002
  - attack.t1070.001
  - attack.g0149
correlation:
  type: event_count
  rules:
    - wiper-native-001a
    - wiper-native-001b
    - wiper-native-002a
    - wiper-native-002b
    - wiper-native-003
    - wiper-native-004
    - wiper-native-005
    - wiper-native-006a
    - wiper-native-006b
    - wiper-native-006c
    - wiper-native-007
    - wiper-native-008
    - wiper-native-009a
    - wiper-native-009b
  group-by:
    - ComputerName
  timespan: 30m
  condition: gte 4
falsepositives:
  - Authorized destructive DR testing — implement maintenance window suppression
level: critical`;

// Phase timeline text
const PHASE_TIMELINE = `T+00m  [Phase 1 — Pre-Impact: Cleanup & Service Stop]
         wiper-native-009a/009b  → Scheduled task deletion (persistence removal)
         wiper-native-002a       → Security services stopped via sc.exe / net.exe
         wiper-native-002b       → Service state change EID 7036 confirms stops

T+02m  [Phase 2 — Pre-Impact: Recovery Prevention]
         wiper-native-003        → VSS deletion (vssadmin / wmic / PowerShell)
         wiper-native-004        → BCDEdit: recoveryenabled=no, bootstatuspolicy
         wiper-native-005        → CrashControl registry modified (EID 4657)
         wiper-native-008        → reagentc /disable removes WinRE entirely

T+05m  [Phase 3 — Impact: Wiper Execution]
         wiper-native-001a       → Wiper process executes (--force / -d flags)
         wiper-native-001b       → rrm.exe spawned (rstrtmgr handle-unlock proxy)
         wiper-native-007        → diskpart clean / PhysicalDrive overwrite (MBR)

T+10m  [Phase 4 — Anti-Forensics: Evidence Destruction]
         wiper-native-006c       → wevtutil cl / Clear-EventLog executed
         wiper-native-006a       → EID 1102: Security log cleared (self-logging)
         wiper-native-006b       → EID 104: System log cleared (self-logging)

T+30m  [Post-Wipe System State]
         System is non-bootable. MBR overwritten. All VSS snapshots deleted.
         Recovery environment disabled. Event logs cleared.
         Off-host SIEM / WEF collector retains pre-clear log data.`;

// ── DOCUMENT SECTION BUILDERS ──────────────────────────────────────────────

function buildCover() {
  return [
    spacer(), spacer(), spacer(),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: 'THREAT HUNT REPORT', bold: true, color: C.navy, size: 56 })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 120, after: 160 },
      children: [new TextRun({ text: 'CyberAvengers / Cotton Sandstorm — Wiper Malware Activity', bold: true, color: C.accent, size: 30 })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 80 },
      children: [new TextRun({ text: 'Native Windows Event Logs Edition  |  No Sysmon Required', color: C.muted, size: 22 })],
    }),
    hr(),
    buildTable(
      [{ text: 'Field', width: 2400 }, { text: 'Value', width: 6400 }],
      [
        [{ text: 'Date', bold: true }, { text: '2026-03-15' }],
        [{ text: 'Mode', bold: true }, { text: 'Standard' }],
        [{ text: 'Priority', bold: true }, { text: 'CRITICAL', color: C.critical_bg, bold: true }],
        [{ text: 'Actor', bold: true }, { text: 'CyberAvengers / Cotton Sandstorm (G0149) — IRGC-affiliated' }],
        [{ text: 'Malware', bold: true }, { text: 'BiBi-Windows Wiper, ROADSWEEP, CHIMNEYSWEEP' }],
        [{ text: 'Log Sources', bold: true }, { text: 'Windows Security, System, Task Scheduler Operational (no Sysmon)' }],
        [{ text: 'Rules Delivered', bold: true }, { text: '14 Sigma rules + 2 gap rules + 1 kill-chain correlation' }],
        [{ text: 'Kill-Chain Score', bold: true }, { text: '4.1 / 5.0' }],
        [{ text: 'Techniques', bold: true }, { text: 'T1485 | T1489 | T1490 | T1561.002 | T1070.001 | T1070' }],
      ]
    ),
    pageBreak(),
  ];
}

function buildExecutiveSummary() {
  return [
    h1('1. Executive Summary'),
    body('CyberAvengers (Cotton Sandstorm, IRGC-affiliated) is an Iranian state-sponsored threat actor conducting destructive wiper campaigns against Israeli organisations, Albanian government infrastructure, and regional critical infrastructure targets. Their primary toolset — BiBi-Windows wiper and ROADSWEEP — follows a predictable five-phase kill chain: service termination, recovery prevention, data destruction, MBR overwrite, and anti-forensics log clearing.'),
    body('This report delivers a complete detection package for that kill chain using exclusively native Windows event logs (Security EID 4688, System EID 7036/104, Task Scheduler EID 141, Security EID 1102/4657) — applicable to any environment without Sysmon deployed. All 14 Sigma rules are production-ready with specific FP filters, and a kill-chain correlation rule ties them into a single high-confidence alert.'),
    body('The actor is actively operational with campaigns documented through late 2023. The TTPs are stable, well-documented, and map to high-confidence detection opportunities at every phase except DLL load monitoring (rstrtmgr.dll), which requires Sysmon EID 7 or host-based EDR.'),
    hr(),
    pageBreak(),
  ];
}

function buildKillChainCoverage() {
  return [
    h1('2. MITRE Kill-Chain Coverage'),
    buildTable(
      [
        { text: 'Phase', width: 1600 },
        { text: 'Technique', width: 1800 },
        { text: 'T-ID', width: 1000 },
        { text: 'Data Source', width: 2200 },
        { text: 'Status', width: 1200 },
      ],
      [
        [
          { text: 'Pre-Impact' },
          { text: 'Service Stop' },
          { text: 'T1489' },
          { text: 'Security EID 4688 + System EID 7036' },
          { text: 'COVERED', color: C.white, bg: C.covered_bg, bold: true },
        ],
        [
          { text: 'Pre-Impact' },
          { text: 'Inhibit System Recovery' },
          { text: 'T1490' },
          { text: 'Security EID 4688 + EID 4657' },
          { text: 'COVERED', color: C.white, bg: C.covered_bg, bold: true },
        ],
        [
          { text: 'Impact' },
          { text: 'Data Destruction' },
          { text: 'T1485' },
          { text: 'Security EID 4688' },
          { text: 'COVERED', color: C.white, bg: C.covered_bg, bold: true },
        ],
        [
          { text: 'Impact' },
          { text: 'Disk Structure Wipe' },
          { text: 'T1561.002' },
          { text: 'Security EID 4688' },
          { text: 'COVERED', color: C.white, bg: C.covered_bg, bold: true },
        ],
        [
          { text: 'Anti-Forensics' },
          { text: 'Clear Windows Event Logs' },
          { text: 'T1070.001' },
          { text: 'Security EID 1102 + System EID 104' },
          { text: 'COVERED', color: C.white, bg: C.covered_bg, bold: true },
        ],
        [
          { text: 'Anti-Forensics' },
          { text: 'Indicator Removal' },
          { text: 'T1070' },
          { text: 'Security EID 4688 + TaskSched EID 141' },
          { text: 'COVERED', color: C.white, bg: C.covered_bg, bold: true },
        ],
        [
          { text: 'Impact' },
          { text: 'DLL Load (rstrtmgr.dll)' },
          { text: 'T1574' },
          { text: 'NO NATIVE EID — Sysmon EID 7 required' },
          { text: 'GAP', color: C.white, bg: C.gap_bg, bold: true },
        ],
        [
          { text: 'Lateral Movement' },
          { text: 'Remote Services (SMB)' },
          { text: 'T1021.002' },
          { text: 'Security EID 4624/5140' },
          { text: 'PARTIAL', color: C.white, bg: C.partial_bg, bold: true },
        ],
        [
          { text: 'Execution' },
          { text: 'PowerShell Staging' },
          { text: 'T1059.001' },
          { text: 'PS Operational EID 4104' },
          { text: 'PARTIAL', color: C.white, bg: C.partial_bg, bold: true },
        ],
        [
          { text: 'Initial Access' },
          { text: 'Exploit Public App' },
          { text: 'T1190' },
          { text: 'Web / App logs — not Windows event logs' },
          { text: 'OUT OF SCOPE', color: C.body, bold: false },
        ],
      ]
    ),
    spacer(),
    hr(),
    pageBreak(),
  ];
}

function buildIntelSources() {
  return [
    h1('3. Intelligence Sources'),

    h2('3.1  Actor Profile'),
    buildTable(
      [{ text: 'Attribute', width: 2400 }, { text: 'Detail', width: 6400 }],
      [
        [{ text: 'MITRE ID', bold: true }, { text: 'G0149 — Cotton Sandstorm' }],
        [{ text: 'Also Known As', bold: true }, { text: 'CyberAvengers, Haghjoyan, Emennet Pasargad, DEV-0198' }],
        [{ text: 'Sponsorship', bold: true }, { text: 'IRGC-affiliated (Iranian Islamic Revolutionary Guard Corps)' }],
        [{ text: 'Target Profile', bold: true }, { text: 'Israeli organisations, Albanian government, regional critical infrastructure' }],
        [{ text: 'Active Since', bold: true }, { text: '2021 — present; BiBi campaigns October–November 2023' }],
      ]
    ),
    spacer(),

    h2('3.2  Malware Families'),
    buildTable(
      [
        { text: 'Family', width: 1800 },
        { text: 'Type', width: 1200 },
        { text: 'Key Behaviours', width: 4400 },
        { text: 'First Seen', width: 1400 },
      ],
      [
        [
          { text: 'BiBi-Windows (Win32/Bibi.A)', bold: true },
          { text: 'Wiper' },
          { text: 'rstrtmgr.dll handle unlock, 8-thread file corruption, .BiBi extension append, MBR overwrite' },
          { text: 'Oct 2023' },
        ],
        [
          { text: 'ROADSWEEP', bold: true },
          { text: 'Wiper' },
          { text: 'Targeted file deletion, boot sector overwrite, fake ransomware note (IMPORTANT.txt)' },
          { text: '2022' },
        ],
        [
          { text: 'CHIMNEYSWEEP', bold: true },
          { text: 'Backdoor' },
          { text: 'Initial access, C2 communication, pre-wiper reconnaissance and staging' },
          { text: '2022' },
        ],
      ]
    ),
    spacer(),

    h2('3.3  Key IOC Patterns (for hunting — do not hardcode in rules)'),
    bullet('BiBi-Windows spawns 8 or more threads immediately on execution'),
    bullet('Corrupted files receive a random 10-character alphanumeric extension (e.g., .TsM5fKyNaY)'),
    bullet('ROADSWEEP drops a fake ransom note (IMPORTANT.txt) to mislead investigators'),
    bullet('Both wipers stage from %TEMP%, C:\\ProgramData, and C:\\Users\\Public directories'),
    bullet('rstrtmgr.dll loaded in-process to unlock file handles before overwriting in-use files'),
    spacer(),

    h2('3.4  References'),
    bullet('MITRE ATT&CK G0149 — Cotton Sandstorm: https://attack.mitre.org/groups/G0149/'),
    bullet('CISA Advisory AA23-335A — IRGC-Affiliated Cyber Actors'),
    bullet('BiBi-Windows Wiper Analysis — BleepingComputer, October 2023'),
    bullet('ROADSWEEP / CyberAvengers — ClearSky Cyber Security Research 2022'),
    bullet('Atomic Red Team T1490 — github.com/redcanaryco/atomic-red-team'),
    hr(),
    pageBreak(),
  ];
}

function buildDetectionGaps() {
  return [
    h1('4. Detection Gaps'),
    buildTable(
      [
        { text: 'T-ID', width: 1000 },
        { text: 'Phase', width: 1400 },
        { text: 'Priority', width: 900 },
        { text: 'Log Required', width: 2100 },
        { text: 'Gap Description', width: 3400 },
      ],
      [
        [
          { text: 'T1574.002' },
          { text: 'DLL Load' },
          { text: 'HIGH', color: C.white, bg: C.high_bg, bold: true },
          { text: 'Sysmon EID 7 (image_load)' },
          { text: 'rstrtmgr.dll load is invisible in native logs. Rule 001b is a compensating behavioural proxy only.' },
        ],
        [
          { text: 'T1070.004' },
          { text: 'File Deletion' },
          { text: 'HIGH', color: C.white, bg: C.high_bg, bold: true },
          { text: 'EID 4663 + SACL on directories' },
          { text: 'File deletion events require SACL on every target directory — high overhead, not recommended for all hosts.' },
        ],
        [
          { text: 'T1021.002' },
          { text: 'Lateral Movement' },
          { text: 'MEDIUM', color: C.white, bg: C.medium_bg, bold: true },
          { text: 'Security EID 4624/4625/5140' },
          { text: 'Not covered in this wiper-phase ruleset. Gap rule included in Section 7.' },
        ],
        [
          { text: 'T1059.001' },
          { text: 'PS Staging' },
          { text: 'MEDIUM', color: C.white, bg: C.medium_bg, bold: true },
          { text: 'PS Operational EID 4104' },
          { text: 'Requires ScriptBlock logging policy. Gap rule included in Section 7.' },
        ],
        [
          { text: 'T1190' },
          { text: 'Initial Access' },
          { text: 'HIGH', color: C.white, bg: C.high_bg, bold: true },
          { text: 'Web / Application logs' },
          { text: 'Exploitation of internet-facing services — outside Windows Security log scope entirely.' },
        ],
        [
          { text: 'T1055' },
          { text: 'Process Injection' },
          { text: 'HIGH', color: C.white, bg: C.high_bg, bold: true },
          { text: 'Sysmon EID 10 / EDR' },
          { text: 'EID 4663 on LSASS with SACL is very high FP overhead. No practical native alternative.' },
        ],
      ]
    ),
    spacer(),
    hr(),
    pageBreak(),
  ];
}

function buildAbuseMatrix() {
  return [
    h1('5. Abuse Matrix — Wiper Technique Patterns'),
    buildTable(
      [
        { text: 'Pattern', width: 2000 },
        { text: 'T-ID', width: 900 },
        { text: 'CLI / Mechanism', width: 2800 },
        { text: 'Actors', width: 1400 },
        { text: 'Coverage', width: 1700 },
      ],
      [
        [{ text: 'BiBi wiper --force -d flag' }, { text: 'T1485' }, { text: '<wiper.exe> --force -d C:\\' }, { text: 'CyberAvengers' }, { text: 'wiper-native-001a' }],
        [{ text: 'rstrtmgr.dll handle unlock' }, { text: 'T1485' }, { text: 'LoadLibrary("rstrtmgr.dll") in-process' }, { text: 'CyberAvengers' }, { text: '001b (PARTIAL)' }],
        [{ text: 'sc.exe stop AV/EDR' }, { text: 'T1489' }, { text: 'sc stop WinDefend' }, { text: 'CyberAvengers, Lazarus' }, { text: 'wiper-native-002a' }],
        [{ text: 'net stop backup service' }, { text: 'T1489' }, { text: 'net stop VeeamDeploymentSvc' }, { text: 'CyberAvengers' }, { text: 'wiper-native-002a' }],
        [{ text: 'API-based service kill' }, { text: 'T1489' }, { text: 'ControlService() / TerminateProcess()' }, { text: 'CyberAvengers' }, { text: 'wiper-native-002b' }],
        [{ text: 'vssadmin delete shadows' }, { text: 'T1490' }, { text: 'vssadmin delete shadows /all /quiet' }, { text: 'CyberAvengers, Conti, LockBit' }, { text: 'wiper-native-003' }],
        [{ text: 'wmic shadowcopy delete' }, { text: 'T1490' }, { text: 'wmic shadowcopy delete' }, { text: 'CyberAvengers, multiple' }, { text: 'wiper-native-003' }],
        [{ text: 'PowerShell VSS deletion' }, { text: 'T1490' }, { text: 'Win32_ShadowCopy | Remove-WmiObject' }, { text: 'CyberAvengers, ransomware' }, { text: 'wiper-native-003' }],
        [{ text: 'bcdedit recoveryenabled no' }, { text: 'T1490' }, { text: 'bcdedit /set recoveryenabled no' }, { text: 'CyberAvengers, NotPetya' }, { text: 'wiper-native-004' }],
        [{ text: 'bcdedit bootstatuspolicy' }, { text: 'T1490' }, { text: 'bcdedit /set bootstatuspolicy ignoreallfailures' }, { text: 'CyberAvengers, WannaCry' }, { text: 'wiper-native-004' }],
        [{ text: 'CrashControl registry' }, { text: 'T1490' }, { text: 'reg add ...CrashControl /v AutoReboot /d 0' }, { text: 'CyberAvengers' }, { text: 'wiper-native-005' }],
        [{ text: 'reagentc /disable WinRE' }, { text: 'T1490' }, { text: 'reagentc /disable' }, { text: 'CyberAvengers' }, { text: 'wiper-native-008' }],
        [{ text: 'wevtutil cl Security' }, { text: 'T1070.001' }, { text: 'wevtutil cl Security' }, { text: 'CyberAvengers, APT38' }, { text: 'wiper-native-006c' }],
        [{ text: 'Clear-EventLog PowerShell' }, { text: 'T1070.001' }, { text: 'Clear-EventLog -LogName Security' }, { text: 'CyberAvengers, multiple' }, { text: 'wiper-native-006c' }],
        [{ text: 'diskpart clean (MBR)' }, { text: 'T1561.002' }, { text: 'diskpart /s script (select disk 0, clean)' }, { text: 'CyberAvengers, Shamoon' }, { text: 'wiper-native-007' }],
        [{ text: 'Direct PhysicalDrive write' }, { text: 'T1561.002' }, { text: 'dd of=\\\\.\\PhysicalDrive0 if=/dev/zero' }, { text: 'CyberAvengers, custom' }, { text: 'wiper-native-007' }],
        [{ text: 'schtasks /delete /f' }, { text: 'T1070' }, { text: 'schtasks /delete /tn "TaskName" /f' }, { text: 'CyberAvengers' }, { text: 'wiper-native-009a' }],
      ]
    ),
    spacer(),
    hr(),
    pageBreak(),
  ];
}

function buildRuleSection(ruleId, title, technique, eventLog, eventId, level, validationScore, yaml, auditNote) {
  const lc = levelColor(level);
  return [
    h2(`Rule ${ruleId.toUpperCase()}  —  ${title}`),
    new Paragraph({
      spacing: { after: 80 },
      children: [
        new TextRun({ text: 'Technique: ', bold: true, size: 19, color: C.body }),
        new TextRun({ text: ` ${technique} `, size: 18, color: C.body }),
        new TextRun({ text: '    ', size: 18 }),
        new TextRun({ text: 'Level: ', bold: true, size: 19, color: C.body }),
        new TextRun({
          text: ` ${level.toUpperCase()} `,
          bold: true, size: 18, color: C.white,
          shading: { type: ShadingType.SOLID, color: lc, fill: lc },
        }),
        new TextRun({ text: '    ', size: 18 }),
        new TextRun({ text: 'Log / EID: ', bold: true, size: 19, color: C.body }),
        new TextRun({ text: `${eventLog} / EID ${eventId}`, size: 18, color: C.body }),
      ],
    }),
    new Paragraph({
      spacing: { after: 100 },
      children: [
        new TextRun({ text: 'Validation: ', bold: true, size: 19, color: C.body }),
        new TextRun({ text: validationScore, size: 18, color: C.body }),
      ],
    }),
    ...(auditNote ? [
      ...noteBox([`Audit Prerequisite: ${auditNote}`]),
      spacer(),
    ] : []),
    h3('Sigma Rule'),
    ...codeBlock(yaml),
    spacer(),
    hr(),
  ];
}

function buildAtomicRules() {
  return [
    h1('6. Atomic Detection Rules (Sigma — All 14 Production Rules)'),
    body('All rules target native Windows event logs only. No Sysmon required. EID 4688 rules require GPO command line auditing (see Audit Prerequisites).'),
    spacer(),

    ...buildRuleSection('wiper-native-001a', 'BiBi/ROADSWEEP Wiper Process Execution', 'T1485 — Data Destruction', 'Windows Security', '4688', 'high',
      'Evasion 3/5 | Fields 4/5 | Paths 4/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['001a'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-001b', 'rstrtmgr.dll Abuse — Compensating Detection via rrm.exe', 'T1485 — Data Destruction', 'Windows Security', '4688', 'high',
      'Evasion 3/5 | Fields 4/5 | Paths 3/5 | FP 3/5 | Syntax 5/5',
      SIGMA_RULES['001b'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-002a', 'Security Tool Service Termination via sc.exe / net.exe', 'T1489 — Service Stop', 'Windows Security', '4688', 'high',
      'Evasion 3/5 | Fields 5/5 | Paths 4/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['002a'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-002b', 'Security Tool Service Transitioned to Stopped State', 'T1489 — Service Stop', 'Windows System', '7036', 'medium',
      'Evasion 4/5 | Fields 4/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
      SIGMA_RULES['002b'],
      'No additional policy required — EID 7036 is generated by default'),

    ...buildRuleSection('wiper-native-003', 'Volume Shadow Copy Deletion via vssadmin / wmic / PowerShell', 'T1490 — Inhibit System Recovery', 'Windows Security', '4688', 'high',
      'Evasion 3/5 | Fields 5/5 | Paths 5/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['003'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-004', 'BCDEdit Boot Recovery and Repair Disabled', 'T1490 — Inhibit System Recovery', 'Windows Security', '4688', 'high',
      'Evasion 3/5 | Fields 5/5 | Paths 5/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['004'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-005', 'CrashControl Registry Key Modified to Disable Recovery', 'T1490 — Inhibit System Recovery', 'Windows Security', '4657', 'high',
      'Evasion 4/5 | Fields 4/5 | Paths 3/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['005'],
      'Object Access > Audit Registry: Success + SACL on HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl with Everyone: Set Value (Success)'),

    ...buildRuleSection('wiper-native-006a', 'Windows Security Event Log Cleared', 'T1070.001 — Clear Windows Event Logs', 'Windows Security', '1102', 'high',
      'Evasion 5/5 | Fields 4/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
      SIGMA_RULES['006a'],
      'No additional policy required — EID 1102 is self-generated by the Security log'),

    ...buildRuleSection('wiper-native-006b', 'Windows System Event Log Cleared', 'T1070.001 — Clear Windows Event Logs', 'Windows System', '104', 'high',
      'Evasion 5/5 | Fields 4/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
      SIGMA_RULES['006b'],
      'No additional policy required — EID 104 is self-generated by the System log'),

    ...buildRuleSection('wiper-native-006c', 'Event Log Clearing via wevtutil / PowerShell / WMI', 'T1070.001 — Clear Windows Event Logs', 'Windows Security', '4688', 'high',
      'Evasion 3/5 | Fields 5/5 | Paths 5/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['006c'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-007', 'Raw Disk Access or MBR Overwrite via diskpart / dd / Direct Handle', 'T1561.002 — Disk Structure Wipe', 'Windows Security', '4688', 'critical',
      'Evasion 3/5 | Fields 5/5 | Paths 5/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['007'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-008', 'Windows Recovery Environment Disabled via reagentc.exe', 'T1490 — Inhibit System Recovery', 'Windows Security', '4688', 'high',
      'Evasion 3/5 | Fields 5/5 | Paths 4/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['008'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-009a', 'Scheduled Task Bulk Deletion via schtasks.exe', 'T1070 — Indicator Removal', 'Windows Security', '4688', 'medium',
      'Evasion 3/5 | Fields 5/5 | Paths 4/5 | FP 4/5 | Syntax 5/5',
      SIGMA_RULES['009a'],
      'Audit Process Creation (Success) + Include command line in process creation events'),

    ...buildRuleSection('wiper-native-009b', 'Scheduled Task Deleted via Task Scheduler Operational Log', 'T1070 — Indicator Removal', 'Task Scheduler Operational', '141', 'medium',
      'Evasion 5/5 | Fields 4/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
      SIGMA_RULES['009b'],
      'Task Scheduler operational log must be enabled: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true'),

    h2('6.1  Gap Rules — Partial Coverage for Out-of-Scope Techniques'),
    body('These two rules address techniques in the detection gap list. They require additional log sources not covered by the core 14 rules.'),
    spacer(),

    ...buildRuleSection('gap-smb', 'SMB Lateral Movement — NTLM Type 3 Logon', 'T1021.002 — Remote Services: SMB', 'Windows Security', '4624', 'medium',
      'Evasion 4/5 | Fields 4/5 | Paths 3/5 | FP 3/5 | Syntax 5/5',
      SIGMA_RULES['smb'],
      'Audit Logon (Success) — enabled by default on most Windows systems'),

    ...buildRuleSection('gap-ps4104', 'PowerShell ScriptBlock — Wiper Staging Patterns', 'T1059.001 — PowerShell', 'PowerShell Operational', '4104', 'high',
      'Evasion 4/5 | Fields 5/5 | Paths 4/5 | FP 3/5 | Syntax 5/5',
      SIGMA_RULES['ps4104'],
      'Enable ScriptBlock logging: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging = 1'),

    pageBreak(),
  ];
}

function buildKillChainCorrelation() {
  return [
    h1('7. Kill-Chain Correlation (Primary)'),
    body('The following Sigma correlation rule ties all 14 individual alerts into a single high-confidence kill-chain indicator. It fires when 4 or more distinct phase rules trigger on the same host within a 30-minute window.'),
    spacer(),

    h2('7.1  Sigma Correlation Rule'),
    ...codeBlock(CORRELATION_SIGMA),
    spacer(),

    h2('7.2  Phase-Ordered Kill-Chain Timeline'),
    ...codeBlock(PHASE_TIMELINE),
    spacer(),

    h2('7.3  SIEM-Layer Correlation Patterns'),
    body('Implement these as SIEM-native scheduled analytics or alert aggregation rules:'),
    spacer(),

    bodyBold('CORR-01 — Pre-Wiper Kill Chain (Service Stop + VSS Delete + BCDEdit)'),
    bullet('Trigger: 002a AND 003 AND 004 on same host within 10 minutes'),
    bullet('Severity: CRITICAL — page on-call immediately'),
    spacer(),

    bodyBold('CORR-02 — Anti-Forensics Sequence (Wiper Execution + Log Clearing)'),
    bullet('Trigger: 001a FOLLOWED BY 006a or 006b within 5 minutes on same host'),
    bullet('Severity: CRITICAL — preserve all off-host logs before investigating'),
    spacer(),

    bodyBold('CORR-03 — Dual Recovery Prevention (BCDEdit + WinRE Disable)'),
    bullet('Trigger: 004 AND 008 on same host within 15 minutes'),
    bullet('Severity: HIGH — system being made unrecoverable'),
    spacer(),

    bodyBold('CORR-04 — Service Mass-Kill Threshold'),
    bullet('Trigger: 3 or more 002a/002b alerts from same host within 60 seconds'),
    bullet('Severity: HIGH — bulk security tool termination in progress'),
    spacer(),

    bodyBold('CORR-05 — Full Wiper Kill Chain (All Phases)'),
    bullet('Trigger: 4 or more unique rules from this playbook on same host within 30 minutes'),
    bullet('Severity: CRITICAL — confirmed multi-phase attack'),
    bullet('Action: Isolate host, preserve off-host logs, initiate IR playbook immediately'),
    hr(),
    pageBreak(),
  ];
}

function buildKillChainScore() {
  return [
    h1('8. Kill-Chain Score'),
    buildTable(
      [{ text: 'Dimension', width: 2400 }, { text: 'Score', width: 1000 }, { text: 'Notes', width: 5400 }],
      [
        [{ text: 'Sequence Coverage', bold: true }, { text: '4 / 5' }, { text: 'All 4 wiper phases covered; initial access and lateral movement are gaps' }],
        [{ text: 'Entity Correlation', bold: true }, { text: '4 / 5' }, { text: 'ComputerName grouping; SubjectUserName available in EID 4688 for user pivot' }],
        [{ text: 'Time Window', bold: true }, { text: '5 / 5' }, { text: '30-minute window appropriate for multi-phase wiper kill chain' }],
        [{ text: 'FP Risk', bold: true }, { text: '4 / 5' }, { text: 'Low FP at 4+ rule threshold; individual rules well-filtered' }],
        [{ text: 'Evasion Coverage', bold: true }, { text: '3.5 / 5' }, { text: 'Binary rename gap in all EID 4688 rules; DLL load gap for rstrtmgr.dll' }],
      ]
    ),
    spacer(),
    new Paragraph({
      spacing: { after: 100 },
      children: [
        new TextRun({ text: 'Overall Kill-Chain Score: ', bold: true, size: 24, color: C.navy }),
        new TextRun({ text: '4.1 / 5.0', bold: true, size: 28, color: C.covered_bg }),
      ],
    }),
    body('Phases covered: Pre-Impact (service stop, recovery disable) | Impact (data destruction, MBR wipe) | Anti-Forensics (log clearing, task cleanup)'),
    body('FP Risk Level: LOW at correlation threshold (4+ rules); MEDIUM for individual rules in isolation'),
    hr(),
    pageBreak(),
  ];
}

function buildDataRequirements() {
  return [
    h1('9. Data Requirements'),
    buildTable(
      [
        { text: 'Phase', width: 1400 },
        { text: 'Log Source', width: 1800 },
        { text: 'Event ID', width: 900 },
        { text: 'Collection Status', width: 2200 },
        { text: 'Notes', width: 2500 },
      ],
      [
        [
          { text: 'All EID 4688 rules' },
          { text: 'Windows Security' },
          { text: '4688' },
          { text: 'MUST VERIFY', color: C.white, bg: C.gap_bg, bold: true },
          { text: 'Requires: Audit Process Creation + Include command line GPO' },
        ],
        [
          { text: 'Service state change' },
          { text: 'Windows System' },
          { text: '7036' },
          { text: 'Default — verify forwarding', color: C.body },
          { text: 'No policy change required' },
        ],
        [
          { text: 'Security log cleared' },
          { text: 'Windows Security' },
          { text: '1102' },
          { text: 'Default — verify forwarding', color: C.body },
          { text: 'Self-generated — cannot be suppressed' },
        ],
        [
          { text: 'System log cleared' },
          { text: 'Windows System' },
          { text: '104' },
          { text: 'Default — verify forwarding', color: C.body },
          { text: 'Self-generated — cannot be suppressed' },
        ],
        [
          { text: 'Registry modifications' },
          { text: 'Windows Security' },
          { text: '4657' },
          { text: 'MUST CONFIGURE SACL', color: C.white, bg: C.gap_bg, bold: true },
          { text: 'Object Access auditing + SACL on CrashControl key' },
        ],
        [
          { text: 'Task deletion' },
          { text: 'Task Scheduler' },
          { text: '141' },
          { text: 'MUST ENABLE LOG', color: C.white, bg: C.partial_bg, bold: true },
          { text: 'wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true' },
        ],
        [
          { text: 'PowerShell staging' },
          { text: 'PowerShell Operational' },
          { text: '4104' },
          { text: 'MUST ENABLE ScriptBlock', color: C.white, bg: C.partial_bg, bold: true },
          { text: 'HKLM\\...\\PowerShell\\ScriptBlockLogging = 1' },
        ],
        [
          { text: 'DLL load monitoring' },
          { text: 'NO NATIVE EID' },
          { text: 'N/A' },
          { text: 'GAP — Sysmon / EDR required', color: C.white, bg: C.gap_bg, bold: true },
          { text: 'Sysmon EID 7 or host EDR telemetry only' },
        ],
        [
          { text: 'File deletion events' },
          { text: 'Windows Security' },
          { text: '4663' },
          { text: 'NOT RECOMMENDED', color: C.body },
          { text: 'SACL required on every directory — extreme volume overhead' },
        ],
        [
          { text: 'SMB lateral movement' },
          { text: 'Windows Security' },
          { text: '4624/5140' },
          { text: 'Default logon auditing', color: C.body },
          { text: 'Verify Audit Logon and Object Access policies are enabled' },
        ],
      ]
    ),
    spacer(),
    hr(),
    pageBreak(),
  ];
}

function buildRecommendedActions() {
  return [
    h1('10. Recommended Actions'),

    h2('10.1  Immediate — Deploy within 24 Hours'),
    bullet('Verify EID 4688 command line auditing: run auditpol /get /subcategory:"Process Creation" on endpoints. If not enabled, deploy via GPO immediately — 11 of 14 rules produce zero detections without it.'),
    bullet('Deploy wiper-native-006a and 006b (EID 1102 + 104) first — zero prerequisites, highest standalone confidence.'),
    bullet('Deploy wiper-native-004 and 003 (BCDEdit + VSS deletion) — high-confidence, minimal FP, no special audit config.'),
    bullet('Enable Task Scheduler operational log: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true via GPO startup script.'),
    spacer(),

    h2('10.2  Short-Term — Deploy within 1 Week'),
    bullet('Deploy all remaining EID 4688 rules after verifying command line auditing is active. Validate by running bcdedit /? on a test endpoint and checking EID 4688 with CommandLine field populated.'),
    bullet('Configure CrashControl SACL for wiper-native-005. Test by writing to the key from a non-SYSTEM process and verifying EID 4657 appears.'),
    bullet('Implement SIEM correlation rules CORR-01 through CORR-05. These are higher-confidence than individual rules and should be the primary paging criteria.'),
    bullet('Populate authorized account suppressions in wiper-native-006a (EID 1102 filter) with known SOC and admin accounts.'),
    spacer(),

    h2('10.3  Medium-Term — Within 1 Month'),
    bullet('Deploy Sysmon on critical assets to close the rstrtmgr.dll gap (EID 7 image_load) — or confirm EDR already captures DLL load telemetry.'),
    bullet('Enable PowerShell ScriptBlock logging (EID 4104) for wiper staging detection.'),
    bullet('Deploy SMB lateral movement rules (EID 4624/4625) as supporting context for wiper propagation detection across network.'),
    spacer(),

    h2('10.4  MITRE Mitigations'),
    buildTable(
      [{ text: 'Mitigation', width: 2400 }, { text: 'ID', width: 800 }, { text: 'Applicability', width: 5600 }],
      [
        [{ text: 'Data Backup', bold: true }, { text: 'M1053' }, { text: 'Maintain offline or immutable backups not reachable from a compromised host' }],
        [{ text: 'Restrict File and Directory Permissions', bold: true }, { text: 'M1022' }, { text: 'Restrict write access to boot files, BCD, and WinRE from non-admin accounts' }],
        [{ text: 'Privileged Account Management', bold: true }, { text: 'M1026' }, { text: 'Limit accounts with ability to stop security services (T1489)' }],
        [{ text: 'User Account Control', bold: true }, { text: 'M1052' }, { text: 'Require UAC elevation for bcdedit, reagentc, diskpart, and vssadmin' }],
        [{ text: 'Audit', bold: true }, { text: 'M1047' }, { text: 'Implement all audit policies described in the Data Requirements section' }],
      ]
    ),
    spacer(),

    h2('10.5  Knowledge Graph Entities to Persist'),
    bullet('CyberAvengers / Cotton Sandstorm — actor entity, techniques: T1485/T1489/T1490/T1561.002/T1070.001'),
    bullet('BiBi-Windows Wiper — malware family entity, linked to G0149'),
    bullet('ROADSWEEP — malware family entity, linked to G0149'),
    bullet('wiper-kill-chain-native — detection package entity: 14 Sigma rules, native Windows logs'),
    bullet('Learning: EID 4688 lacks OriginalFileName — binary rename is always a gap without Sysmon'),
    bullet('Decision: Native Windows rules use service: security + EventID: 4688 field names (NewProcessName, ParentProcessName)'),
    hr(),
    pageBreak(),
  ];
}

function buildAppendix() {
  return [
    h1('Appendix — Rule Index'),
    buildTable(
      [
        { text: 'Rule ID', width: 2400 },
        { text: 'Technique', width: 1000 },
        { text: 'Log Source', width: 1800 },
        { text: 'EID', width: 700 },
        { text: 'Level', width: 900 },
        { text: 'Audit Prerequisite', width: 2000 },
      ],
      [
        [{ text: 'wiper-native-001a' }, { text: 'T1485' }, { text: 'Security' }, { text: '4688' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-001b' }, { text: 'T1485' }, { text: 'Security' }, { text: '4688' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-002a' }, { text: 'T1489' }, { text: 'Security' }, { text: '4688' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-002b' }, { text: 'T1489' }, { text: 'System' }, { text: '7036' }, { text: 'Medium', color: C.white, bg: C.medium_bg, bold: true }, { text: 'Default (none)' }],
        [{ text: 'wiper-native-003' }, { text: 'T1490' }, { text: 'Security' }, { text: '4688' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-004' }, { text: 'T1490' }, { text: 'Security' }, { text: '4688' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-005' }, { text: 'T1490' }, { text: 'Security' }, { text: '4657' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'Object Access + SACL' }],
        [{ text: 'wiper-native-006a' }, { text: 'T1070.001' }, { text: 'Security' }, { text: '1102' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'Default (none)' }],
        [{ text: 'wiper-native-006b' }, { text: 'T1070.001' }, { text: 'System' }, { text: '104' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'Default (none)' }],
        [{ text: 'wiper-native-006c' }, { text: 'T1070.001' }, { text: 'Security' }, { text: '4688' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-007' }, { text: 'T1561.002' }, { text: 'Security' }, { text: '4688' }, { text: 'Critical', color: C.white, bg: C.critical_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-008' }, { text: 'T1490' }, { text: 'Security' }, { text: '4688' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-009a' }, { text: 'T1070' }, { text: 'Security' }, { text: '4688' }, { text: 'Medium', color: C.white, bg: C.medium_bg, bold: true }, { text: 'EID 4688 CLI' }],
        [{ text: 'wiper-native-009b' }, { text: 'T1070' }, { text: 'TaskScheduler' }, { text: '141' }, { text: 'Medium', color: C.white, bg: C.medium_bg, bold: true }, { text: 'Enable TS log' }],
        [{ text: 'gap-smb' }, { text: 'T1021.002' }, { text: 'Security' }, { text: '4624' }, { text: 'Medium', color: C.white, bg: C.medium_bg, bold: true }, { text: 'Default logon audit' }],
        [{ text: 'gap-ps4104' }, { text: 'T1059.001' }, { text: 'PowerShell' }, { text: '4104' }, { text: 'High', color: C.white, bg: C.high_bg, bold: true }, { text: 'ScriptBlock logging' }],
      ]
    ),
    spacer(),
    h2('Key Limitations vs Sysmon'),
    bullet('OriginalFileName (PE metadata) — NOT in EID 4688. Binary rename detection is impossible without Sysmon EID 1 or EDR.'),
    bullet('DLL load monitoring — NO native EID for image_load. Sysmon EID 7 or EDR required for rstrtmgr.dll.'),
    bullet('File deletion events — EID 4663 requires SACL on every target directory. High overhead; not included in this ruleset.'),
    bullet('Process hashes — NOT available in EID 4688. Hash-based detection requires Sysmon or EDR.'),
    bullet('EID 4688 CommandLine — ONLY populated when GPO "Include command line" is explicitly enabled. Verify before deploying.'),
  ];
}

// ── Main ───────────────────────────────────────────────────────────────────
async function main() {
  const dateStr = new Date().toISOString().split('T')[0];
  const outDir  = path.join(os.homedir(), 'Desktop', 'Detection Engineering Reports');
  const outPath = path.join(outDir, `ThreatHunt_CyberAvengers_Native_${dateStr}.docx`);

  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const children = [
    ...buildCover(),
    ...buildExecutiveSummary(),
    ...buildKillChainCoverage(),
    ...buildIntelSources(),
    ...buildDetectionGaps(),
    ...buildAbuseMatrix(),
    ...buildAtomicRules(),
    ...buildKillChainCorrelation(),
    ...buildKillChainScore(),
    ...buildDataRequirements(),
    ...buildRecommendedActions(),
    ...buildAppendix(),
  ];

  const doc = new Document({
    creator: 'Detection Engineering Team',
    title: 'Threat Hunt Report — CyberAvengers / Cotton Sandstorm (Native Windows)',
    description: 'Full threat hunt report for CyberAvengers wiper activity using native Windows event logs. No Sysmon required. Sigma rules only.',
    sections: [{ children }],
  });

  const buf = await Packer.toBuffer(doc);
  fs.writeFileSync(outPath, buf);

  console.log('\nThreat Hunt Report written to:');
  console.log(`  ${outPath}`);
  console.log(`  Sections: 10 + Appendix`);
  console.log(`  Rules: 14 production + 2 gap + 1 kill-chain correlation`);
  console.log(`  Code blocks: light grey background (F4F6F7) — no black backgrounds\n`);
}

main().catch(e => { console.error(e); process.exit(1); });
