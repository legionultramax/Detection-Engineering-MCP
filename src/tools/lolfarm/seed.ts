// LOLFarm Seed Data — curated high-value entries for immediate availability
// Sources: LOLDrivers, HijackLibs, LOLRMM, LoFP, WADComs, LOTS, MalAPI
// This provides offline-first data; GitHub sync expands coverage.

import type {
  LOLDriverEntry, HijackLibEntry, LOLRMMEntry, LoFPEntry,
  WADComEntry, LOTSEntry, MalAPIEntry,
} from '../../db/lolfarm.js';

// ---------------------------------------------------------------------------
// LOLDrivers — Top BYOVD drivers used in real attacks
// Source: loldrivers.io / magicsword-io/LOLDrivers
// ---------------------------------------------------------------------------

export const SEED_DRIVERS: LOLDriverEntry[] = [
  {
    id: '7b2fa3a1-1b3a-4f5e-9f2a-1c2d3e4f5a6b',
    name: 'RTCore64.sys',
    description: 'Micro-Star MSI Afterburner RTCore64.sys — arbitrary kernel memory read/write. Most abused BYOVD driver (BlackByte, AvosLocker, Cuba, Lazarus).',
    category: 'vulnerable',
    hashes: { sha256: '01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862571c04b4525eee' },
    detection: [{ type: 'sigma', value: 'RTCore64.sys driver load' }, { type: 'yara', value: 'BYOVD_RTCore64' }],
    mitre_techniques: ['T1068', 'T1562.001'],
    cve: ['CVE-2019-16098'],
    verified: true,
    resources: ['https://loldrivers.io/', 'https://www.elastic.co/security-labs/stopping-vulnerable-driver-attacks'],
  },
  {
    id: '8c3fb4b2-2c4b-5a6f-0a3b-2d3e4f5a6b7c',
    name: 'DBUtil_2_3.sys',
    description: 'Dell BIOS utility driver — arbitrary kernel memory access. Used by Scattered Spider, BlackCat/ALPHV.',
    category: 'vulnerable',
    hashes: { sha256: '0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5' },
    detection: [{ type: 'sigma', value: 'DBUtil driver load' }],
    mitre_techniques: ['T1068', 'T1562.001'],
    cve: ['CVE-2021-21551'],
    verified: true,
    resources: ['https://www.sentinelone.com/labs/cve-2021-21551-dbutil-dell/'],
  },
  {
    id: '9d4gc5c3-3d5c-6b7g-1b4c-3e4f5a6b7c8d',
    name: 'gdrv.sys',
    description: 'GIGABYTE GDrv low-level access driver — arbitrary physical memory read/write. Used by RobbinHood ransomware.',
    category: 'vulnerable',
    hashes: { sha256: '31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427' },
    mitre_techniques: ['T1068', 'T1562.001'],
    cve: ['CVE-2018-19320'],
    verified: true,
    resources: ['https://www.rapid7.com/blog/post/2020/01/30/cve-2018-19320-gigabyte-drivers/'],
  },
  {
    id: 'ae5hd6d4-4e6d-7c8h-2c5d-4f5a6b7c8d9e',
    name: 'asWarPot.sys',
    description: 'ASUS AURA SYNC driver — arbitrary read/write physical memory. Used in AvosLocker and Cuba ransomware attacks.',
    category: 'vulnerable',
    hashes: { sha256: 'b8132a98a4d17eae3a5c27cb28bf2a3b0daa9e91d4c91c58c69a6dbba7f76df4' },
    mitre_techniques: ['T1068', 'T1562.001'],
    verified: true,
  },
  {
    id: 'bf6ie7e5-5f7e-8d9i-3d6e-5a6b7c8d9e0f',
    name: 'ProcExp152.sys',
    description: 'Process Explorer driver from Sysinternals — abused to terminate EDR processes. Used by AuKill/Medusa and other ransomware.',
    category: 'vulnerable',
    hashes: { sha256: '440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c' },
    mitre_techniques: ['T1562.001', 'T1068'],
    verified: true,
    resources: ['https://www.sophos.com/en-us/x-ops/research/aukill-edr-killer-malware-abuses-process-explorer-driver'],
  },
  {
    id: 'cg7jf8f6-6g8f-9e0j-4e7f-6b7c8d9e0f1g',
    name: 'WinRing0x64.sys',
    description: 'WinRing0 — open-source hardware access library driver. Low-level I/O port and MSR access. Widely abused in coin miners and by multiple APTs.',
    category: 'vulnerable',
    hashes: { sha256: '11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5' },
    mitre_techniques: ['T1068'],
    verified: true,
  },
  {
    id: 'dh8kg9g7-7h9g-0f1k-5f8g-7c8d9e0f1g2h',
    name: 'IQVW64E.SYS',
    description: 'Intel iQVW64 — Intel Network Adapter Diagnostic Driver. Arbitrary physical memory mapping. Used by Lazarus Group BYOVD campaigns.',
    category: 'vulnerable',
    hashes: { sha256: '4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b' },
    mitre_techniques: ['T1068', 'T1562.001'],
    cve: ['CVE-2015-2291'],
    verified: true,
    resources: ['https://decoded.avast.io/janvojtesek/lazarus-and-the-firmachagent/'],
  },
  {
    id: 'ei9lh0h8-8i0h-1g2l-6g9h-8d9e0f1g2h3i',
    name: 'mhyprot2.sys',
    description: 'Genshin Impact anti-cheat driver (mhyprotect) — arbitrary kernel memory read/write and process termination. Abused by ransomware to kill AV/EDR.',
    category: 'vulnerable',
    hashes: { sha256: '0466e90bf0e83b776ca8716e01d35a8a5e13159d30e5d63bd95e8d115ca1c11c' },
    mitre_techniques: ['T1562.001', 'T1068'],
    verified: true,
    resources: ['https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html'],
  },
  {
    id: 'fj0mi1i9-9j1i-2h3m-7h0i-9e0f1g2h3i4j',
    name: 'zamguard64.sys',
    description: 'Zemana Anti-Malware driver — arbitrary kernel-mode code execution. Abused by multiple ransomware families to terminate security products.',
    category: 'vulnerable',
    hashes: { sha256: '543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91' },
    mitre_techniques: ['T1562.001'],
    verified: true,
  },
  {
    id: 'gk1nj2j0-0k2j-3i4n-8i1j-0f1g2h3i4j5k',
    name: 'kprocesshacker.sys',
    description: 'Process Hacker kernel driver — full system access including process termination and memory operations. Used by Medusa, BlackCat to kill EDR.',
    category: 'vulnerable',
    hashes: { sha256: 'ab15d1e69373b2cffa095e36a7be57b09bcddf7beb9a26e0c0bbf5c59a92b1df' },
    mitre_techniques: ['T1562.001', 'T1068'],
    verified: true,
  },
];

// ---------------------------------------------------------------------------
// HijackLibs — Top DLL hijacking targets
// Source: hijacklibs.net / wietze/HijackLibs
// ---------------------------------------------------------------------------

export const SEED_HIJACKLIBS: HijackLibEntry[] = [
  {
    name: 'version.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeClickToRun.exe', type: 'Sideloading' },
      { path: 'C:\\Windows\\System32\\msiexec.exe', type: 'Search Order' },
    ],
    hijack_type: 'Sideloading',
    resources: ['https://hijacklibs.net/entries/microsoft/built-in/version.html'],
  },
  {
    name: 'dbghelp.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'C:\\Windows\\System32\\calc.exe', type: 'Search Order' },
    ],
    hijack_type: 'Search Order',
    resources: ['https://hijacklibs.net/'],
  },
  {
    name: 'winmm.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'Multiple signed executables', type: 'Sideloading' },
    ],
    hijack_type: 'Sideloading',
  },
  {
    name: 'WTSAPI32.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'C:\\Windows\\System32\\calc.exe', type: 'Phantom' },
    ],
    hijack_type: 'Phantom',
  },
  {
    name: 'userenv.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'C:\\Windows\\System32\\svchost.exe', type: 'Search Order' },
    ],
    hijack_type: 'Search Order',
  },
  {
    name: 'msasn1.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'Multiple applications', type: 'Search Order' },
    ],
    hijack_type: 'Search Order',
  },
  {
    name: 'edputil.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'C:\\Windows\\System32\\DeviceCensus.exe', type: 'Phantom', auto_elevate: true, privilege_escalation: true },
    ],
    hijack_type: 'Phantom',
    resources: ['https://hijacklibs.net/entries/microsoft/built-in/edputil.html'],
  },
  {
    name: 'DUI70.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'C:\\Windows\\System32\\ComputerDefaults.exe', type: 'Search Order', auto_elevate: true, privilege_escalation: true },
    ],
    hijack_type: 'Search Order',
  },
  {
    name: 'cscapi.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'C:\\Windows\\explorer.exe', type: 'Phantom' },
    ],
    hijack_type: 'Phantom',
  },
  {
    name: 'profapi.dll',
    vendor: 'Microsoft',
    expected_locations: ['%SYSTEMROOT%\\System32\\'],
    vulnerable_executables: [
      { path: 'Multiple signed Microsoft executables', type: 'Sideloading' },
    ],
    hijack_type: 'Sideloading',
  },
];

// ---------------------------------------------------------------------------
// LOLRMM — Remote Monitoring & Management tools abused for C2
// Source: lolrmm.io (community project)
// ---------------------------------------------------------------------------

export const SEED_RMM: LOLRMMEntry[] = [
  {
    name: 'AnyDesk',
    vendor: 'AnyDesk Software GmbH',
    description: 'Remote desktop application commonly abused by ransomware operators for persistent access.',
    executable_names: ['AnyDesk.exe', 'anydesk.exe'],
    network_artifacts: { domains: ['*.net.anydesk.com'], ports: [6568, 7070], user_agents: ['AnyDesk'] },
    registry_artifacts: ['HKLM\\SOFTWARE\\AnyDesk', 'HKCU\\SOFTWARE\\AnyDesk'],
    detection_guidance: 'Monitor for AnyDesk process execution outside IT-managed deployments. Check ad.trace log for connection history.',
    mitre_techniques: ['T1219', 'T1133'],
    abuse_references: ['Conti', 'BlackCat/ALPHV', 'Royal', 'Akira', 'Storm-0501'],
  },
  {
    name: 'TeamViewer',
    vendor: 'TeamViewer AG',
    description: 'Remote support tool frequently abused by threat actors for hands-on-keyboard access.',
    executable_names: ['TeamViewer.exe', 'tv_w32.exe', 'tv_x64.exe', 'TeamViewer_Service.exe'],
    network_artifacts: { domains: ['*.teamviewer.com'], ports: [5938], user_agents: ['TeamViewer'] },
    registry_artifacts: ['HKLM\\SOFTWARE\\TeamViewer', 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer'],
    detection_guidance: 'Look for TeamViewer_Service.exe running without corporate approval. Connections_incoming.txt logs all inbound sessions.',
    mitre_techniques: ['T1219', 'T1133'],
    abuse_references: ['APT29', 'LAPSUS$', 'Storm-1567'],
  },
  {
    name: 'ConnectWise ScreenConnect',
    vendor: 'ConnectWise',
    description: 'Remote support/access tool. Major target after CVE-2024-1709 auth bypass. Widely abused by ransomware.',
    executable_names: ['ScreenConnect.ClientService.exe', 'ScreenConnect.WindowsClient.exe'],
    network_artifacts: { domains: ['*.screenconnect.com', '*.connectwise.com'], ports: [443, 8040, 8041] },
    registry_artifacts: ['HKLM\\SOFTWARE\\ScreenConnect Client'],
    detection_guidance: 'Monitor for ScreenConnect client installation outside IT approval. Instance URLs in registry reveal C2 server.',
    mitre_techniques: ['T1219', 'T1133', 'T1190'],
    abuse_references: ['LockBit', 'Black Basta', 'Scattered Spider', 'CVE-2024-1709'],
  },
  {
    name: 'Atera',
    vendor: 'Atera Networks',
    description: 'Cloud-based RMM. Abused by ransomware operators — trial accounts provide free C2 infrastructure.',
    executable_names: ['AteraAgent.exe', 'AgentPackageRuntime.exe'],
    network_artifacts: { domains: ['*.atera.com', 'agent.atera.com'] },
    registry_artifacts: ['HKLM\\SOFTWARE\\ATERA Networks'],
    detection_guidance: 'Alert on AteraAgent.exe installation on endpoints not in approved RMM policy.',
    mitre_techniques: ['T1219'],
    abuse_references: ['Royal', 'BianLian'],
  },
  {
    name: 'Splashtop',
    vendor: 'Splashtop Inc',
    description: 'Remote access tool. Used by threat actors as alternative when AnyDesk/TeamViewer are blocked.',
    executable_names: ['SRManager.exe', 'SplashtopStreamer.exe', 'strwinclt.exe'],
    network_artifacts: { domains: ['*.splashtop.com'], ports: [443, 6783] },
    mitre_techniques: ['T1219'],
    abuse_references: ['AvosLocker'],
  },
  {
    name: 'RustDesk',
    vendor: 'RustDesk',
    description: 'Open-source remote desktop. Self-hosted = attacker-controlled C2 with no vendor visibility.',
    executable_names: ['rustdesk.exe'],
    network_artifacts: { ports: [21115, 21116, 21117, 21118, 21119] },
    detection_guidance: 'Self-hosted instances are highest risk — check for non-standard relay server configs.',
    mitre_techniques: ['T1219'],
    abuse_references: ['Play', 'BianLian'],
  },
  {
    name: 'MeshCentral',
    vendor: 'Open Source (ylianst)',
    description: 'Open-source web-based remote management. Self-hosted = full attacker control.',
    executable_names: ['MeshAgent.exe', 'MeshAgent64.exe'],
    network_artifacts: { ports: [443, 4433] },
    detection_guidance: 'MeshAgent running on endpoints not in IT inventory is high-confidence malicious.',
    mitre_techniques: ['T1219'],
    abuse_references: ['SolarMarker', 'Vice Society'],
  },
  {
    name: 'Level.io',
    vendor: 'Level',
    description: 'Modern RMM platform. Emerging in ransomware operations as newer/less-detected alternative.',
    executable_names: ['level-windows-amd64.exe', 'level.exe'],
    network_artifacts: { domains: ['*.level.io'] },
    mitre_techniques: ['T1219'],
    abuse_references: ['Scattered Spider'],
  },
  {
    name: 'NetSupport Manager',
    vendor: 'NetSupport Ltd',
    description: 'Remote control software frequently dropped by phishing campaigns and loaders.',
    executable_names: ['client32.exe', 'PCICL32.EXE'],
    network_artifacts: { ports: [5405, 1270, 1271, 1272] },
    registry_artifacts: ['HKLM\\SOFTWARE\\NetSupport Manager'],
    detection_guidance: 'client32.exe outside corporate deployment is near-certain malicious. Watch for GatherNetworkInfo.vbs in same directory.',
    mitre_techniques: ['T1219'],
    abuse_references: ['TA569', 'SocGholish', 'IcedID', 'Raspberry Robin'],
  },
  {
    name: 'PDQ Deploy',
    vendor: 'PDQ.com',
    description: 'Software deployment tool. Abused by ransomware operators for mass payload distribution post-compromise.',
    executable_names: ['PDQDeploy.exe', 'PDQDeployRunner.exe', 'PDQInventory.exe'],
    network_artifacts: { ports: [443] },
    detection_guidance: 'PDQ Deploy executing non-standard packages or from unexpected admin accounts = high risk.',
    mitre_techniques: ['T1072', 'T1219'],
    abuse_references: ['LockBit', 'Vice Society'],
  },
];

// ---------------------------------------------------------------------------
// LoFP — Known False Positives mapped to ATT&CK techniques
// Curated from Sigma rule FP sections + community experience
// ---------------------------------------------------------------------------

export const SEED_LOFP: LoFPEntry[] = [
  // T1059.001 — PowerShell
  { id: 'lofp-T1059.001-sccm', technique_id: 'T1059.001', process_name: 'CcmExec.exe',
    command_pattern: 'powershell.exe -ExecutionPolicy * -Command *',
    description: 'SCCM client agent executing PowerShell scripts for software deployment and compliance checks.',
    suppression_logic: 'InitiatingProcessFileName =~ "CcmExec.exe" or InitiatingProcessFileName =~ "ccmsetup.exe"',
    confidence: 'confirmed' },
  { id: 'lofp-T1059.001-defender', technique_id: 'T1059.001', process_name: 'MsMpEng.exe',
    command_pattern: 'powershell.exe * Get-MpPreference *',
    description: 'Windows Defender invoking PowerShell for threat remediation and configuration.',
    suppression_logic: 'InitiatingProcessFileName =~ "MsMpEng.exe"',
    confidence: 'confirmed' },
  { id: 'lofp-T1059.001-dsc', technique_id: 'T1059.001', process_name: 'MonAgentCore.exe',
    command_pattern: 'powershell.exe * Desired State Configuration *',
    description: 'Azure Automation DSC agent applying configurations via PowerShell.',
    suppression_logic: 'InitiatingProcessFileName =~ "MonAgentCore.exe" or ProcessCommandLine has "DSC"',
    confidence: 'confirmed' },
  { id: 'lofp-T1059.001-intune', technique_id: 'T1059.001', process_name: 'IntuneManagementExtension.exe',
    command_pattern: 'powershell.exe -executionpolicy bypass *',
    description: 'Microsoft Intune deploying PowerShell scripts to managed endpoints.',
    suppression_logic: 'InitiatingProcessFileName =~ "IntuneManagementExtension.exe"',
    confidence: 'confirmed' },

  // T1003.001 — LSASS Memory
  { id: 'lofp-T1003.001-defender', technique_id: 'T1003.001', process_name: 'MsMpEng.exe',
    description: 'Windows Defender antimalware scanning LSASS process memory for credential theft indicators.',
    suppression_logic: 'InitiatingProcessFileName =~ "MsMpEng.exe"',
    confidence: 'confirmed' },
  { id: 'lofp-T1003.001-crowdstrike', technique_id: 'T1003.001', process_name: 'CSFalconService.exe',
    description: 'CrowdStrike Falcon sensor monitoring LSASS for credential dumping attempts.',
    suppression_logic: 'InitiatingProcessFileName in~ ("CSFalconService.exe", "CSFalconContainer.exe")',
    confidence: 'confirmed' },
  { id: 'lofp-T1003.001-sentinelone', technique_id: 'T1003.001', process_name: 'SentinelAgent.exe',
    description: 'SentinelOne agent accessing LSASS for behavioral monitoring.',
    suppression_logic: 'InitiatingProcessFileName in~ ("SentinelAgent.exe", "SentinelServiceHost.exe")',
    confidence: 'confirmed' },

  // T1053.005 — Scheduled Task
  { id: 'lofp-T1053.005-sccm', technique_id: 'T1053.005', process_name: 'CcmExec.exe',
    command_pattern: 'schtasks /create * /tn *Configuration Manager*',
    description: 'SCCM creating scheduled tasks for software deployment and inventory cycles.',
    suppression_logic: 'InitiatingProcessFileName =~ "CcmExec.exe" or AccountName endswith "$"',
    confidence: 'confirmed' },
  { id: 'lofp-T1053.005-tiworker', technique_id: 'T1053.005', process_name: 'TiWorker.exe',
    description: 'Windows Update Trusted Installer creating scheduled maintenance tasks.',
    suppression_logic: 'InitiatingProcessFileName =~ "TiWorker.exe"',
    confidence: 'confirmed' },
  { id: 'lofp-T1053.005-defender', technique_id: 'T1053.005', process_name: 'MsMpEng.exe',
    description: 'Windows Defender creating scheduled scan tasks.',
    suppression_logic: 'InitiatingProcessFileName =~ "MsMpEng.exe" or ProcessCommandLine has "Windows Defender"',
    confidence: 'confirmed' },

  // T1218.011 — Rundll32
  { id: 'lofp-T1218.011-shell32', technique_id: 'T1218.011', process_name: 'rundll32.exe',
    command_pattern: 'rundll32.exe shell32.dll,Control_RunDLL',
    description: 'Legitimate Control Panel item execution via rundll32 and shell32.dll.',
    suppression_logic: 'ProcessCommandLine has "shell32.dll,Control_RunDLL"',
    confidence: 'confirmed' },
  { id: 'lofp-T1218.011-printui', technique_id: 'T1218.011', process_name: 'rundll32.exe',
    command_pattern: 'rundll32.exe printui.dll,PrintUIEntry',
    description: 'Printer management operations through rundll32.',
    suppression_logic: 'ProcessCommandLine has "printui.dll,PrintUIEntry"',
    confidence: 'confirmed' },

  // T1562.001 — Disable or Modify Tools (BYOVD)
  { id: 'lofp-T1562.001-legit-drivers', technique_id: 'T1562.001', process_name: 'System',
    description: 'Legitimate driver loading during Windows boot or hardware installation. Focus on driver hashes, not just driver load events.',
    suppression_logic: 'Cross-reference driver hash against LOLDrivers database; allow if hash NOT in known-vulnerable list',
    confidence: 'confirmed' },

  // T1021.001 — RDP
  { id: 'lofp-T1021.001-admin', technique_id: 'T1021.001',
    description: 'IT administrators using RDP for legitimate server management. Filter by known admin accounts and approved jump hosts.',
    suppression_logic: 'AccountName in (approved_admin_list) and RemoteIP in (approved_jump_hosts)',
    confidence: 'likely' },

  // T1484.001 — GPO Modification
  { id: 'lofp-T1484.001-gpo-admin', technique_id: 'T1484.001', process_name: 'mmc.exe',
    command_pattern: 'mmc.exe * gpmc.msc *',
    description: 'Group Policy Management Console used by domain admins to legitimately modify GPOs.',
    suppression_logic: 'InitiatingProcessFileName =~ "mmc.exe" and AccountName in (domain_admin_list)',
    confidence: 'confirmed' },

  // T1485 — Data Destruction
  { id: 'lofp-T1485-ccleaner', technique_id: 'T1485', process_name: 'CCleaner64.exe',
    description: 'CCleaner performing legitimate file cleanup and disk wiping operations.',
    suppression_logic: 'InitiatingProcessFileName in~ ("CCleaner.exe", "CCleaner64.exe")',
    confidence: 'confirmed' },

  // T1486 — Data Encrypted for Impact
  { id: 'lofp-T1486-backup-encrypt', technique_id: 'T1486',
    description: 'Enterprise backup solutions (Veeam, Commvault) encrypting backups as part of normal operations.',
    suppression_logic: 'InitiatingProcessFileName in~ ("VeeamAgent.exe", "CvMountd.exe", "Galaxy.exe")',
    confidence: 'likely' },

  // T1087.002 — Domain Account Discovery
  { id: 'lofp-T1087.002-admin-tools', technique_id: 'T1087.002', process_name: 'dsquery.exe',
    description: 'IT admins using RSAT tools (dsquery, Get-ADUser) for legitimate Active Directory management.',
    suppression_logic: 'AccountName in (domain_admin_list) and InitiatingProcessFileName in~ ("powershell.exe", "dsquery.exe")',
    confidence: 'likely' },

  // T1574.001/002 — DLL Search Order Hijacking / Sideloading
  { id: 'lofp-T1574-legit-install', technique_id: 'T1574.001',
    description: 'Legitimate software installations placing DLLs in application directories. Focus on unsigned DLLs in signed application directories.',
    suppression_logic: 'Filter by DLL signature status; alert only on unsigned DLLs loaded by signed executables',
    confidence: 'likely' },
];

// ---------------------------------------------------------------------------
// WADComs — Windows/AD offensive commands
// Source: wadcoms.github.io
// ---------------------------------------------------------------------------

export const SEED_WADCOMS: WADComEntry[] = [
  {
    name: 'Impacket-SecretsDump',
    description: 'Dump domain credentials remotely using DCSync or SAM/SYSTEM hive extraction via Impacket.',
    command: 'secretsdump.py DOMAIN/user:pass@DC_IP -just-dc-ntlm',
    category: 'credential',
    os: 'Cross',
    tools_required: ['impacket'],
    mitre_techniques: ['T1003.006', 'T1003.002', 'T1003.003'],
  },
  {
    name: 'Impacket-PSExec',
    description: 'Remote command execution via SMB service creation (Impacket).',
    command: 'psexec.py DOMAIN/user:pass@TARGET_IP',
    category: 'lateral',
    os: 'Cross',
    tools_required: ['impacket'],
    mitre_techniques: ['T1021.002', 'T1569.002'],
  },
  {
    name: 'BloodHound-SharpHound',
    description: 'Active Directory enumeration and attack path mapping.',
    command: 'SharpHound.exe -c All --domain DOMAIN',
    category: 'recon',
    os: 'Windows',
    tools_required: ['SharpHound'],
    mitre_techniques: ['T1087.002', 'T1069.002', 'T1482'],
  },
  {
    name: 'Rubeus-Kerberoast',
    description: 'Extract TGS tickets for offline password cracking of service accounts.',
    command: 'Rubeus.exe kerberoast /outfile:hashes.txt',
    category: 'credential',
    os: 'Windows',
    tools_required: ['Rubeus'],
    mitre_techniques: ['T1558.003'],
  },
  {
    name: 'Rubeus-ASREPRoast',
    description: 'Target accounts with Kerberos pre-authentication disabled.',
    command: 'Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt',
    category: 'credential',
    os: 'Windows',
    tools_required: ['Rubeus'],
    mitre_techniques: ['T1558.004'],
  },
  {
    name: 'Mimikatz-DCSync',
    description: 'Replicate domain controller to extract all credentials using Directory Replication Service.',
    command: 'lsadump::dcsync /domain:DOMAIN /user:krbtgt',
    category: 'credential',
    os: 'Windows',
    tools_required: ['mimikatz'],
    mitre_techniques: ['T1003.006'],
  },
  {
    name: 'CrackMapExec-SMB',
    description: 'Mass credential validation and command execution via SMB.',
    command: 'crackmapexec smb TARGET -u USER -p PASS --exec-method smbexec -x "COMMAND"',
    category: 'lateral',
    os: 'Cross',
    tools_required: ['crackmapexec'],
    mitre_techniques: ['T1021.002', 'T1110.001'],
  },
  {
    name: 'PowerView-DomainTrust',
    description: 'Enumerate Active Directory domain trusts for lateral movement paths.',
    command: 'Get-DomainTrust -API | Get-DomainTrustMapping',
    category: 'recon',
    os: 'Windows',
    tools_required: ['PowerView'],
    mitre_techniques: ['T1482'],
  },
  {
    name: 'Certify-VulnTemplates',
    description: 'Find vulnerable AD CS certificate templates for privilege escalation.',
    command: 'Certify.exe find /vulnerable',
    category: 'recon',
    os: 'Windows',
    tools_required: ['Certify'],
    mitre_techniques: ['T1649'],
  },
  {
    name: 'Certipy-ESC1',
    description: 'Exploit misconfigured AD CS templates (ESC1) for domain admin escalation.',
    command: 'certipy req -u user@DOMAIN -p pass -ca CA-NAME -target CA-HOST -template VulnTemplate -upn admin@DOMAIN',
    category: 'credential',
    os: 'Cross',
    tools_required: ['certipy'],
    mitre_techniques: ['T1649'],
  },
];

// ---------------------------------------------------------------------------
// LOTS — Legitimate domains abused for C2/exfiltration
// Source: lots-project.com
// ---------------------------------------------------------------------------

export const SEED_LOTS: LOTSEntry[] = [
  { domain: 'pastebin.com', service_name: 'Pastebin', category: 'C2', description: 'Text paste site used to host C2 configs, exfil data, and malware payloads.', mitre_techniques: ['T1102.001', 'T1567.002'] },
  { domain: 'discord.com', service_name: 'Discord', category: 'C2', description: 'CDN and webhooks used for payload hosting and C2 communication.', mitre_techniques: ['T1102', 'T1567.002'] },
  { domain: 'cdn.discordapp.com', service_name: 'Discord CDN', category: 'file_hosting', description: 'Discord CDN for malware payload staging.', mitre_techniques: ['T1102.001'] },
  { domain: 'raw.githubusercontent.com', service_name: 'GitHub Raw', category: 'file_hosting', description: 'GitHub raw content for hosting malware and tools.', mitre_techniques: ['T1102.001', 'T1105'] },
  { domain: 'ngrok.io', service_name: 'ngrok', category: 'C2', description: 'Reverse tunnel service for C2 and exposing local services.', mitre_techniques: ['T1572', 'T1090'] },
  { domain: '*.trycloudflare.com', service_name: 'Cloudflare Tunnel', category: 'C2', description: 'Cloudflare quick tunnels abused to proxy C2 traffic through trusted infrastructure.', mitre_techniques: ['T1572', 'T1090'] },
  { domain: 'transfer.sh', service_name: 'transfer.sh', category: 'exfiltration', description: 'File sharing service for data exfiltration.', mitre_techniques: ['T1567.002'] },
  { domain: 'mega.nz', service_name: 'MEGA', category: 'exfiltration', description: 'Cloud storage abused for data exfiltration by ransomware groups.', mitre_techniques: ['T1567.002'] },
  { domain: 'anonfiles.com', service_name: 'AnonFiles', category: 'exfiltration', description: 'Anonymous file hosting for exfiltration and payload staging.', mitre_techniques: ['T1567.002'] },
  { domain: 'telegram.org', service_name: 'Telegram', category: 'C2', description: 'Telegram Bot API used for C2 communication and data exfiltration.', mitre_techniques: ['T1102', 'T1567'] },
  { domain: 'notion.so', service_name: 'Notion', category: 'C2', description: 'Notion API abused for C2 callbacks in APT campaigns.', mitre_techniques: ['T1102'] },
  { domain: 'slack.com', service_name: 'Slack', category: 'C2', description: 'Slack webhooks and APIs used for C2 communication.', mitre_techniques: ['T1102'] },
  { domain: 'onedrive.live.com', service_name: 'OneDrive', category: 'exfiltration', description: 'Microsoft OneDrive for data exfiltration.', mitre_techniques: ['T1567.002'] },
  { domain: 'dropbox.com', service_name: 'Dropbox', category: 'exfiltration', description: 'Dropbox used for payload staging and data exfiltration.', mitre_techniques: ['T1567.002', 'T1102'] },
];

// ---------------------------------------------------------------------------
// MalAPI — Windows APIs mapped to malware behavior
// Source: malapi.io
// ---------------------------------------------------------------------------

export const SEED_MALAPI: MalAPIEntry[] = [
  { api_name: 'VirtualAllocEx', description: 'Allocate memory in remote process virtual address space. Core API for process injection.', category: 'injection', mitre_techniques: ['T1055.001', 'T1055.002'], malware_families: ['Cobalt Strike', 'Metasploit', 'TrickBot'] },
  { api_name: 'WriteProcessMemory', description: 'Write data to remote process memory. Used with VirtualAllocEx for shellcode injection.', category: 'injection', mitre_techniques: ['T1055.001'], malware_families: ['Cobalt Strike', 'Emotet'] },
  { api_name: 'CreateRemoteThread', description: 'Create thread in remote process. Classic injection execution trigger.', category: 'injection', mitre_techniques: ['T1055.001'], malware_families: ['Cobalt Strike', 'AgentTesla'] },
  { api_name: 'NtQueueApcThread', description: 'Queue APC to target thread. Used for APC injection / early bird injection.', category: 'injection', mitre_techniques: ['T1055.004'], malware_families: ['TrickBot', 'DoppelPaymer'] },
  { api_name: 'NtMapViewOfSection', description: 'Map section of shared memory into process. Used for process hollowing.', category: 'injection', mitre_techniques: ['T1055.012'], malware_families: ['Emotet', 'Dridex'] },
  { api_name: 'CreateFile', description: 'Open or create file/device. When targeting \\\\.\\PhysicalDrive0, indicates raw disk access (MBR wipe).', category: 'destruction', mitre_techniques: ['T1561.002'], malware_families: ['NotPetya', 'WhisperGate', 'HermeticWiper'], detection_notes: 'Alert on CreateFile calls to PhysicalDrive or HarddiskVolume targets from non-system processes.' },
  { api_name: 'DeviceIoControl', description: 'Send control code to device driver. Used by BYOVD tools to communicate with vulnerable drivers.', category: 'evasion', mitre_techniques: ['T1068', 'T1562.001'], malware_families: ['BlackByte', 'AvosLocker'], detection_notes: 'Monitor IOCTL calls to known vulnerable driver device names.' },
  { api_name: 'SetWindowsHookEx', description: 'Install application-defined hook procedure. Used for keylogging and DLL injection.', category: 'collection', mitre_techniques: ['T1056.001', 'T1055.001'], malware_families: ['AgentTesla', 'Snake Keylogger'] },
  { api_name: 'MiniDumpWriteDump', description: 'Write minidump of process. Primary API for LSASS credential dumping.', category: 'credential', mitre_techniques: ['T1003.001'], malware_families: ['Mimikatz', 'custom tools'], detection_notes: 'Any non-WerFault process calling MiniDumpWriteDump on lsass.exe is credential theft.' },
  { api_name: 'CryptEncrypt', description: 'Encrypt data using CryptoAPI. Used by ransomware for file encryption.', category: 'impact', mitre_techniques: ['T1486'], malware_families: ['WannaCry', 'REvil', 'Dharma'] },
  { api_name: 'AmsiScanBuffer', description: 'AMSI scan interface. Patching this API is the primary AMSI bypass technique.', category: 'evasion', mitre_techniques: ['T1562.001'], malware_families: ['PowerShell-based malware'], detection_notes: 'Monitor for amsi.dll memory patches — bytes 0x80, 0x07, 0x00, 0x80 written to AmsiScanBuffer.' },
  { api_name: 'NtUnmapViewOfSection', description: 'Unmap memory section. Used in process hollowing to hollow out legitimate process.', category: 'injection', mitre_techniques: ['T1055.012'], malware_families: ['Formbook', 'Remcos'] },
];
