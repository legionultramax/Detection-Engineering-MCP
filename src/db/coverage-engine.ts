// Coverage Engine Database Schema
// Maps telemetry (Event IDs, log sources) → MITRE ATT&CK Data Components → Techniques
// Provides the "EventID → DataComponent" mapping that MITRE doesn't give you natively.
//
// Tables:
//   telemetry_mappings   — Pre-populated: EventID → MITRE Data Source + Data Component + fields
//   coverage_sessions    — User sessions for coverage assessments
//   session_telemetry    — Logs ingested per session (parsed + mapped)
//   session_coverage     — Per-technique coverage results per session

import { getDb, runQuery, runStatement, runBulkStatement, saveDb } from './connection.js';

// ────────────────────────────────────────────────────────────────────────────
// Schema Initialization
// ────────────────────────────────────────────────────────────────────────────

export function initCoverageEngineSchema(): void {
  const db = getDb();

  db.exec(`
    -- Pre-populated mapping: EventID → MITRE Data Source + Component
    -- This is the intellectual core of the coverage engine.
    CREATE TABLE IF NOT EXISTS telemetry_mappings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_source TEXT NOT NULL,
      event_id TEXT NOT NULL,
      event_name TEXT,
      mitre_data_source TEXT NOT NULL,
      mitre_data_component TEXT NOT NULL,
      fields_provided TEXT NOT NULL,
      fields_critical TEXT NOT NULL,
      detection_quality TEXT DEFAULT 'high',
      notes TEXT,
      UNIQUE(event_source, event_id, mitre_data_component)
    );

    CREATE INDEX IF NOT EXISTS idx_tmap_source_eid ON telemetry_mappings(event_source, event_id);
    CREATE INDEX IF NOT EXISTS idx_tmap_ds ON telemetry_mappings(mitre_data_source);
    CREATE INDEX IF NOT EXISTS idx_tmap_dc ON telemetry_mappings(mitre_data_component);

    -- Coverage assessment sessions
    CREATE TABLE IF NOT EXISTS coverage_sessions (
      session_id TEXT PRIMARY KEY,
      name TEXT,
      description TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      total_techniques_full INTEGER DEFAULT 0,
      total_techniques_partial INTEGER DEFAULT 0,
      total_techniques_gap INTEGER DEFAULT 0,
      total_techniques_detectable INTEGER DEFAULT 0
    );

    -- Telemetry ingested per session
    CREATE TABLE IF NOT EXISTS session_telemetry (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      event_source TEXT NOT NULL,
      event_id TEXT NOT NULL,
      sample_log TEXT,
      parsed_fields TEXT,
      mapped_data_source TEXT,
      mapped_data_component TEXT,
      field_coverage_pct REAL DEFAULT 0,
      quality_tier TEXT DEFAULT 'unknown',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (session_id) REFERENCES coverage_sessions(session_id)
    );

    CREATE INDEX IF NOT EXISTS idx_sestel_session ON session_telemetry(session_id);

    -- Per-technique coverage results per session
    CREATE TABLE IF NOT EXISTS session_coverage (
      session_id TEXT NOT NULL,
      technique_id TEXT NOT NULL,
      technique_name TEXT,
      tactic TEXT,
      coverage_status TEXT NOT NULL,
      data_sources_present TEXT,
      data_sources_missing TEXT,
      detection_rules_available INTEGER DEFAULT 0,
      field_quality TEXT DEFAULT 'unknown',
      remediation TEXT,
      PRIMARY KEY (session_id, technique_id)
    );

    CREATE INDEX IF NOT EXISTS idx_sescov_session ON session_coverage(session_id);
    CREATE INDEX IF NOT EXISTS idx_sescov_status ON session_coverage(coverage_status);
  `);

  // Seed the telemetry mappings if table is empty
  const count = runQuery<{ cnt: number }>('SELECT COUNT(*) as cnt FROM telemetry_mappings');
  if (count[0]?.cnt === 0) {
    seedTelemetryMappings();
  }

  console.error('[db] Coverage engine schema initialized');
}

// ────────────────────────────────────────────────────────────────────────────
// Telemetry Mapping Seed Data
// ────────────────────────────────────────────────────────────────────────────
// This is the mapping MITRE doesn't provide: EventID → Data Source + Component
// Fields marked with * in comments are critical — detection degrades severely without them.

function seedTelemetryMappings(): void {
  const db = getDb();
  db.exec('BEGIN TRANSACTION');

  try {
    const mappings: Array<{
      event_source: string;
      event_id: string;
      event_name: string;
      mitre_data_source: string;
      mitre_data_component: string;
      fields_provided: string[];
      fields_critical: string[];
      detection_quality: string;
      notes?: string;
    }> = [
      // ── Windows Security Log ────────────────────────────────────────
      {
        event_source: 'windows_security',
        event_id: '4688',
        event_name: 'Process Creation',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Creation',
        fields_provided: ['NewProcessName', 'CommandLine', 'ParentProcessName', 'SubjectUserName', 'SubjectDomainName', 'TokenElevationType', 'ProcessId', 'NewProcessId', 'MandatoryLabel'],
        fields_critical: ['CommandLine', 'ParentProcessName', 'NewProcessName'],
        detection_quality: 'high',
        notes: 'CommandLine auditing must be enabled via GPO. Without it, detection quality drops to low.',
      },
      {
        event_source: 'windows_security',
        event_id: '4689',
        event_name: 'Process Termination',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Termination',
        fields_provided: ['ProcessName', 'SubjectUserName', 'ProcessId', 'Status'],
        fields_critical: ['ProcessName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4624',
        event_name: 'Successful Logon',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'LogonType', 'IpAddress', 'IpPort', 'WorkstationName', 'LogonProcessName', 'AuthenticationPackageName', 'LogonGuid', 'ElevatedToken'],
        fields_critical: ['LogonType', 'TargetUserName', 'IpAddress'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4625',
        event_name: 'Failed Logon',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'LogonType', 'IpAddress', 'IpPort', 'WorkstationName', 'FailureReason', 'Status', 'SubStatus'],
        fields_critical: ['LogonType', 'TargetUserName', 'FailureReason', 'IpAddress'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4648',
        event_name: 'Explicit Credential Logon',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'TargetUserName', 'TargetDomainName', 'TargetServerName', 'ProcessName'],
        fields_critical: ['TargetServerName', 'SubjectUserName', 'TargetUserName'],
        detection_quality: 'high',
        notes: 'Key for detecting runas / lateral movement with explicit credentials.',
      },
      {
        event_source: 'windows_security',
        event_id: '4672',
        event_name: 'Special Privileges Assigned',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Metadata',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'PrivilegeList'],
        fields_critical: ['SubjectUserName', 'PrivilegeList'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4698',
        event_name: 'Scheduled Task Created',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Creation',
        fields_provided: ['TaskName', 'TaskContent', 'SubjectUserName', 'SubjectDomainName'],
        fields_critical: ['TaskName', 'TaskContent'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4699',
        event_name: 'Scheduled Task Deleted',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Modification',
        fields_provided: ['TaskName', 'SubjectUserName'],
        fields_critical: ['TaskName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4700',
        event_name: 'Scheduled Task Enabled',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Modification',
        fields_provided: ['TaskName', 'SubjectUserName'],
        fields_critical: ['TaskName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4701',
        event_name: 'Scheduled Task Disabled',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Modification',
        fields_provided: ['TaskName', 'SubjectUserName'],
        fields_critical: ['TaskName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4702',
        event_name: 'Scheduled Task Updated',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Modification',
        fields_provided: ['TaskName', 'TaskContent', 'SubjectUserName'],
        fields_critical: ['TaskName', 'TaskContent'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4720',
        event_name: 'User Account Created',
        mitre_data_source: 'User Account',
        mitre_data_component: 'User Account Creation',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'SubjectUserName', 'SubjectDomainName', 'TargetSid'],
        fields_critical: ['TargetUserName', 'SubjectUserName'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4722',
        event_name: 'User Account Enabled',
        mitre_data_source: 'User Account',
        mitre_data_component: 'User Account Modification',
        fields_provided: ['TargetUserName', 'SubjectUserName'],
        fields_critical: ['TargetUserName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4724',
        event_name: 'Password Reset Attempt',
        mitre_data_source: 'User Account',
        mitre_data_component: 'User Account Modification',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'SubjectUserName'],
        fields_critical: ['TargetUserName', 'SubjectUserName'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4726',
        event_name: 'User Account Deleted',
        mitre_data_source: 'User Account',
        mitre_data_component: 'User Account Deletion',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'SubjectUserName'],
        fields_critical: ['TargetUserName', 'SubjectUserName'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4728',
        event_name: 'Member Added to Security-Enabled Global Group',
        mitre_data_source: 'Group',
        mitre_data_component: 'Group Modification',
        fields_provided: ['MemberName', 'MemberSid', 'TargetUserName', 'SubjectUserName'],
        fields_critical: ['MemberName', 'TargetUserName'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4732',
        event_name: 'Member Added to Security-Enabled Local Group',
        mitre_data_source: 'Group',
        mitre_data_component: 'Group Modification',
        fields_provided: ['MemberName', 'MemberSid', 'TargetUserName', 'SubjectUserName'],
        fields_critical: ['MemberName', 'TargetUserName'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4756',
        event_name: 'Member Added to Universal Security Group',
        mitre_data_source: 'Group',
        mitre_data_component: 'Group Modification',
        fields_provided: ['MemberName', 'MemberSid', 'TargetUserName', 'SubjectUserName'],
        fields_critical: ['MemberName', 'TargetUserName'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4768',
        event_name: 'Kerberos TGT Request',
        mitre_data_source: 'Active Directory',
        mitre_data_component: 'Active Directory Credential Request',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'ServiceName', 'TicketOptions', 'TicketEncryptionType', 'IpAddress', 'Status', 'PreAuthType'],
        fields_critical: ['TargetUserName', 'TicketEncryptionType', 'IpAddress'],
        detection_quality: 'high',
        notes: 'Encryption type 0x17 (RC4) = potential AS-REP roasting.',
      },
      {
        event_source: 'windows_security',
        event_id: '4769',
        event_name: 'Kerberos Service Ticket Request',
        mitre_data_source: 'Active Directory',
        mitre_data_component: 'Active Directory Credential Request',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'ServiceName', 'TicketOptions', 'TicketEncryptionType', 'IpAddress', 'Status'],
        fields_critical: ['ServiceName', 'TicketEncryptionType', 'IpAddress'],
        detection_quality: 'high',
        notes: 'Key for Kerberoasting detection (encryption type 0x17).',
      },
      {
        event_source: 'windows_security',
        event_id: '4771',
        event_name: 'Kerberos Pre-Authentication Failed',
        mitre_data_source: 'Active Directory',
        mitre_data_component: 'Active Directory Credential Request',
        fields_provided: ['TargetUserName', 'TargetSid', 'ServiceName', 'TicketOptions', 'FailureCode', 'IpAddress'],
        fields_critical: ['TargetUserName', 'FailureCode', 'IpAddress'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '5156',
        event_name: 'WFP Connection Allowed',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Connection Creation',
        fields_provided: ['Application', 'SourceAddress', 'SourcePort', 'DestAddress', 'DestPort', 'Protocol', 'Direction'],
        fields_critical: ['DestAddress', 'DestPort', 'Application'],
        detection_quality: 'medium',
        notes: 'Windows Filtering Platform. Less detail than Sysmon 3.',
      },
      {
        event_source: 'windows_security',
        event_id: '5157',
        event_name: 'WFP Connection Blocked',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Connection Creation',
        fields_provided: ['Application', 'SourceAddress', 'SourcePort', 'DestAddress', 'DestPort', 'Protocol', 'Direction'],
        fields_critical: ['DestAddress', 'DestPort', 'Application'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4104',
        event_name: 'PowerShell Script Block Logging',
        mitre_data_source: 'Script',
        mitre_data_component: 'Script Execution',
        fields_provided: ['ScriptBlockText', 'ScriptBlockId', 'Path', 'MessageNumber', 'MessageTotal'],
        fields_critical: ['ScriptBlockText'],
        detection_quality: 'high',
        notes: 'Requires PowerShell Script Block Logging GPO. Critical for deobfuscated command visibility.',
      },
      {
        event_source: 'windows_security',
        event_id: '4103',
        event_name: 'PowerShell Module Logging',
        mitre_data_source: 'Command',
        mitre_data_component: 'Command Execution',
        fields_provided: ['Payload', 'ContextInfo', 'UserData'],
        fields_critical: ['Payload'],
        detection_quality: 'high',
        notes: 'Requires Module Logging GPO.',
      },

      // ── Windows Security — Object Access / Shares / Policy ─────────
      {
        event_source: 'windows_security',
        event_id: '4634',
        event_name: 'Account Logoff',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Metadata',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'LogonType', 'TargetLogonId'],
        fields_critical: ['TargetUserName', 'LogonType'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4647',
        event_name: 'User Initiated Logoff',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Metadata',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'TargetLogonId'],
        fields_critical: ['TargetUserName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '4656',
        event_name: 'Handle to Object Requested',
        mitre_data_source: 'File',
        mitre_data_component: 'File Access',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'ObjectName', 'ObjectType', 'AccessMask', 'ProcessName', 'HandleId'],
        fields_critical: ['ObjectName', 'ObjectType', 'AccessMask', 'SubjectUserName'],
        detection_quality: 'high',
        notes: 'Requires object access auditing. Covers file, registry, and kernel objects.',
      },
      {
        event_source: 'windows_security',
        event_id: '4657',
        event_name: 'Registry Value Modified (Audit)',
        mitre_data_source: 'Windows Registry',
        mitre_data_component: 'Windows Registry Key Modification',
        fields_provided: ['SubjectUserName', 'ObjectName', 'ObjectValueName', 'OldValue', 'NewValue', 'OperationType'],
        fields_critical: ['ObjectName', 'ObjectValueName', 'NewValue'],
        detection_quality: 'high',
        notes: 'Requires registry auditing SACL.',
      },
      {
        event_source: 'windows_security',
        event_id: '4663',
        event_name: 'Object Access Attempt',
        mitre_data_source: 'File',
        mitre_data_component: 'File Access',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'ObjectName', 'ObjectType', 'AccessMask', 'ProcessName', 'HandleId', 'ResourceAttributes'],
        fields_critical: ['ObjectName', 'AccessMask', 'SubjectUserName', 'ProcessName'],
        detection_quality: 'high',
        notes: 'Key for detecting SAM/NTDS.dit access and sensitive file reads.',
      },
      {
        event_source: 'windows_security',
        event_id: '4670',
        event_name: 'Object Permissions Changed',
        mitre_data_source: 'File',
        mitre_data_component: 'File Modification',
        fields_provided: ['SubjectUserName', 'ObjectName', 'ObjectType', 'OldSd', 'NewSd', 'ProcessName'],
        fields_critical: ['ObjectName', 'SubjectUserName', 'NewSd'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4673',
        event_name: 'Privileged Service Called',
        mitre_data_source: 'Process',
        mitre_data_component: 'OS API Execution',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'Service', 'PrivilegeList', 'ProcessName'],
        fields_critical: ['PrivilegeList', 'ProcessName', 'SubjectUserName'],
        detection_quality: 'high',
        notes: 'Detects SeDebugPrivilege, SeTcbPrivilege usage.',
      },
      {
        event_source: 'windows_security',
        event_id: '4674',
        event_name: 'Privileged Object Operation',
        mitre_data_source: 'Process',
        mitre_data_component: 'OS API Execution',
        fields_provided: ['SubjectUserName', 'ObjectName', 'ObjectType', 'PrivilegeList', 'ProcessName', 'AccessMask'],
        fields_critical: ['ObjectName', 'PrivilegeList', 'ProcessName'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4697',
        event_name: 'Service Installed in System (Security)',
        mitre_data_source: 'Service',
        mitre_data_component: 'Service Creation',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'ServiceName', 'ServiceFileName', 'ServiceType', 'ServiceStartType', 'ServiceAccount'],
        fields_critical: ['ServiceName', 'ServiceFileName', 'SubjectUserName'],
        detection_quality: 'high',
        notes: 'Security log version of 7045. More reliable — does not require SCM logging.',
      },
      {
        event_source: 'windows_security',
        event_id: '4719',
        event_name: 'System Audit Policy Changed',
        mitre_data_source: 'Sensor Health',
        mitre_data_component: 'Host Status',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'CategoryId', 'SubcategoryId', 'AuditPolicyChanges'],
        fields_critical: ['SubjectUserName', 'AuditPolicyChanges', 'CategoryId'],
        detection_quality: 'high',
        notes: 'Critical — detects attackers disabling audit logging (T1562.002).',
      },
      {
        event_source: 'windows_security',
        event_id: '4738',
        event_name: 'User Account Changed',
        mitre_data_source: 'User Account',
        mitre_data_component: 'User Account Modification',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'SubjectUserName', 'UserAccountControl', 'PasswordLastSet', 'AllowedToDelegateTo'],
        fields_critical: ['TargetUserName', 'SubjectUserName', 'UserAccountControl'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4740',
        event_name: 'Account Locked Out',
        mitre_data_source: 'User Account',
        mitre_data_component: 'User Account Modification',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'SubjectUserName', 'TargetSid'],
        fields_critical: ['TargetUserName', 'SubjectUserName'],
        detection_quality: 'high',
        notes: 'Brute force / password spray indicator.',
      },
      {
        event_source: 'windows_security',
        event_id: '4741',
        event_name: 'Computer Account Created',
        mitre_data_source: 'Active Directory',
        mitre_data_component: 'Active Directory Object Creation',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'SubjectUserName', 'ServicePrincipalNames', 'SamAccountName'],
        fields_critical: ['TargetUserName', 'SubjectUserName'],
        detection_quality: 'high',
        notes: 'Key for detecting machine account abuse (resource-based constrained delegation attacks).',
      },
      {
        event_source: 'windows_security',
        event_id: '4742',
        event_name: 'Computer Account Changed',
        mitre_data_source: 'Active Directory',
        mitre_data_component: 'Active Directory Object Modification',
        fields_provided: ['TargetUserName', 'TargetDomainName', 'SubjectUserName', 'ServicePrincipalNames', 'AllowedToDelegateTo'],
        fields_critical: ['TargetUserName', 'SubjectUserName', 'AllowedToDelegateTo'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_security',
        event_id: '4776',
        event_name: 'NTLM Credential Validation',
        mitre_data_source: 'Active Directory',
        mitre_data_component: 'Active Directory Credential Request',
        fields_provided: ['TargetUserName', 'Workstation', 'Status', 'PackageName'],
        fields_critical: ['TargetUserName', 'Workstation', 'Status'],
        detection_quality: 'high',
        notes: 'NTLM authentication — key for pass-the-hash detection and NTLM relay.',
      },
      {
        event_source: 'windows_security',
        event_id: '4778',
        event_name: 'RDP Session Reconnected',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['AccountName', 'AccountDomain', 'LogonID', 'SessionName', 'ClientName', 'ClientAddress'],
        fields_critical: ['AccountName', 'ClientAddress', 'SessionName'],
        detection_quality: 'high',
        notes: 'RDP session reconnect — key for lateral movement tracking.',
      },
      {
        event_source: 'windows_security',
        event_id: '4779',
        event_name: 'RDP Session Disconnected',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Metadata',
        fields_provided: ['AccountName', 'AccountDomain', 'LogonID', 'SessionName', 'ClientName', 'ClientAddress'],
        fields_critical: ['AccountName', 'ClientAddress'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_security',
        event_id: '5140',
        event_name: 'Network Share Accessed',
        mitre_data_source: 'Network Share',
        mitre_data_component: 'Network Share Access',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'ShareName', 'ShareLocalPath', 'IpAddress', 'IpPort', 'AccessMask'],
        fields_critical: ['ShareName', 'SubjectUserName', 'IpAddress'],
        detection_quality: 'high',
        notes: 'Key for detecting C$/ADMIN$/IPC$ lateral movement.',
      },
      {
        event_source: 'windows_security',
        event_id: '5145',
        event_name: 'Network Share Object Checked',
        mitre_data_source: 'Network Share',
        mitre_data_component: 'Network Share Access',
        fields_provided: ['SubjectUserName', 'SubjectDomainName', 'ShareName', 'RelativeTargetName', 'IpAddress', 'AccessMask', 'AccessList'],
        fields_critical: ['ShareName', 'RelativeTargetName', 'SubjectUserName', 'IpAddress'],
        detection_quality: 'high',
        notes: 'More granular than 5140 — shows exact file accessed within share.',
      },

      // ── Windows System Log ──────────────────────────────────────────
      {
        event_source: 'windows_system',
        event_id: '7045',
        event_name: 'Service Installed',
        mitre_data_source: 'Service',
        mitre_data_component: 'Service Creation',
        fields_provided: ['ServiceName', 'ImagePath', 'ServiceType', 'StartType', 'AccountName'],
        fields_critical: ['ServiceName', 'ImagePath', 'ServiceType'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_system',
        event_id: '7040',
        event_name: 'Service Start Type Changed',
        mitre_data_source: 'Service',
        mitre_data_component: 'Service Modification',
        fields_provided: ['ServiceName', 'StartType'],
        fields_critical: ['ServiceName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_system',
        event_id: '7036',
        event_name: 'Service Start/Stop',
        mitre_data_source: 'Service',
        mitre_data_component: 'Service Metadata',
        fields_provided: ['ServiceName', 'State'],
        fields_critical: ['ServiceName'],
        detection_quality: 'low',
      },
      {
        event_source: 'windows_system',
        event_id: '1001',
        event_name: 'Windows Error Reporting',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Metadata',
        fields_provided: ['EventType', 'P1', 'P2', 'P3', 'P4', 'P5'],
        fields_critical: ['EventType'],
        detection_quality: 'low',
        notes: 'Application crash data. Can indicate exploitation attempts.',
      },

      // ── Windows Application Log ─────────────────────────────────────
      {
        event_source: 'windows_application',
        event_id: '1033',
        event_name: 'Application Installed',
        mitre_data_source: 'Application Log',
        mitre_data_component: 'Application Log Content',
        fields_provided: ['ProductName', 'ProductVersion', 'Manufacturer', 'Language'],
        fields_critical: ['ProductName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_application',
        event_id: '1034',
        event_name: 'Application Removed',
        mitre_data_source: 'Application Log',
        mitre_data_component: 'Application Log Content',
        fields_provided: ['ProductName', 'ProductVersion', 'Manufacturer'],
        fields_critical: ['ProductName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_application',
        event_id: '11707',
        event_name: 'MSI Install Succeeded',
        mitre_data_source: 'Application Log',
        mitre_data_component: 'Application Log Content',
        fields_provided: ['ProductName', 'ProductVersion'],
        fields_critical: ['ProductName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_application',
        event_id: '11708',
        event_name: 'MSI Install Failed',
        mitre_data_source: 'Application Log',
        mitre_data_component: 'Application Log Content',
        fields_provided: ['ProductName', 'ProductVersion'],
        fields_critical: ['ProductName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_application',
        event_id: '1000',
        event_name: 'Application Error',
        mitre_data_source: 'Application Log',
        mitre_data_component: 'Application Log Content',
        fields_provided: ['FaultingApplicationName', 'FaultingModuleName', 'ExceptionCode', 'FaultingApplicationPath'],
        fields_critical: ['FaultingApplicationName', 'ExceptionCode'],
        detection_quality: 'low',
        notes: 'Crash events can indicate exploitation. ExceptionCode 0xC0000005 = access violation.',
      },
      {
        event_source: 'windows_application',
        event_id: '1002',
        event_name: 'Application Hang',
        mitre_data_source: 'Application Log',
        mitre_data_component: 'Application Log Content',
        fields_provided: ['ApplicationName', 'ApplicationVersion', 'ApplicationTimestamp'],
        fields_critical: ['ApplicationName'],
        detection_quality: 'low',
      },

      // ── RDP / Terminal Services ──────────────────────────────────────
      {
        event_source: 'windows_rdp_local',
        event_id: '21',
        event_name: 'RDP Session Logon Succeeded',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['User', 'SessionID', 'Source Network Address'],
        fields_critical: ['User', 'Source Network Address'],
        detection_quality: 'high',
        notes: 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational. Gold standard for RDP tracking.',
      },
      {
        event_source: 'windows_rdp_local',
        event_id: '22',
        event_name: 'RDP Shell Start',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['User', 'SessionID', 'Source Network Address'],
        fields_critical: ['User', 'Source Network Address'],
        detection_quality: 'high',
        notes: 'Shell (explorer.exe) started for RDP session.',
      },
      {
        event_source: 'windows_rdp_local',
        event_id: '23',
        event_name: 'RDP Session Logoff',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Metadata',
        fields_provided: ['User', 'SessionID'],
        fields_critical: ['User'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_rdp_local',
        event_id: '24',
        event_name: 'RDP Session Disconnected',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Metadata',
        fields_provided: ['User', 'SessionID', 'Source Network Address'],
        fields_critical: ['User', 'Source Network Address'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_rdp_local',
        event_id: '25',
        event_name: 'RDP Session Reconnection',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['User', 'SessionID', 'Source Network Address'],
        fields_critical: ['User', 'Source Network Address'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_rdp_remote',
        event_id: '1149',
        event_name: 'RDP User Authentication Succeeded',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['User', 'Domain', 'Source Network Address'],
        fields_critical: ['User', 'Source Network Address'],
        detection_quality: 'high',
        notes: 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational. First event in RDP chain — appears BEFORE 4624.',
      },
      {
        event_source: 'windows_rdp_remote',
        event_id: '261',
        event_name: 'RDP Listener Received Connection',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Connection Creation',
        fields_provided: ['ClientIP'],
        fields_critical: ['ClientIP'],
        detection_quality: 'medium',
        notes: 'Microsoft-Windows-TerminalServices-RemoteConnectionManager. Shows inbound RDP connections.',
      },
      {
        event_source: 'windows_rdp_gateway',
        event_id: '302',
        event_name: 'RDP Gateway User Connected',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['User', 'ClientIP', 'Resource'],
        fields_critical: ['User', 'ClientIP'],
        detection_quality: 'high',
        notes: 'Microsoft-Windows-TerminalServices-Gateway. RD Gateway connection.',
      },
      {
        event_source: 'windows_rdp_gateway',
        event_id: '303',
        event_name: 'RDP Gateway User Disconnected',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Metadata',
        fields_provided: ['User', 'ClientIP', 'Resource'],
        fields_critical: ['User', 'ClientIP'],
        detection_quality: 'medium',
      },

      // ── PowerShell Operational (extended) ────────────────────────────
      {
        event_source: 'windows_powershell',
        event_id: '400',
        event_name: 'PowerShell Engine Started',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Creation',
        fields_provided: ['EngineVersion', 'HostName', 'HostVersion', 'HostApplication', 'RunspaceId'],
        fields_critical: ['HostApplication'],
        detection_quality: 'medium',
        notes: 'Windows PowerShell log. Shows what launched PS — useful for fileless detection.',
      },
      {
        event_source: 'windows_powershell',
        event_id: '403',
        event_name: 'PowerShell Engine Stopped',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Termination',
        fields_provided: ['EngineVersion', 'HostName', 'HostVersion', 'HostApplication', 'RunspaceId'],
        fields_critical: ['HostApplication'],
        detection_quality: 'low',
      },
      {
        event_source: 'windows_powershell',
        event_id: '600',
        event_name: 'PowerShell Provider Started',
        mitre_data_source: 'Command',
        mitre_data_component: 'Command Execution',
        fields_provided: ['ProviderName', 'HostName', 'HostApplication'],
        fields_critical: ['ProviderName', 'HostApplication'],
        detection_quality: 'medium',
        notes: 'Shows which PS providers loaded (FileSystem, Registry, WSMan, etc.).',
      },
      {
        event_source: 'windows_powershell_operational',
        event_id: '4105',
        event_name: 'Script Block Invocation Start',
        mitre_data_source: 'Script',
        mitre_data_component: 'Script Execution',
        fields_provided: ['ScriptBlockId', 'RunspaceId'],
        fields_critical: ['ScriptBlockId'],
        detection_quality: 'low',
        notes: 'Microsoft-Windows-PowerShell/Operational. Companion to 4104.',
      },
      {
        event_source: 'windows_powershell_operational',
        event_id: '4106',
        event_name: 'Script Block Invocation Complete',
        mitre_data_source: 'Script',
        mitre_data_component: 'Script Execution',
        fields_provided: ['ScriptBlockId', 'RunspaceId'],
        fields_critical: ['ScriptBlockId'],
        detection_quality: 'low',
      },
      {
        event_source: 'windows_powershell_operational',
        event_id: '53504',
        event_name: 'PowerShell Named Pipe Connected',
        mitre_data_source: 'Named Pipe',
        mitre_data_component: 'Named Pipe Metadata',
        fields_provided: ['AppDomain'],
        fields_critical: ['AppDomain'],
        detection_quality: 'medium',
        notes: 'Detects PowerShell Remoting / Enter-PSSession connections.',
      },

      // ── Windows Defender (Antimalware) ───────────────────────────────
      {
        event_source: 'windows_defender',
        event_id: '1006',
        event_name: 'Malware or PUA Detected',
        mitre_data_source: 'Sensor Health',
        mitre_data_component: 'Host Status',
        fields_provided: ['ThreatName', 'Severity', 'Path', 'ProcessName', 'User', 'ActionTaken'],
        fields_critical: ['ThreatName', 'Path', 'ActionTaken'],
        detection_quality: 'high',
        notes: 'Microsoft-Windows-Windows Defender/Operational.',
      },
      {
        event_source: 'windows_defender',
        event_id: '1116',
        event_name: 'Malware Detection (Real-time)',
        mitre_data_source: 'Sensor Health',
        mitre_data_component: 'Host Status',
        fields_provided: ['ThreatName', 'ThreatID', 'Severity', 'Category', 'Path', 'ProcessName', 'DetectionUser', 'FWLink'],
        fields_critical: ['ThreatName', 'Path', 'ProcessName', 'Severity'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_defender',
        event_id: '1117',
        event_name: 'Malware Action Taken',
        mitre_data_source: 'Sensor Health',
        mitre_data_component: 'Host Status',
        fields_provided: ['ThreatName', 'ThreatID', 'Severity', 'Path', 'Action', 'Error'],
        fields_critical: ['ThreatName', 'Action', 'Path'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_defender',
        event_id: '5001',
        event_name: 'Real-Time Protection Disabled',
        mitre_data_source: 'Sensor Health',
        mitre_data_component: 'Host Status',
        fields_provided: ['Product Version'],
        fields_critical: [],
        detection_quality: 'high',
        notes: 'Critical — defense evasion indicator (T1562.001).',
      },
      {
        event_source: 'windows_defender',
        event_id: '5010',
        event_name: 'Scanning for Malware Disabled',
        mitre_data_source: 'Sensor Health',
        mitre_data_component: 'Host Status',
        fields_provided: ['Product Version'],
        fields_critical: [],
        detection_quality: 'high',
        notes: 'Defense evasion — antimalware scanning disabled.',
      },
      {
        event_source: 'windows_defender',
        event_id: '1121',
        event_name: 'ASR Rule Triggered',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Creation',
        fields_provided: ['RuleId', 'DetectionUser', 'ProcessName', 'Path', 'TargetCommandLine'],
        fields_critical: ['RuleId', 'ProcessName', 'Path'],
        detection_quality: 'high',
        notes: 'Attack Surface Reduction rules — strong signal for Office macro abuse, credential theft, etc.',
      },

      // ── Windows Firewall ─────────────────────────────────────────────
      {
        event_source: 'windows_firewall',
        event_id: '2003',
        event_name: 'Firewall Rule Added',
        mitre_data_source: 'Firewall',
        mitre_data_component: 'Firewall Rule Modification',
        fields_provided: ['RuleId', 'RuleName', 'ModifyingUser', 'ModifyingApplication', 'Direction', 'Protocol', 'LocalPort', 'RemotePort', 'Action'],
        fields_critical: ['RuleName', 'ModifyingApplication', 'Action'],
        detection_quality: 'high',
        notes: 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall. Key for T1562.004.',
      },
      {
        event_source: 'windows_firewall',
        event_id: '2004',
        event_name: 'Firewall Rule Added (Exception)',
        mitre_data_source: 'Firewall',
        mitre_data_component: 'Firewall Rule Modification',
        fields_provided: ['RuleId', 'RuleName', 'ApplicationPath', 'Direction', 'Protocol', 'LocalPort'],
        fields_critical: ['RuleName', 'ApplicationPath'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_firewall',
        event_id: '2005',
        event_name: 'Firewall Rule Modified',
        mitre_data_source: 'Firewall',
        mitre_data_component: 'Firewall Rule Modification',
        fields_provided: ['RuleId', 'RuleName', 'ModifyingUser', 'ModifyingApplication'],
        fields_critical: ['RuleName', 'ModifyingApplication'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_firewall',
        event_id: '2006',
        event_name: 'Firewall Rule Deleted',
        mitre_data_source: 'Firewall',
        mitre_data_component: 'Firewall Rule Modification',
        fields_provided: ['RuleId', 'RuleName', 'ModifyingUser'],
        fields_critical: ['RuleName', 'ModifyingUser'],
        detection_quality: 'high',
      },

      // ── Task Scheduler Operational ───────────────────────────────────
      {
        event_source: 'windows_taskscheduler',
        event_id: '106',
        event_name: 'Task Registered',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Creation',
        fields_provided: ['TaskName', 'UserContext'],
        fields_critical: ['TaskName', 'UserContext'],
        detection_quality: 'high',
        notes: 'Microsoft-Windows-TaskScheduler/Operational. Complement to Security 4698.',
      },
      {
        event_source: 'windows_taskscheduler',
        event_id: '140',
        event_name: 'Task Updated',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Modification',
        fields_provided: ['TaskName', 'UserContext'],
        fields_critical: ['TaskName', 'UserContext'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_taskscheduler',
        event_id: '141',
        event_name: 'Task Removed',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Modification',
        fields_provided: ['TaskName', 'UserContext'],
        fields_critical: ['TaskName', 'UserContext'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_taskscheduler',
        event_id: '200',
        event_name: 'Task Action Started',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Metadata',
        fields_provided: ['TaskName', 'ActionName', 'TaskInstanceId'],
        fields_critical: ['TaskName', 'ActionName'],
        detection_quality: 'high',
        notes: 'Shows actual execution — pairs with 201 for duration analysis.',
      },
      {
        event_source: 'windows_taskscheduler',
        event_id: '201',
        event_name: 'Task Action Completed',
        mitre_data_source: 'Scheduled Job',
        mitre_data_component: 'Scheduled Job Metadata',
        fields_provided: ['TaskName', 'ActionName', 'TaskInstanceId', 'ResultCode'],
        fields_critical: ['TaskName', 'ResultCode'],
        detection_quality: 'medium',
      },

      // ── BITS Client ──────────────────────────────────────────────────
      {
        event_source: 'windows_bits',
        event_id: '59',
        event_name: 'BITS Transfer Start',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Traffic Content',
        fields_provided: ['jobTitle', 'jobId', 'url', 'fileTime', 'fileLength', 'User'],
        fields_critical: ['url', 'jobTitle', 'User'],
        detection_quality: 'high',
        notes: 'Microsoft-Windows-Bits-Client/Operational. Key for detecting BITS abuse (T1197).',
      },
      {
        event_source: 'windows_bits',
        event_id: '60',
        event_name: 'BITS Transfer Complete',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Traffic Content',
        fields_provided: ['jobTitle', 'jobId', 'url', 'fileTime', 'fileLength', 'peerName', 'bytesTotal', 'bytesTransferred'],
        fields_critical: ['url', 'jobTitle', 'bytesTransferred'],
        detection_quality: 'high',
      },
      {
        event_source: 'windows_bits',
        event_id: '16403',
        event_name: 'BITS Job Created',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Traffic Content',
        fields_provided: ['jobTitle', 'jobId', 'User', 'processPath'],
        fields_critical: ['jobTitle', 'processPath', 'User'],
        detection_quality: 'high',
        notes: 'Shows which process created the BITS job — critical for attribution.',
      },

      // ── WMI Activity ─────────────────────────────────────────────────
      {
        event_source: 'windows_wmi',
        event_id: '5857',
        event_name: 'WMI Provider Loaded',
        mitre_data_source: 'WMI',
        mitre_data_component: 'WMI Creation',
        fields_provided: ['ProviderName', 'ProviderPath', 'ProcessId', 'HostProcess'],
        fields_critical: ['ProviderName', 'ProviderPath'],
        detection_quality: 'medium',
        notes: 'Microsoft-Windows-WMI-Activity/Operational.',
      },
      {
        event_source: 'windows_wmi',
        event_id: '5858',
        event_name: 'WMI Query Error',
        mitre_data_source: 'WMI',
        mitre_data_component: 'WMI Creation',
        fields_provided: ['ErrorCode', 'Query', 'User', 'Namespace'],
        fields_critical: ['Query', 'ErrorCode'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_wmi',
        event_id: '5861',
        event_name: 'WMI Permanent Event Subscription',
        mitre_data_source: 'WMI',
        mitre_data_component: 'WMI Creation',
        fields_provided: ['Namespace', 'ESS', 'CONSUMER', 'PossibleCause'],
        fields_critical: ['CONSUMER', 'ESS'],
        detection_quality: 'high',
        notes: 'Key for detecting WMI persistence (T1546.003). Complement to Sysmon 19/20/21.',
      },

      // ── Sysmon ──────────────────────────────────────────────────────
      {
        event_source: 'sysmon',
        event_id: '1',
        event_name: 'Process Creation',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Creation',
        fields_provided: ['Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'User', 'Hashes', 'OriginalFileName', 'IntegrityLevel', 'ParentProcessGuid', 'ProcessGuid', 'ProcessId', 'ParentProcessId', 'FileVersion', 'Description', 'Product', 'Company', 'CurrentDirectory', 'LogonGuid', 'LogonId', 'TerminalSessionId'],
        fields_critical: ['CommandLine', 'ParentImage', 'ParentCommandLine', 'Image', 'Hashes', 'OriginalFileName'],
        detection_quality: 'high',
        notes: 'Gold standard for process creation detection. ParentCommandLine + Hashes + OriginalFileName provide defense against binary rename.',
      },
      {
        event_source: 'sysmon',
        event_id: '2',
        event_name: 'File Creation Time Changed',
        mitre_data_source: 'File',
        mitre_data_component: 'File Modification',
        fields_provided: ['Image', 'TargetFilename', 'CreationUtcTime', 'PreviousCreationUtcTime', 'ProcessGuid'],
        fields_critical: ['TargetFilename', 'Image'],
        detection_quality: 'high',
        notes: 'Timestomping detection.',
      },
      {
        event_source: 'sysmon',
        event_id: '3',
        event_name: 'Network Connection',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Connection Creation',
        fields_provided: ['Image', 'User', 'Protocol', 'SourceIp', 'SourcePort', 'DestinationIp', 'DestinationPort', 'DestinationHostname', 'SourceHostname', 'Initiated', 'ProcessGuid'],
        fields_critical: ['DestinationIp', 'DestinationPort', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '5',
        event_name: 'Process Terminated',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Termination',
        fields_provided: ['Image', 'ProcessGuid', 'ProcessId'],
        fields_critical: ['Image'],
        detection_quality: 'medium',
      },
      {
        event_source: 'sysmon',
        event_id: '6',
        event_name: 'Driver Loaded',
        mitre_data_source: 'Driver',
        mitre_data_component: 'Driver Load',
        fields_provided: ['ImageLoaded', 'Hashes', 'Signed', 'Signature', 'SignatureStatus'],
        fields_critical: ['ImageLoaded', 'Signed', 'Hashes'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '7',
        event_name: 'Image Loaded (DLL)',
        mitre_data_source: 'Module',
        mitre_data_component: 'Module Load',
        fields_provided: ['Image', 'ImageLoaded', 'Hashes', 'Signed', 'Signature', 'SignatureStatus', 'OriginalFileName', 'ProcessGuid'],
        fields_critical: ['ImageLoaded', 'Hashes', 'Signature', 'Image'],
        detection_quality: 'high',
        notes: 'High volume. Filter in Sysmon config to reduce noise.',
      },
      {
        event_source: 'sysmon',
        event_id: '8',
        event_name: 'CreateRemoteThread',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Access',
        fields_provided: ['SourceImage', 'TargetImage', 'NewThreadId', 'StartAddress', 'StartModule', 'StartFunction', 'SourceProcessGuid', 'TargetProcessGuid'],
        fields_critical: ['SourceImage', 'TargetImage', 'StartAddress'],
        detection_quality: 'high',
        notes: 'Key for process injection detection (CreateRemoteThread).',
      },
      {
        event_source: 'sysmon',
        event_id: '9',
        event_name: 'RawAccessRead',
        mitre_data_source: 'Drive',
        mitre_data_component: 'Drive Access',
        fields_provided: ['Image', 'Device', 'ProcessGuid'],
        fields_critical: ['Image', 'Device'],
        detection_quality: 'high',
        notes: 'Detects raw disk reads (e.g., credential dumping via direct volume access).',
      },
      {
        event_source: 'sysmon',
        event_id: '10',
        event_name: 'Process Access',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Access',
        fields_provided: ['SourceImage', 'TargetImage', 'GrantedAccess', 'CallTrace', 'SourceProcessGuid', 'TargetProcessGuid', 'SourceProcessId', 'TargetProcessId'],
        fields_critical: ['SourceImage', 'TargetImage', 'GrantedAccess'],
        detection_quality: 'high',
        notes: 'Critical for LSASS credential dumping detection (GrantedAccess 0x1010, 0x1FFFFF).',
      },
      {
        event_source: 'sysmon',
        event_id: '11',
        event_name: 'File Created',
        mitre_data_source: 'File',
        mitre_data_component: 'File Creation',
        fields_provided: ['Image', 'TargetFilename', 'CreationUtcTime', 'ProcessGuid'],
        fields_critical: ['TargetFilename', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '12',
        event_name: 'Registry Object Created/Deleted',
        mitre_data_source: 'Windows Registry',
        mitre_data_component: 'Windows Registry Key Creation',
        fields_provided: ['Image', 'TargetObject', 'EventType', 'ProcessGuid'],
        fields_critical: ['TargetObject', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '13',
        event_name: 'Registry Value Set',
        mitre_data_source: 'Windows Registry',
        mitre_data_component: 'Windows Registry Key Modification',
        fields_provided: ['Image', 'TargetObject', 'Details', 'EventType', 'ProcessGuid'],
        fields_critical: ['TargetObject', 'Details', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '14',
        event_name: 'Registry Object Renamed',
        mitre_data_source: 'Windows Registry',
        mitre_data_component: 'Windows Registry Key Modification',
        fields_provided: ['Image', 'TargetObject', 'NewName', 'EventType', 'ProcessGuid'],
        fields_critical: ['TargetObject', 'NewName', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '15',
        event_name: 'FileCreateStreamHash',
        mitre_data_source: 'File',
        mitre_data_component: 'File Metadata',
        fields_provided: ['Image', 'TargetFilename', 'Hash', 'Contents'],
        fields_critical: ['TargetFilename', 'Hash'],
        detection_quality: 'high',
        notes: 'Alternate Data Streams (ADS) + downloaded file MOTW detection.',
      },
      {
        event_source: 'sysmon',
        event_id: '17',
        event_name: 'Pipe Created',
        mitre_data_source: 'Named Pipe',
        mitre_data_component: 'Named Pipe Metadata',
        fields_provided: ['Image', 'PipeName', 'ProcessGuid'],
        fields_critical: ['PipeName', 'Image'],
        detection_quality: 'high',
        notes: 'Key for C2 named pipe detection (Cobalt Strike, etc.).',
      },
      {
        event_source: 'sysmon',
        event_id: '18',
        event_name: 'Pipe Connected',
        mitre_data_source: 'Named Pipe',
        mitre_data_component: 'Named Pipe Metadata',
        fields_provided: ['Image', 'PipeName', 'ProcessGuid'],
        fields_critical: ['PipeName', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '19',
        event_name: 'WMI Event Filter Created',
        mitre_data_source: 'WMI',
        mitre_data_component: 'WMI Creation',
        fields_provided: ['EventType', 'Operation', 'User', 'EventNamespace', 'Name', 'Query'],
        fields_critical: ['Name', 'Query'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '20',
        event_name: 'WMI Event Consumer Created',
        mitre_data_source: 'WMI',
        mitre_data_component: 'WMI Creation',
        fields_provided: ['EventType', 'Operation', 'User', 'Name', 'Type', 'Destination'],
        fields_critical: ['Name', 'Destination', 'Type'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '21',
        event_name: 'WMI Event Consumer Bound',
        mitre_data_source: 'WMI',
        mitre_data_component: 'WMI Creation',
        fields_provided: ['EventType', 'Operation', 'User', 'Consumer', 'Filter'],
        fields_critical: ['Consumer', 'Filter'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '22',
        event_name: 'DNS Query',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Traffic Content',
        fields_provided: ['Image', 'QueryName', 'QueryResults', 'QueryStatus', 'ProcessGuid'],
        fields_critical: ['QueryName', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '23',
        event_name: 'File Deleted',
        mitre_data_source: 'File',
        mitre_data_component: 'File Deletion',
        fields_provided: ['Image', 'TargetFilename', 'Hashes', 'IsExecutable', 'Archived', 'ProcessGuid'],
        fields_critical: ['TargetFilename', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '24',
        event_name: 'Clipboard Changed',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Modification',
        fields_provided: ['Image', 'Session', 'ClientInfo', 'Hashes', 'Archived'],
        fields_critical: ['Image'],
        detection_quality: 'medium',
      },
      {
        event_source: 'sysmon',
        event_id: '25',
        event_name: 'Process Tampering',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Modification',
        fields_provided: ['Image', 'Type', 'ProcessGuid'],
        fields_critical: ['Image', 'Type'],
        detection_quality: 'high',
        notes: 'Detects process hollowing, herpaderping, etc.',
      },
      {
        event_source: 'sysmon',
        event_id: '26',
        event_name: 'File Delete Logged',
        mitre_data_source: 'File',
        mitre_data_component: 'File Deletion',
        fields_provided: ['Image', 'TargetFilename', 'Hashes', 'IsExecutable', 'ProcessGuid'],
        fields_critical: ['TargetFilename', 'Image'],
        detection_quality: 'high',
      },
      {
        event_source: 'sysmon',
        event_id: '27',
        event_name: 'File Block Executable',
        mitre_data_source: 'File',
        mitre_data_component: 'File Creation',
        fields_provided: ['Image', 'TargetFilename', 'ProcessGuid'],
        fields_critical: ['TargetFilename', 'Image'],
        detection_quality: 'medium',
      },
      {
        event_source: 'sysmon',
        event_id: '28',
        event_name: 'File Block Shredding',
        mitre_data_source: 'File',
        mitre_data_component: 'File Deletion',
        fields_provided: ['Image', 'TargetFilename', 'ProcessGuid'],
        fields_critical: ['TargetFilename', 'Image'],
        detection_quality: 'medium',
      },

      // ── Windows PowerShell Log ──────────────────────────────────────
      {
        event_source: 'windows_powershell',
        event_id: '800',
        event_name: 'Pipeline Execution Details',
        mitre_data_source: 'Command',
        mitre_data_component: 'Command Execution',
        fields_provided: ['DetailSequence', 'DetailTotal', 'SequenceNumber', 'UserId', 'HostName', 'HostApplication', 'CommandLine', 'CommandType', 'CommandName'],
        fields_critical: ['CommandLine', 'CommandName'],
        detection_quality: 'medium',
      },
      {
        event_source: 'windows_powershell',
        event_id: '4104',
        event_name: 'Script Block Logging',
        mitre_data_source: 'Script',
        mitre_data_component: 'Script Execution',
        fields_provided: ['ScriptBlockText', 'ScriptBlockId', 'Path'],
        fields_critical: ['ScriptBlockText'],
        detection_quality: 'high',
        notes: 'Same as Security 4104 — appears in Microsoft-Windows-PowerShell/Operational.',
      },

      // ── Linux auditd ────────────────────────────────────────────────
      {
        event_source: 'linux_auditd',
        event_id: 'EXECVE',
        event_name: 'Command Execution',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Creation',
        fields_provided: ['argc', 'a0', 'a1', 'a2', 'a3', 'exe', 'comm', 'uid', 'gid', 'pid', 'ppid', 'cwd'],
        fields_critical: ['exe', 'a0', 'a1', 'uid', 'ppid'],
        detection_quality: 'high',
        notes: 'Requires auditd rules for execve syscall.',
      },
      {
        event_source: 'linux_auditd',
        event_id: 'SYSCALL',
        event_name: 'System Call',
        mitre_data_source: 'Process',
        mitre_data_component: 'OS API Execution',
        fields_provided: ['syscall', 'exe', 'comm', 'uid', 'gid', 'pid', 'ppid', 'success', 'exit', 'key'],
        fields_critical: ['syscall', 'exe', 'uid'],
        detection_quality: 'high',
      },
      {
        event_source: 'linux_auditd',
        event_id: 'USER_AUTH',
        event_name: 'User Authentication',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['acct', 'exe', 'hostname', 'addr', 'terminal', 'res'],
        fields_critical: ['acct', 'addr', 'res'],
        detection_quality: 'high',
      },
      {
        event_source: 'linux_auditd',
        event_id: 'USER_LOGIN',
        event_name: 'User Login',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['acct', 'exe', 'hostname', 'addr', 'terminal', 'res'],
        fields_critical: ['acct', 'addr'],
        detection_quality: 'high',
      },
      {
        event_source: 'linux_auditd',
        event_id: 'PATH',
        event_name: 'File Access Path',
        mitre_data_source: 'File',
        mitre_data_component: 'File Access',
        fields_provided: ['name', 'inode', 'mode', 'ouid', 'ogid', 'nametype'],
        fields_critical: ['name', 'nametype'],
        detection_quality: 'medium',
      },
      {
        event_source: 'linux_auditd',
        event_id: 'SOCKADDR',
        event_name: 'Socket Address',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Connection Creation',
        fields_provided: ['saddr', 'family', 'laddr', 'lport'],
        fields_critical: ['saddr'],
        detection_quality: 'medium',
      },

      // ── EDR: CrowdStrike Falcon ─────────────────────────────────────
      {
        event_source: 'crowdstrike',
        event_id: 'ProcessRollup2',
        event_name: 'Process Execution',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Creation',
        fields_provided: ['ImageFileName', 'CommandLine', 'ParentBaseFileName', 'ParentCommandLine', 'SHA256HashData', 'MD5HashData', 'UserName', 'UserSid', 'TokenType', 'SessionId'],
        fields_critical: ['CommandLine', 'ParentBaseFileName', 'ImageFileName', 'SHA256HashData'],
        detection_quality: 'high',
      },
      {
        event_source: 'crowdstrike',
        event_id: 'NetworkConnectIP4',
        event_name: 'Network Connection IPv4',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Connection Creation',
        fields_provided: ['RemoteAddressIP4', 'RemotePort', 'LocalAddressIP4', 'LocalPort', 'Protocol', 'ConnectionDirection'],
        fields_critical: ['RemoteAddressIP4', 'RemotePort'],
        detection_quality: 'high',
      },
      {
        event_source: 'crowdstrike',
        event_id: 'DnsRequest',
        event_name: 'DNS Request',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Traffic Content',
        fields_provided: ['DomainName', 'RequestType'],
        fields_critical: ['DomainName'],
        detection_quality: 'high',
      },

      // ── EDR: Microsoft Defender for Endpoint ────────────────────────
      {
        event_source: 'mde',
        event_id: 'DeviceProcessEvents',
        event_name: 'Process Events',
        mitre_data_source: 'Process',
        mitre_data_component: 'Process Creation',
        fields_provided: ['FileName', 'ProcessCommandLine', 'InitiatingProcessFileName', 'InitiatingProcessCommandLine', 'SHA256', 'MD5', 'AccountName', 'AccountDomain', 'FolderPath', 'InitiatingProcessFolderPath'],
        fields_critical: ['ProcessCommandLine', 'InitiatingProcessFileName', 'FileName', 'SHA256'],
        detection_quality: 'high',
      },
      {
        event_source: 'mde',
        event_id: 'DeviceNetworkEvents',
        event_name: 'Network Events',
        mitre_data_source: 'Network Traffic',
        mitre_data_component: 'Network Connection Creation',
        fields_provided: ['RemoteIP', 'RemotePort', 'RemoteUrl', 'LocalIP', 'LocalPort', 'Protocol', 'InitiatingProcessFileName'],
        fields_critical: ['RemoteIP', 'RemotePort', 'InitiatingProcessFileName'],
        detection_quality: 'high',
      },
      {
        event_source: 'mde',
        event_id: 'DeviceFileEvents',
        event_name: 'File Events',
        mitre_data_source: 'File',
        mitre_data_component: 'File Creation',
        fields_provided: ['FileName', 'FolderPath', 'SHA256', 'InitiatingProcessFileName', 'ActionType'],
        fields_critical: ['FileName', 'FolderPath', 'InitiatingProcessFileName'],
        detection_quality: 'high',
      },
      {
        event_source: 'mde',
        event_id: 'DeviceRegistryEvents',
        event_name: 'Registry Events',
        mitre_data_source: 'Windows Registry',
        mitre_data_component: 'Windows Registry Key Modification',
        fields_provided: ['RegistryKey', 'RegistryValueName', 'RegistryValueData', 'ActionType', 'InitiatingProcessFileName'],
        fields_critical: ['RegistryKey', 'RegistryValueData', 'InitiatingProcessFileName'],
        detection_quality: 'high',
      },
      {
        event_source: 'mde',
        event_id: 'DeviceLogonEvents',
        event_name: 'Logon Events',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['AccountName', 'AccountDomain', 'LogonType', 'RemoteIP', 'RemoteDeviceName', 'IsLocalAdmin', 'ActionType'],
        fields_critical: ['AccountName', 'LogonType', 'RemoteIP'],
        detection_quality: 'high',
      },
      {
        event_source: 'mde',
        event_id: 'DeviceImageLoadEvents',
        event_name: 'Image Load Events',
        mitre_data_source: 'Module',
        mitre_data_component: 'Module Load',
        fields_provided: ['FileName', 'FolderPath', 'SHA256', 'InitiatingProcessFileName', 'FileSize'],
        fields_critical: ['FileName', 'InitiatingProcessFileName', 'SHA256'],
        detection_quality: 'high',
      },

      // ── Cloud: AWS CloudTrail ───────────────────────────────────────
      {
        event_source: 'aws_cloudtrail',
        event_id: 'ConsoleLogin',
        event_name: 'Console Login',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['userIdentity.arn', 'userIdentity.userName', 'sourceIPAddress', 'userAgent', 'responseElements.ConsoleLogin', 'additionalEventData.MFAUsed'],
        fields_critical: ['userIdentity.userName', 'sourceIPAddress', 'responseElements.ConsoleLogin'],
        detection_quality: 'high',
      },
      {
        event_source: 'aws_cloudtrail',
        event_id: 'AssumeRole',
        event_name: 'STS Assume Role',
        mitre_data_source: 'Cloud Service',
        mitre_data_component: 'Cloud Service Modification',
        fields_provided: ['userIdentity.arn', 'requestParameters.roleArn', 'requestParameters.roleSessionName', 'sourceIPAddress'],
        fields_critical: ['requestParameters.roleArn', 'userIdentity.arn', 'sourceIPAddress'],
        detection_quality: 'high',
      },
      {
        event_source: 'aws_cloudtrail',
        event_id: 'CreateUser',
        event_name: 'IAM User Created',
        mitre_data_source: 'User Account',
        mitre_data_component: 'User Account Creation',
        fields_provided: ['userIdentity.arn', 'requestParameters.userName', 'sourceIPAddress'],
        fields_critical: ['requestParameters.userName', 'userIdentity.arn'],
        detection_quality: 'high',
      },

      // ── Cloud: Azure AD / Entra ID ──────────────────────────────────
      {
        event_source: 'azure_ad',
        event_id: 'SignInLogs',
        event_name: 'Azure AD Sign-In',
        mitre_data_source: 'Logon Session',
        mitre_data_component: 'Logon Session Creation',
        fields_provided: ['UserPrincipalName', 'IPAddress', 'Location', 'AppDisplayName', 'ResultType', 'ConditionalAccessStatus', 'DeviceDetail', 'RiskLevelAggregated'],
        fields_critical: ['UserPrincipalName', 'IPAddress', 'ResultType'],
        detection_quality: 'high',
      },
      {
        event_source: 'azure_ad',
        event_id: 'AuditLogs',
        event_name: 'Azure AD Audit',
        mitre_data_source: 'Active Directory',
        mitre_data_component: 'Active Directory Object Modification',
        fields_provided: ['OperationName', 'Category', 'ActivityDisplayName', 'InitiatedBy', 'TargetResources', 'Result'],
        fields_critical: ['OperationName', 'InitiatedBy', 'TargetResources'],
        detection_quality: 'high',
      },
    ];

    for (const m of mappings) {
      runBulkStatement(
        `INSERT OR IGNORE INTO telemetry_mappings
         (event_source, event_id, event_name, mitre_data_source, mitre_data_component,
          fields_provided, fields_critical, detection_quality, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          m.event_source,
          m.event_id,
          m.event_name,
          m.mitre_data_source,
          m.mitre_data_component,
          JSON.stringify(m.fields_provided),
          JSON.stringify(m.fields_critical),
          m.detection_quality,
          m.notes || null,
        ]
      );
    }

    db.exec('COMMIT');
    saveDb();
    console.error(`[db] Seeded ${mappings.length} telemetry mappings`);
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Query Functions (used by tools)
// ────────────────────────────────────────────────────────────────────────────

export interface TelemetryMapping {
  id: number;
  event_source: string;
  event_id: string;
  event_name: string;
  mitre_data_source: string;
  mitre_data_component: string;
  fields_provided: string;
  fields_critical: string;
  detection_quality: string;
  notes: string | null;
}

export function lookupMapping(eventSource: string, eventId: string): TelemetryMapping[] {
  return runQuery<TelemetryMapping>(
    `SELECT * FROM telemetry_mappings WHERE event_source = ? AND event_id = ?`,
    [eventSource, eventId]
  );
}

export function lookupMappingByComponent(dataComponent: string): TelemetryMapping[] {
  return runQuery<TelemetryMapping>(
    `SELECT * FROM telemetry_mappings WHERE mitre_data_component = ?`,
    [dataComponent]
  );
}

export function getAllMappings(): TelemetryMapping[] {
  return runQuery<TelemetryMapping>('SELECT * FROM telemetry_mappings ORDER BY event_source, event_id');
}

export function getAllMappedDataComponents(): string[] {
  const rows = runQuery<{ mitre_data_component: string }>(
    'SELECT DISTINCT mitre_data_component FROM telemetry_mappings'
  );
  return rows.map(r => r.mitre_data_component);
}

// Session management
export function createCoverageSession(sessionId: string, name: string, description?: string): void {
  runStatement(
    `INSERT OR REPLACE INTO coverage_sessions (session_id, name, description) VALUES (?, ?, ?)`,
    [sessionId, name, description || null]
  );
}

export function getSession(sessionId: string): Record<string, unknown> | null {
  const rows = runQuery<Record<string, unknown>>(
    'SELECT * FROM coverage_sessions WHERE session_id = ?',
    [sessionId]
  );
  return rows[0] || null;
}

export function listSessions(): Record<string, unknown>[] {
  return runQuery<Record<string, unknown>>(
    'SELECT * FROM coverage_sessions ORDER BY created_at DESC LIMIT 50'
  );
}

export function addSessionTelemetry(
  sessionId: string,
  eventSource: string,
  eventId: string,
  sampleLog: string | null,
  parsedFields: string[],
  mappedDataSource: string,
  mappedDataComponent: string,
  fieldCoveragePct: number,
  qualityTier: string
): void {
  runStatement(
    `INSERT INTO session_telemetry
     (session_id, event_source, event_id, sample_log, parsed_fields,
      mapped_data_source, mapped_data_component, field_coverage_pct, quality_tier)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [sessionId, eventSource, eventId, sampleLog, JSON.stringify(parsedFields),
     mappedDataSource, mappedDataComponent, fieldCoveragePct, qualityTier]
  );
}

export function getSessionTelemetry(sessionId: string): Record<string, unknown>[] {
  return runQuery<Record<string, unknown>>(
    'SELECT * FROM session_telemetry WHERE session_id = ?',
    [sessionId]
  );
}

export function getSessionDataComponents(sessionId: string): string[] {
  const rows = runQuery<{ mapped_data_component: string }>(
    'SELECT DISTINCT mapped_data_component FROM session_telemetry WHERE session_id = ?',
    [sessionId]
  );
  return rows.map(r => r.mapped_data_component);
}

export function writeSessionCoverage(
  sessionId: string,
  techniqueId: string,
  techniqueName: string,
  tactic: string,
  coverageStatus: string,
  dataSourcesPresent: string[],
  dataSourcesMissing: string[],
  detectionRulesAvailable: number,
  fieldQuality: string,
  remediation: string | null
): void {
  runBulkStatement(
    `INSERT OR REPLACE INTO session_coverage
     (session_id, technique_id, technique_name, tactic, coverage_status,
      data_sources_present, data_sources_missing, detection_rules_available,
      field_quality, remediation)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [sessionId, techniqueId, techniqueName, tactic, coverageStatus,
     JSON.stringify(dataSourcesPresent), JSON.stringify(dataSourcesMissing),
     detectionRulesAvailable, fieldQuality, remediation]
  );
}

export function getSessionCoverage(sessionId: string, statusFilter?: string): Record<string, unknown>[] {
  let sql = 'SELECT * FROM session_coverage WHERE session_id = ?';
  const params: unknown[] = [sessionId];

  if (statusFilter) {
    sql += ' AND coverage_status = ?';
    params.push(statusFilter);
  }

  sql += ' ORDER BY coverage_status, technique_id';
  return runQuery<Record<string, unknown>>(sql, params);
}

export function updateSessionStats(
  sessionId: string,
  full: number,
  partial: number,
  gap: number,
  detectable: number
): void {
  runStatement(
    `UPDATE coverage_sessions SET
       total_techniques_full = ?,
       total_techniques_partial = ?,
       total_techniques_gap = ?,
       total_techniques_detectable = ?
     WHERE session_id = ?`,
    [full, partial, gap, detectable, sessionId]
  );
}

export function getMappingStats(): Record<string, unknown> {
  const total = runQuery<{ cnt: number }>('SELECT COUNT(*) as cnt FROM telemetry_mappings');
  const bySrc = runQuery<{ event_source: string; cnt: number }>(
    'SELECT event_source, COUNT(*) as cnt FROM telemetry_mappings GROUP BY event_source ORDER BY cnt DESC'
  );
  const byDs = runQuery<{ mitre_data_source: string; cnt: number }>(
    'SELECT mitre_data_source, COUNT(*) as cnt FROM telemetry_mappings GROUP BY mitre_data_source ORDER BY cnt DESC'
  );
  const sessions = runQuery<{ cnt: number }>('SELECT COUNT(*) as cnt FROM coverage_sessions');

  return {
    total_mappings: total[0]?.cnt || 0,
    by_event_source: bySrc,
    by_data_source: byDs,
    total_sessions: sessions[0]?.cnt || 0,
  };
}
