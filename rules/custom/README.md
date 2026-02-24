# Custom Detection Rules — Session-Built Sigma Rules Index

> **Total**: 106 Sigma detection rules built across 4 sessions
> **Author**: Detection Engineering (Claude-assisted)
> **Date**: February 2026
> **Framework**: MITRE ATT&CK mapped, WAT-41 self-tested

---

## Batch 1 — UAE-Targeted Threat Detections (49 rules)

Iranian and regional threat actors targeting UAE infrastructure.

| # | Rule Name | Technique | Actor/Context | Priority |
|---|---|---|---|---|
| 1 | MuddyWater PowerShell Backdoor | T1059.001 | MuddyWater | Critical |
| 2 | MuddyWater DLL Side-Loading | T1574.002 | MuddyWater | Critical |
| 3 | MuddyWater Scheduled Task Persistence | T1053.005 | MuddyWater | High |
| 4 | MuddyWater Registry Run Key | T1547.001 | MuddyWater | High |
| 5 | MuddyWater LOLBAS Abuse (mshta.exe) | T1218.005 | MuddyWater | High |
| 6 | APT33 Spearphishing Attachment | T1566.001 | APT33 | Critical |
| 7 | APT33 Credential Harvesting | T1003.001 | APT33 | Critical |
| 8 | APT33 WMI Execution | T1047 | APT33 | High |
| 9 | APT34 DNS Tunneling | T1071.004 | APT34/OilRig | Critical |
| 10 | APT34 Web Shell Deployment | T1505.003 | APT34/OilRig | Critical |
| 11 | APT34 Mimikatz Usage | T1003.001 | APT34/OilRig | High |
| 12 | APT34 PowerShell Download Cradle | T1059.001 | APT34/OilRig | High |
| 13 | APT35 Credential Phishing | T1566.002 | APT35/Charming Kitten | Critical |
| 14 | APT35 Browser Credential Theft | T1555.003 | APT35/Charming Kitten | High |
| 15 | APT35 SSH Tunnel | T1572 | APT35/Charming Kitten | High |
| 16 | APT42 Social Engineering via Cloud | T1566.002 | APT42 | Critical |
| 17 | APT42 Cloud Token Theft | T1528 | APT42 | Critical |
| 18 | Agrius Wiper Activity (Apostle) | T1485 | Agrius | Critical |
| 19 | Agrius Data Destruction via Disk Wipe | T1561.001 | Agrius | Critical |
| 20 | Hexane ISMDOOR Backdoor | T1059.003 | Hexane/Lyceum | High |
| 21 | Hexane DNS Exfiltration | T1048.003 | Hexane/Lyceum | High |
| 22 | Turla Carbon Framework | T1071.001 | Turla | High |
| 23 | Turla Penquin Backdoor | T1059.004 | Turla | High |
| 24 | Sandworm CaddyWiper Execution | T1485 | Sandworm | Critical |
| 25 | Generic Iran-linked Certutil Download | T1105 | Multiple | High |
| 26 | Iran-linked BITSAdmin Abuse | T1197 | Multiple | High |
| 27 | Iran-linked Registry Persistence | T1547.001 | Multiple | Medium |
| 28 | UAE-Targeted Spearphishing (Energy Sector) | T1566.001 | Multiple | Critical |
| 29 | UAE-Targeted Watering Hole | T1189 | Multiple | High |
| 30 | Middle East VPN Credential Harvesting | T1133 | Multiple | Critical |
| 31 | PowGoop DLL Loader | T1574.002 | MuddyWater | Critical |
| 32 | POWERSTATS Backdoor | T1059.001 | MuddyWater | High |
| 33 | SharpChisel Tunneling | T1572 | Multiple | High |
| 34 | Koadic RAT Execution | T1059.005 | Multiple | High |
| 35 | RDAT Backdoor DNS C2 | T1071.004 | APT34 | Critical |
| 36 | Shark Backdoor Communication | T1071.001 | MuddyWater | High |
| 37 | Milan Backdoor Registry | T1547.001 | Hexane/Lyceum | High |
| 38 | PhonyC2 Framework Detection | T1071.001 | MuddyWater | High |
| 39 | BugSleep Backdoor | T1059.001 | MuddyWater | High |
| 40 | Shamoon Disk Wiper | T1561.002 | APT33 | Critical |
| 41 | ZeroCleare Wiper | T1561.001 | APT34 | Critical |
| 42 | Dustman Wiper Activity | T1485 | Multiple Iran | Critical |
| 43 | MOIS-linked Service Installation | T1543.003 | Multiple Iran | High |
| 44 | Iran IRGC Exploitation Patterns | T1190 | IRGC-linked | Critical |
| 45 | UAE Critical Infra SCADA Recon | T1046 | Multiple | Critical |
| 46 | OilRig ISMAgent Execution | T1059.003 | APT34 | High |
| 47 | Fox Kitten VPN Exploitation | T1190 | Fox Kitten | Critical |
| 48 | Peach Sandstorm Password Spray | T1110.003 | Peach Sandstorm | High |
| 49 | Cotton Sandstorm Wiper Patterns | T1485 | Cotton Sandstorm | Critical |

## Batch 2 — Iranian Threat Actor TTPs (23 rules)

Deep-dive into specific Iranian actor technique chains.

| # | Rule Name | Technique | Actor/Context | Priority |
|---|---|---|---|---|
| 50 | APT33 StoneDrill Dropper | T1204.002 | APT33 | Critical |
| 51 | APT33 TurnedUp Backdoor | T1059.003 | APT33 | High |
| 52 | APT33 Empire Framework | T1059.001 | APT33 | High |
| 53 | APT34 BONDUPDATER Script | T1059.001 | APT34 | High |
| 54 | APT34 SideTwist Backdoor | T1071.001 | APT34 | High |
| 55 | APT34 Karkoff Implant | T1059.003 | APT34 | High |
| 56 | APT35 CharmPower Module | T1059.001 | APT35 | High |
| 57 | APT35 BellaCiao Backdoor | T1505.003 | APT35 | Critical |
| 58 | APT35 HYPERSCRAPE Tool | T1114.002 | APT35 | Critical |
| 59 | APT42 NICECURL Backdoor | T1059.001 | APT42 | High |
| 60 | APT42 TAMECAT Backdoor | T1059.005 | APT42 | High |
| 61 | MuddyWater SimpleHarm | T1059.001 | MuddyWater | High |
| 62 | MuddyWater MuddyC2Go | T1071.001 | MuddyWater | Critical |
| 63 | MuddyWater Atera RMM Abuse | T1219 | MuddyWater | High |
| 64 | MuddyWater ConnectWise Abuse | T1219 | MuddyWater | High |
| 65 | Agrius Moneybird Ransomware | T1486 | Agrius | Critical |
| 66 | Agrius Fantasy Wiper | T1485 | Agrius | Critical |
| 67 | Moses Staff StrifeWater RAT | T1059.001 | Moses Staff | High |
| 68 | Moses Staff PyDCrypt | T1059.006 | Moses Staff | High |
| 69 | Tortoiseshell LEMPO Tool | T1082 | Tortoiseshell | Medium |
| 70 | Tortoiseshell Syskit Backdoor | T1059.003 | Tortoiseshell | High |
| 71 | CopyKittens Matryoshka RAT | T1059.001 | CopyKittens | High |
| 72 | Iran-linked AnyDesk RMM Abuse | T1219 | Multiple | High |

## Batch 3 — Extended TTP Coverage (14 rules)

Cross-actor technique coverage for high-priority gaps.

| # | Rule Name | Technique | Actor/Context | Priority |
|---|---|---|---|---|
| 73 | Lateral Movement via WMI | T1047 | Multiple | High |
| 74 | RDP Lateral Movement Detection | T1021.001 | Multiple | High |
| 75 | PsExec Remote Execution | T1021.002 | Multiple | High |
| 76 | LSASS Memory Dump (Various Tools) | T1003.001 | Multiple | Critical |
| 77 | Kerberoasting Activity | T1558.003 | Multiple | High |
| 78 | AS-REP Roasting | T1558.004 | Multiple | High |
| 79 | DCSync Attack Detection | T1003.006 | Multiple | Critical |
| 80 | Golden Ticket Usage | T1558.001 | Multiple | Critical |
| 81 | Scheduled Task Remote Creation | T1053.005 | Multiple | High |
| 82 | Service Installation for Persistence | T1543.003 | Multiple | High |
| 83 | BITS Job Abuse for Download | T1197 | Multiple | High |
| 84 | DLL Search Order Hijacking | T1574.001 | Multiple | High |
| 85 | Reflective DLL Injection | T1055.001 | Multiple | Critical |
| 86 | Process Hollowing Detection | T1055.012 | Multiple | Critical |

## Batch 4 — YARA-to-Sigma Conversions (20 rules)

YARA rules converted to Sigma format for SIEM integration.

| # | Rule Name | Technique | Source YARA | Priority |
|---|---|---|---|---|
| 87 | Cobalt Strike Beacon Detection | T1071.001 | CS_beacon.yar | Critical |
| 88 | Cobalt Strike Malleable C2 | T1071.001 | CS_malleable.yar | Critical |
| 89 | Meterpreter Shellcode Patterns | T1059.006 | meterpreter.yar | Critical |
| 90 | Emotet Document Macro | T1204.002 | emotet_doc.yar | High |
| 91 | Emotet Process Injection | T1055.001 | emotet_inject.yar | High |
| 92 | QakBot DLL Execution | T1574.002 | qakbot_dll.yar | High |
| 93 | IcedID Loader Patterns | T1204.002 | icedid_loader.yar | High |
| 94 | TrickBot Module Loading | T1129 | trickbot_mod.yar | High |
| 95 | BazarLoader Execution | T1204.002 | bazarloader.yar | High |
| 96 | Ryuk Ransomware Indicators | T1486 | ryuk.yar | Critical |
| 97 | Conti Ransomware Patterns | T1486 | conti.yar | Critical |
| 98 | BlackCat/ALPHV Ransomware | T1486 | blackcat.yar | Critical |
| 99 | LockBit 3.0 Execution | T1486 | lockbit3.yar | Critical |
| 100 | Mimikatz Memory Patterns | T1003.001 | mimikatz.yar | Critical |
| 101 | Sliver C2 Framework | T1071.001 | sliver_c2.yar | High |
| 102 | Brute Ratel C4 Indicators | T1071.001 | bruteratel.yar | Critical |
| 103 | Havoc Framework Detection | T1071.001 | havoc.yar | High |
| 104 | SystemBC Proxy Bot | T1090.001 | systembc.yar | High |
| 105 | AsyncRAT Execution | T1059.001 | asyncrat.yar | High |
| 106 | RemcosRAT Communication | T1071.001 | remcos.yar | High |

---

## MITRE ATT&CK Coverage Summary

| Tactic | Techniques Covered | Rule Count |
|---|---|---|
| Initial Access | T1566.001, T1566.002, T1189, T1190, T1133 | 8 |
| Execution | T1059.001/003/004/005/006, T1047, T1204.002, T1129 | 28 |
| Persistence | T1547.001, T1543.003, T1053.005, T1505.003 | 10 |
| Privilege Escalation | T1055.001, T1055.012, T1574.001, T1574.002 | 8 |
| Defense Evasion | T1218.005, T1197, T1574.002 | 5 |
| Credential Access | T1003.001, T1003.006, T1558.001/003/004, T1555.003, T1528 | 10 |
| Lateral Movement | T1021.001, T1021.002, T1047 | 5 |
| Collection | T1114.002, T1082 | 3 |
| Command and Control | T1071.001, T1071.004, T1572, T1090.001, T1219 | 18 |
| Impact | T1485, T1486, T1561.001, T1561.002 | 11 |

---

## Notes

- All rules were built using the WAT-40/41/42 pipeline (construction → self-testing → hardening)
- Rules exist in chat history from sessions dated February 2026
- YAML content should be extracted from chat transcripts and saved as individual `.yml` files
- Each rule includes: Sigma YAML + KQL conversion + Splunk SPL + self-test scores
- To extract rules: search chat transcripts for `title:` + `logsource:` + `detection:` blocks

## File Location

Rules are currently stored in **chat session transcripts** (not yet as individual files).
To materialize:
```bash
# After extraction, save each rule as:
rules/custom/batch1-uae/rule_001_muddywater_powershell.yml
rules/custom/batch2-iran/rule_050_apt33_stonedrill.yml
rules/custom/batch3-extended/rule_073_wmi_lateral.yml
rules/custom/batch4-yara/rule_087_cobaltstrike_beacon.yml
```
