

Invoke-ESCAssessment

SYNOPSIS
------------------------------------------------------------

Runs a read-only, non-destructive security assessment of an Active Directory
Certificate Services (AD CS) environment against the ESC1-ESC16 privilege-escalation
misconfigurations, scores the findings, and produces an HTML + JSON report.

SYNTAX
------------------------------------------------------------

Live (Default)

Invoke-ESCAssessment [-Server <String>] [-OutputPath <String>] [-Format <String[]>]
 [-ExtraLowPrivSid <String[]>] [-CollectOnly] [-ExportCaData] [-CaExportRoot <String>]
 [-BackupCa] [-CaBackupPassword <SecureString>] [-AnalyzeTemplateUsage] [<CommonParameters>]

Offline

Invoke-ESCAssessment -Offline -FixturePath <String> [-OutputPath <String>]
 [-Format <String[]>] [-ExtraLowPrivSid <String[]>] [-CollectOnly] [<CommonParameters>]

All parameters belong to a single parameter set; the two blocks above show the typical live
and offline usage. When -Offline is supplied, -FixturePath is required and the live-only,
CA-specific parameters (-ExportCaData, -BackupCa, -AnalyzeTemplateUsage) are ignored.

DESCRIPTION
------------------------------------------------------------

The Invoke-ESCAssessment cmdlet is the module's main entry point and runs the entire
assessment end to end. It serves a purpose similar to Locksmith or Certipy find, but takes an
entirely non-destructive path:

1. Collect. Reads the AD CS configuration read-only through the Get-Esc* collectors; in
   -Offline mode it loads normalized fixture JSON files instead.
2. Cross-reference. Maps published templates onto CAs (Template.PublishedOnCAs).
3. Analyze. Builds a single AssessmentContext and runs every Test-Esc1 ... Test-Esc16
   analyzer.
4. Score. Scores findings with Get-EscRiskScore (0-10) and computes the overall posture
   with Get-EscPostureScore (0-100 plus an A-F grade).
5. Report. Writes a scored, visual HTML report and/or a machine-readable JSON report.

IMPORTANT:
Run this tool only against environments you own or have written permission to test.
It is intended for defense and audit. No certificate is ever requested / issued / submitted,
and no AD/CA object is modified. Permitted calls: LDAP search, certutil -getreg (read),
registry reads, and HTTP GET/HEAD (endpoint detection). Enrollment rights are computed by
ACE analysis; no real request is sent.

Coverage (ESC1-ESC16). Enrollee-supplied SAN, Any-Purpose EKU, enrollment agent,
template/PKI/CA ACLs, EDITF_ATTRIBUTESUBJECTALTNAME2, ManageCA, web-enrollment NTLM relay,
missing security extension, weak/explicit mappings, ICertPassage RPC encryption, HSM/shell
access, OID group link, altSecurityIdentities, and EKUwu / CVE-2024-49019.

Environment. Live collection requires Windows + PowerShell 5.1/7 - preferably the
ActiveDirectory RSAT module, otherwise a System.DirectoryServices fallback is used. Offline
mode runs on any platform (pwsh 7) from fixtures.

EXAMPLES
------------------------------------------------------------

Example 1: Live assessment in an authorized domain

Import-Module .\src\ADCS.ESC.Assessment.psd1 -Force
Invoke-ESCAssessment -OutputPath .\out

Runs on an authorized, domain-joined Windows host. Collects the configuration, runs the 16
analyzers, and writes esc-assessment-report.html and .json to .\out. It also returns an
object with the summary and findings.

Example 2: Offline (fixture-based) assessment

Invoke-ESCAssessment -Offline -FixturePath .\tests\fixtures\sample -OutputPath .\out

Runs against normalized JSON fixtures without touching a live CA. Ideal for CI, demos and
analyzer validation; also works on non-Windows platforms (pwsh 7).

Example 3: Collect only - verify read-only behavior

Invoke-ESCAssessment -CollectOnly | Select-Object -ExpandProperty Context

Returns only the AssessmentContext without running analysis or producing a report. Useful for
confirming exactly what the tool reads, or inspecting the raw collected data.

Example 4: JSON-only output with an extra low-privilege SID

Invoke-ESCAssessment -Format Json -ExtraLowPrivSid 'S-1-5-21-...-1234' -OutputPath .\out

Produces only the machine-readable JSON report and treats a broad custom group as
"low-privileged" during analysis, so enrollment rights granted to that group are also flagged.

Example 5: Export CA data and take a backup

$pw = Read-Host -AsSecureString -Prompt 'CA backup password'
Invoke-ESCAssessment -OutputPath .\out -ExportCaData -BackupCa -CaBackupPassword $pw

In addition to the assessment, exports each CA's registry configuration and issued-cert list
into a CA_Assesment_<timestamp> folder under the report output directory, and takes a full CA
backup with -BackupCa. When a password is given, the private key (.p12) is included. Runs on
the CA host only.

Example 6: Analyze unused published templates

Invoke-ESCAssessment -OutputPath .\out -AnalyzeTemplateUsage

Identifies templates that are published on a CA but have no still-valid issued certificate
(runs certutil -view per CA). Off by default because it can be slow on large CA databases.

Example 7: Full assessment - export, backup, and template-usage analysis together

Import-Module .\src\ADCS.ESC.Assessment.psd1 -Force

$pw = Read-Host -AsSecureString -Prompt 'CA backup password'

Invoke-ESCAssessment -OutputPath .\out 
    -ExportCaData 
    -BackupCa -CaBackupPassword $pw 
    -AnalyzeTemplateUsage 
    -Verbose

Runs the complete, fully-loaded pass in one call on the CA host: the read-only ESC1-ESC16
assessment, the CA data export (registry + issued certificates + CRLs), a full CA backup
including the private key, and the unused-template usage analysis - all written under .\out.
This is the recommended one-shot command for an on-box CA audit where you want the reports and
every collected artifact side by side.

- Must run on the CA host itself - -BackupCa is local-only, and -AnalyzeTemplateUsage /
  -ExportCaData are live-only.
- Requires elevation (backup and issued-cert enumeration need CA-host privileges).
- Omit -CaBackupPassword to take a database-only backup without the private key.
- Still fully read-only: the backup and every export only read CA state; nothing is issued,
  published, or modified, and the CA service is never stopped.

The returned object carries the full result set - Summary, Findings, CaStatus,
CaExports, UnusedTemplates, CaRoleAssignments and ReportPaths:

$result = Invoke-ESCAssessment -OutputPath .\out -ExportCaData -BackupCa -CaBackupPassword $pw -AnalyzeTemplateUsage
$result.Summary            # PostureScore + Grade (A-F)
$result.CaExports          # exported CA folders + files
$result.UnusedTemplates    # published-but-unused templates
$result.ReportPaths        # .html + .json paths

PARAMETERS
------------------------------------------------------------

-Server

Specifies the domain controller (DC) or server to target for live collection. If omitted, the
current domain context is used.

Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None (current domain context)
Accept pipeline input: False
Accept wildcard characters: False

-OutputPath

The directory to write reports into (created if missing). Files:
esc-assessment-report.html and esc-assessment-report.json. With -ExportCaData, CA exports
are placed under this directory by default, so reports and exports sit together.

Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: . (current directory)
Accept pipeline input: False
Accept wildcard characters: False

-Format

The report format to produce: Html, Json, or both. Html is a self-contained visual report
with no network dependency; Json is machine-readable output for SIEM/automation/diff.

Type: String[]
Parameter Sets: (All)
Aliases:
Accepted values: Html, Json

Required: False
Position: Named
Default value: Html, Json
Accept pipeline input: False
Accept wildcard characters: False

-Offline

Loads normalized fixtures from -FixturePath instead of doing live collection. When this switch
is set, -FixturePath is required.

Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False

-FixturePath

The directory of normalized fixture JSON files (used with -Offline). Expected files:
templates.json, enrollmentservices.json, caconfigs.json, pkiacls.json,
dcmappings.json, webendpoints.json, oidgrouplinks.json, altsecurityidentities.json.
Any missing file is treated as empty.

Type: String
Parameter Sets: (All)
Aliases:

Required: True (only when -Offline is specified)
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False

-ExtraLowPrivSid

Additional SIDs to treat as "low-privileged" (for example, a broad custom group).
Enrollment/ACL rights granted to these principals are also flagged as findings.

Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None (empty array)
Accept pipeline input: False
Accept wildcard characters: False

-CollectOnly

Runs collection only and returns the AssessmentContext; no analysis is run and no report is
produced. Useful for verifying what the tool reads.

Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False

-ExportCaData

Also exports each CA's registry configuration and issued-certificate list into a
CA_Assesment_<timestamp> folder under the report output directory, so reports and exports stay
in one place. Live Windows only.

Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False

-CaExportRoot

Overrides the CA export root. Defaults to -OutputPath when omitted.

Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: The -OutputPath value
Accept pipeline input: False
Accept wildcard characters: False

-BackupCa

With -ExportCaData, also takes a full CA backup into the same folder (local CA only). It is a
read-only backup; the CA service is never stopped.

Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False

-CaBackupPassword

A SecureString that protects the exported CA private key (.p12). Omit it for a database-only
backup (no private key).

Type: SecureString
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None (database-only backup)
Accept pipeline input: False
Accept wildcard characters: False

-AnalyzeTemplateUsage

Live only. Analyzes which CA-published templates have no still-valid issued certificate (runs
certutil -view per CA). Off by default because it can be slow on large CA databases.

Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False

CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable,
-Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

INPUTS
------------------------------------------------------------

None

You cannot pipe objects to this cmdlet. All data is obtained by live collection or fixture
loading according to the specified parameters.

OUTPUTS
------------------------------------------------------------

System.Management.Automation.PSCustomObject

The cmdlet returns a single object with the following properties:

| Property            | Type / content   | Description                                                                                                                                                        |
| ------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Summary           | PSCustomObject   | Overall posture: PostureScore (0-100), Grade (A-F), and the severity breakdown. $null with -CollectOnly.                                                   |
| Findings          | PSCustomObject[] | ESC1-16 findings: Id, Title, Severity, Status, AffectedObject, Evidence, Principals, RiskScore, Remediation.                                     |
| Context           | PSCustomObject   | The raw collected AssessmentContext (templates, CAs, ACLs, mappings, meta).                                                                                      |
| ReportPaths       | String[]         | Full paths of the written report files.                                                                                                                            |
| CaStatus          | PSCustomObject   | Live only. CA reachability and Cert Publishers status.                                                                                                             |
| CaExports         | PSCustomObject[] | Live only. Export folders and files produced by -ExportCaData.                                                                                                   |
| UnusedTemplates   | PSCustomObject[] | Live only. Published-but-unused templates found by -AnalyzeTemplateUsage.                                                                                        |
| CaRoleAssignments | PSCustomObject[] | Inventory of Manage CA / Issue and Manage Certificates roles; non-default assignments are flagged.                                                                 |

NOTES
------------------------------------------------------------

Letter grade. The overall Posture Score (100 - min(100, sum(RiskScore * StatusWeight))) maps
to the grade below. A higher score means a better security posture.

| Score range | Grade |
| ----------- | ----- |
| 90-100      | A     |
| 80-89       | B     |
| 70-79       | C     |
| 60-69       | D     |
| < 60        | F     |

Covered checks. ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC7, ESC8, ESC9, ESC10, ESC11, ESC12,
ESC13, ESC14, ESC15, ESC16.

Requirements. Windows + PowerShell 5.1/7 (live); preferably the ActiveDirectory (RSAT)
module, otherwise a System.DirectoryServices fallback; optional PSPKI. Offline mode runs on
any platform with pwsh 7.

Exported commands. The module exports only Invoke-ESCAssessment and Export-EscCaData.

Import. Import-Module .\src\ADCS.ESC.Assessment.psd1 -Force

RELATED LINKS
------------------------------------------------------------

Export-EscCaData  (see docs/Export-EscCaData.md)
