@{
    RootModule            = 'ADCS.ESC.Assessment.psm1'
    ModuleVersion         = '0.1.0'
    GUID                  = 'b6d2e1a4-7c3f-4a9b-9e21-0f5a3c8d2e10'
    Author                = 'Mustafa Emre GUL'
    CompanyName           = 'm3g yazilim ve danismanlik'
    Copyright             = '(c) 2026 Mustafa Emre GUL. All rights reserved.'
    Description           = 'Read-only security assessment for AD CS ESC1-ESC16 misconfigurations. Non-destructive.'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FunctionsToExport     = @('Invoke-ESCAssessment', 'Export-EscCaData')
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    PrivateData = @{
        WebSite        = 'https://www.emregul.com.tr'
        CompanyWebSite = 'https://www.m3g.com.tr'
        PSData = @{
            Tags         = @('ADCS', 'Security', 'ESC', 'Certificate', 'Audit', 'BlueTeam', 'PKI', 'ActiveDirectory')
            ProjectUri   = 'https://www.emregul.com.tr'

            LicenseUri   = 'https://github.com/m3gTech/ADCS.CA.Assessment/blob/master/LICENSE'
            IconUri      = 'https://raw.githubusercontent.com/m3gTech/ADCS.CA.Assessment/master/images/logo.png'

            ReleaseNotes = @'
v0.1.0 - Initial release (2026)

ADCS.ESC.Assessment is a read-only, non-destructive security assessment for
Active Directory Certificate Services (AD CS). It evaluates an environment
against the ESC1-ESC16 privilege-escalation misconfigurations, scores each
finding, and produces a self-contained HTML report plus machine-readable JSON.

Highlights
- Coverage for ESC1 through ESC16 (enrollee-supplied SAN, Any-Purpose EKU,
  enrollment agent, template/PKI/CA ACLs, EDITF_ATTRIBUTESUBJECTALTNAME2,
  ManageCA, web-enrollment NTLM relay, missing security extension, weak/explicit
  mappings, ICertPassage RPC encryption, HSM/shell access, OID group link,
  altSecurityIdentities, and EKUwu / CVE-2024-49019).
- Risk scoring (0-10 per finding) and an overall posture score (0-100 with an
  A-F grade).
- Live collection on Windows (RSAT ActiveDirectory preferred, DirectoryServices
  fallback) and an offline, fixture-based mode that runs on any platform (pwsh 7).
- Optional live-only CA extras: registry + issued-cert export (-ExportCaData),
  full read-only CA backup (-BackupCa), and unused-template analysis
  (-AnalyzeTemplateUsage).
- Exports two commands: Invoke-ESCAssessment and Export-EscCaData.

Safety
Read-only and non-destructive by design. No certificate is requested, issued,
or submitted, and no AD/CA object is modified. Permitted operations are limited
to LDAP search, certutil -getreg (read), registry reads, and HTTP GET/HEAD for
endpoint detection. Run only against environments you own or are authorized to test.

See docs/Invoke-ESCAssessment.md and docs/Export-EscCaData.md for full usage.
'@
        }
    }
}
