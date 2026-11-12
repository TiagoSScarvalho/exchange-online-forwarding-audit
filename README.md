# Exchange Online External Forwarding Audit

A read-only PowerShell tool for administrators who need to answer: **which mailbox settings and Inbox rules could send email elsewhere, and how complete was the check?**

It produces local HTML, CSV and JSON reports. It uses Exchange `Get-*` commands, does not read message bodies, and does not change rules, settings, permissions or messages. Authentication and any module installation are separate administrator steps.

By [Tiago Carvalho](https://www.tiagoscarvalho.com). Licensed under [MIT](LICENSE.txt).

## Download v1.0.1

- [Download the ready-to-run ZIP](https://github.com/TiagoSScarvalho/exchange-online-forwarding-audit/releases/download/v1.0.1/exchange-forwarding-audit-v1.0.1.zip)
- [Release notes and checksum](https://github.com/TiagoSScarvalho/exchange-online-forwarding-audit/releases/tag/v1.0.1)
- [Source code and tests for v1.0.1](https://github.com/TiagoSScarvalho/exchange-online-forwarding-audit/tree/v1.0.1)
- [Full operating guide](README.txt)
- [Simulated report example](examples/README.md)

Verify the ZIP using the steps below, then extract it and keep `Get-ExternalForwardingAudit.ps1` and `ExternalForwardingAudit.psm1` together. Review both files before running them. The release ZIP is the same v1.0.1 package validated on 11 November 2026; the repository adds documentation and offline tests.

**The PowerShell files are not digitally signed.** The author header is attribution, not an Authenticode signature. Follow your organisation's signing policy. Do not weaken execution policy to run this download. SHA-256 verifies that your copy matches the published bytes; it does not establish publisher identity by itself.

## Verify the package before running it

Choose **exchange-forwarding-audit-v1.0.1.zip** under Assets. GitHub's **Source code (zip)** is the repository archive, including tests, rather than the ready-to-run package below. Save the ready-to-run ZIP and [release-sha256.txt](https://github.com/TiagoSScarvalho/exchange-online-forwarding-audit/releases/download/v1.0.1/release-sha256.txt) in the same local folder.

Replace the two example folders with approved paths. The download folder must contain both files; the destination must not already exist. A mismatch stops extraction.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'C:\AdminDownloads\ForwardingAudit'
$zip = 'exchange-forwarding-audit-v1.0.1.zip'
$expected = (Get-Content -LiteralPath '.\release-sha256.txt' -Raw).Trim() -split '\s+', 2
if ($expected.Count -ne 2 -or $expected[0] -notmatch '^[a-fA-F0-9]{64}$' -or $expected[1] -ne $zip) {
    throw 'Unexpected ZIP checksum file. Check the release assets.'
}
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $expected[0]) {
    throw 'ZIP checksum mismatch. Do not extract or run this copy.'
}
$destination = 'C:\AdminTools\ForwardingAudit'
if (Test-Path -LiteralPath $destination) { throw 'Choose a new destination folder.' }
Expand-Archive -LiteralPath $zip -DestinationPath $destination
Set-Location -LiteralPath $destination
```

The separate `release-sha256.txt` checks the ZIP. After extraction, `SHA256SUMS.txt` checks four packaged source/documentation files. Expect four rows with `Match = True`:

```powershell
Get-Content -LiteralPath '.\SHA256SUMS.txt' | ForEach-Object {
    $expectedHash, $file = $_ -split '\s+', 2
    $actualHash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) { throw "Checksum mismatch: $file" }
    [pscustomobject]@{ File = $file; Match = $true }
} | Format-Table -AutoSize
```

### If PowerShell says “not digitally signed”

On Windows, check `Get-ExecutionPolicy -List`. With `AllSigned`, use your organisation's review and signing process. With `RemoteSigned`, downloaded files may be blocked by their Internet marking; after reviewing the files, follow the approved unblocking process only if your organisation permits unsigned scripts. Do not switch to Bypass or Unrestricted to run the tool. See [Microsoft's signing documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-7.6).

## Requirements and access

- PowerShell 7.4 or later.
- ExchangeOnlineManagement 3.9.2 or later, imported before running the launcher.
- One direct, unprefixed Exchange Online connection to the expected tenant.
- An Exchange role and mailbox scope that allow the queries listed in [README.txt](README.txt).

Tested on Windows with PowerShell 7.6.9 and ExchangeOnlineManagement 3.9.2. These are this package's requirements, not Microsoft's minimum versions. GDAP, multiple connections, EOP-only sessions, on-premises Exchange and unattended authentication were not validated.

Read-only code still needs permission to read the objects. Microsoft states that `Get-InboxRule` does not work with Global Reader or View-Only Organization Management. Ask your Exchange role administrator to review the commands and scope; do not grant Global Administrator just to run the tool.

## Start with one mailbox

Get your expected tenant ID independently from **Entra admin center > Entra ID > Overview**. Replace the example administrator, mailbox, GUID placeholder and local paths below.

```powershell
Import-Module ExchangeOnlineManagement -MinimumVersion 3.9.2
Connect-ExchangeOnline -UserPrincipalName 'admin@contoso.com'
Get-ConnectionInformation | Select-Object UserPrincipalName, TenantID, State

Set-Location 'C:\AdminTools\ForwardingAudit'
.\Get-ExternalForwardingAudit.ps1 `
    -ExpectedTenantId 'YOUR-TENANT-GUID' `
    -Mailbox 'pilot@contoso.com' `
    -OutputDirectory 'C:\AdminReports\Forwarding'
```

Open `report.html` in the new run folder. Read the coverage status first, then cross-check the selected mailbox and Inbox rules in Exchange/Outlook. The placeholder GUID must be replaced; it is not a runnable tenant value.

After the pilot, explicitly select all active user/shared mailboxes visible to your account:

```powershell
.\Get-ExternalForwardingAudit.ps1 `
    -ExpectedTenantId 'YOUR-TENANT-GUID' `
    -AllMailboxes `
    -OutputDirectory 'C:\AdminReports\Forwarding'

Disconnect-ExchangeOnline -Confirm:$false
```

The collector neither connects nor disconnects automatically. `-AllMailboxes` means mailboxes visible within your RBAC scope; it is not proof of complete tenant coverage.

## Reports

Each run creates its own folder. Reports are local and contain no external assets or scripts.

| File | Purpose |
| --- | --- |
| `report.html` | Overview, findings, coverage and control context. |
| `forwarding.csv` | One row per returned destination, including disabled rules and shadowed SMTP settings. |
| `mailboxes.csv` | Per-mailbox status and interpretation. |
| `coverage.csv` | Query results, counts, UTC start and error categories. |
| `controls.csv` | Outbound spam policies/assignments, remote domains and transport rules. |
| `rule-review.csv` | Unsupported or incomplete rule objects requiring separate review. |
| `audit.json` | Structured selected values, preserving original strings. |

**Zero findings is not a clean security verdict.** Failed queries, warnings, unsupported rules and unattempted reads remain visible. An enabled external candidate is a configured destination, not evidence of delivery or compromise.

## Boundaries that matter

- `ForwardingAddress` takes precedence over `ForwardingSmtpAddress`; the shadowed setting remains in the report.
- Mail contacts and mail users can resolve to an external next hop. Groups are not expanded and downstream mailbox chains are not followed.
- Accepted-domain destinations are not automatically safe.
- Transport-rule actions are context, not part of the mailbox destination counter. The tool does not calculate effective per-message policy precedence.
- Hidden Inbox rules are requested. The numeric result limit is 10,000; reaching it marks coverage incomplete. Unsupported rule objects are retained for review.
- Recipient lookup failures and warnings count as incomplete. Repeated lookups reuse their recorded result within the run.
- After throttling, later network reads are skipped and marked `NotAttempted`. Do not repeatedly rerun the script to force a response.
- Power Automate flows and application-based access or forwarding are outside the inventory.

## Verification and testing

The read-only tenant retest on **11 November 2026** covered five user/shared mailboxes and returned 105 Inbox rule objects. No forwarding destinations were found in the interpretable data. Five unsupported hidden rules remained incomplete. No configuration was changed and delivery was not tested.

Positive forwarding, recipient failures and throttling are exercised separately by **25 offline tests with synthetic data**. These tests are not evidence of those events occurring in the tenant.

Run them from the repository root in a fresh PowerShell 7.4+ process:

```powershell
pwsh -NoProfile -File .\tests\Test-ExternalForwardingAudit.ps1
```

No Exchange connection, credentials, module download or Pester installation is needed. All Exchange query functions are mocked. Test output is written beneath `artifacts/`, which is ignored by Git.

## Report a problem

[Open an issue](https://github.com/TiagoSScarvalho/exchange-online-forwarding-audit/issues) with the tool/module/PowerShell versions, the affected operation and a synthetic reproduction where possible. Remove mailbox addresses, tenant IDs, rule IDs and sensitive policy conditions. Do not attach real reports or authentication output to a public issue.

## Microsoft references

- [Get-InboxRule and role limitations](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule)
- [Exchange Online cmdlet property sets](https://learn.microsoft.com/en-us/powershell/exchange/cmdlet-property-sets)
- [Get-EXORecipient](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exorecipient)
- [Set-Mailbox forwarding properties](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-mailbox)
- [Control automatic external forwarding](https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding)
- [Find permissions required by Exchange cmdlets](https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions)
- [Connect to Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell)
- [Exchange Team: automatic email forwarding](https://techcommunity.microsoft.com/blog/exchange/all-you-need-to-know-about-automatic-email-forwarding-in-exchange-online/2074888)
