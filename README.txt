EXCHANGE ONLINE EXTERNAL FORWARDING AUDIT
Version 1.0.1 | Tiago Carvalho | https://www.tiagoscarvalho.com | 11 November 2026

PURPOSE
Inventory forwarding configuration with local HTML, CSV and JSON reports.
Only Get-* Exchange cmdlets are used. No tenant settings, grants, rules or
messages are changed. The tool does not read message bodies or send email.
Authentication and any module installation are separate administrator steps.

REQUIREMENTS
PowerShell 7.4 or later. ExchangeOnlineManagement 3.9.2 or later loaded.
Tested on Windows, PowerShell 7.6.9, ExchangeOnlineManagement 3.9.2.
These are this package's requirements, not a statement of Microsoft's minimum.
Use a fresh shell with one direct, unprefixed Exchange Online connection.
GDAP, multiple connections, EOP-only sessions, on-premises and unattended
authentication were not validated by this release.

Keep Get-ExternalForwardingAudit.ps1 and ExternalForwardingAudit.psm1 together.
Review both source files before use. Compare SHA256SUMS.txt with Get-FileHash.
The files are unsigned. Follow your organization's script-signing policy;
do not weaken execution policy to run this download.
The attribution header identifies the publisher; it is not an Authenticode signature.

CONNECT AND RUN
Replace the example admin, tenant GUID and mailbox with your own values.
Obtain the expected tenant ID independently from Entra Overview; do not just
copy whichever connection happens to be active.

Import-Module ExchangeOnlineManagement -MinimumVersion 3.9.2
Connect-ExchangeOnline -UserPrincipalName 'admin@contoso.com'
Get-ConnectionInformation | Select-Object UserPrincipalName,TenantID,State

Set-Location 'C:\AdminTools\ForwardingAudit'
.\Get-ExternalForwardingAudit.ps1 -ExpectedTenantId 'YOUR-TENANT-GUID' -Mailbox 'pilot@contoso.com' -OutputDirectory 'C:\AdminReports\Forwarding'

After the pilot, select all visible active user and shared mailboxes explicitly:
.\Get-ExternalForwardingAudit.ps1 -ExpectedTenantId 'YOUR-TENANT-GUID' -AllMailboxes -OutputDirectory 'C:\AdminReports\Forwarding'

Disconnect-ExchangeOnline -Confirm:$false

Do not run the examples with the literal placeholder GUID. The collector fails
before collection when tenant or connection type does not match. It neither
connects nor disconnects automatically. A WAM-specific authentication failure
can be investigated using Microsoft's Connect-ExchangeOnline documentation;
-DisableWAM was used for the local pilot. MFA and tenant policy still apply.

PERMISSIONS
Read-only code is not the same as a read-only administrator role.
Get-InboxRule does not work with Global Reader or View-Only Organization
Management according to Microsoft. Have your Exchange role administrator
review the cmdlets and scope below; do not grant Global Administrator simply
to run this tool. Successful reads remain limited by the caller's RBAC scope.

Queries: Get-ConnectionInformation; Get-EXOMailbox; Get-InboxRule;
Get-EXORecipient (when a next hop needs resolution); Get-AcceptedDomain;
Get-HostedOutboundSpamFilterPolicy; Get-HostedOutboundSpamFilterRule;
Get-RemoteDomain; Get-TransportRule.

OUTPUTS
Each run creates a new audit-UTC-random folder:
report.html       Local, self-contained report. No external assets or scripts.
forwarding.csv    One row per returned forwarding destination, including
                  disabled rules and shadowed SMTP mailbox settings.
mailboxes.csv     Per-mailbox query status and interpretation.
coverage.csv      Query status, returned count, UTC start and error category.
controls.csv      Outbound policies/assignments, remote domains, transport rules.
rule-review.csv   Rules the command does not fully support or whose required
                  properties were absent. These are not classified as malicious.
audit.json        Structured selected values. Original strings are preserved.

Interpret coverage first. Partial collection is NOT a clean security verdict.
Zero destination rows means none were found in the returned interpretable data.
It is not evidence that no forwarding can exist or that nothing was delivered.
Enabled external candidates counts destinations outside the accepted-domain
inventory; it does not determine message delivery or business approval.

ForwardingAddress takes precedence over ForwardingSmtpAddress. Mail contacts
and mail users may resolve to ExternalEmailAddress. Groups are not expanded;
downstream mailbox forwarding chains are not followed. Accepted-domain routes
are not automatically safe. Transport-rule actions are context, not included
in the mailbox destination counter. Automatic policy values remain Automatic.
No effective per-message policy evaluation or precedence engine is implemented.

Inbox rules include hidden rules. This version requests a numeric limit of
10,000 because the pilot's REST command rejected ResultSize Unlimited. If the
limit is reached, coverage is marked incomplete. Unsupported rules and provider
warnings also remain incomplete. Errors are not converted to successful zeroes.
Each unique recipient lookup is recorded as Recipient:... in coverage.csv.
Failed, unavailable or warning-bearing lookups increase the incomplete count.
Repeated lookups reuse the recorded result within the run, including failures.
Once a read returns a throttling error, all later network reads are skipped,
including recipient lookups and control queries, and marked NotAttempted.
The tool can still interpret data already returned before the throttle.
Wait as directed by your service administrator and rerun the affected scope;
do not loop the script repeatedly to force a response.

Power Automate flows and application-based mail access or forwarding are outside
this inventory. Review those separately in the relevant administration and audit
tools. An Exchange configuration audit does not cover every way to copy email.

WORKED EXAMPLE (SIMULATED)
An enabled Inbox rule named Supplier copy uses ForwardTo contact@contoso.com.
The lookup resolves that mail contact to contact@external.example. The row is
ExternalDomain / Resolved and adds one enabled external candidate. DeliveryEvidence
remains NotTested. This is an offline fixture, not a finding from the tenant.
Check the rule conditions and priority, confirm the contact and business approval,
review the applicable controls, then use message trace for a specific message.
An enabled route alone does not establish delivery or compromise.

PRIVACY AND HANDLING
Reports can contain addresses, rule descriptions, IDs and policy conditions.
Store them in an approved private administration location. This package
contains no tenant report, authentication token or user data.
HTML escapes dynamic values. CSV neutralizes formula-leading cells with an
apostrophe. JSON contains unmodified selected text. Do not publish raw reports.
No access token is deliberately logged or exported by the collector.

VALIDATION
The 11 November 2026 tenant run queried five active user/shared mailboxes,
returning 105 Inbox rule objects. Five Junk E-mail Rule objects reported
SupportedByTask=false and were retained in rule-review.csv. No forwarding
destinations appeared in the interpretable returned data. Delivery was not
tested, and no configuration was changed. Offline fixtures separately exercise
positive forwarding, disabled rules, contacts, groups, precedence, failures,
warnings, limits and output escaping. Those fixtures are not tenant evidence.
Version 1.0.1 passes 25 offline tests, including failed/warning-bearing recipient
lookups, lookup caching, the worked example and stopping reads after throttling
at the domain, mailbox, Inbox-rule, recipient and policy stages.
The v1.0.1 live retest at 19:37 UTC on 11 November returned the same five-mailbox,
105-rule, zero-destination result with five unsupported rules. No main query failed.
This retest did not exercise recipient failures against the live service.

MICROSOFT REFERENCES
https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule
https://learn.microsoft.com/en-us/powershell/exchange/cmdlet-property-sets
https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exorecipient
https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-mailbox
https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding
https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions
https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell
https://techcommunity.microsoft.com/blog/exchange/all-you-need-to-know-about-automatic-email-forwarding-in-exchange-online/2074888

CHANGELOG
1.0.1: Include recipient-query failures and warnings in coverage and incomplete
counts; stop later network reads after throttling; preserve cached lookup outcomes.
Add publisher attribution, a simulated worked example and app/flow scope limits.
1.0.0: Initial review release. Read-only inventory, explicit coverage, numeric
Inbox-rule limit, unsupported-rule review list, HTML/CSV/JSON outputs.
