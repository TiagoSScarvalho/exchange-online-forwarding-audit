#requires -Version 7.4
# Tiago Carvalho | https://www.tiagoscarvalho.com | MIT
Set-StrictMode -Version Latest
$script:Version = '1.0.1'

function Get-Field($Object,[string]$Name,$Default='') {
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}
function ConvertTo-AuditText($Value) {
    if ($null -eq $Value) { return '' }
    return (@($Value) | ForEach-Object { [string]$_ }) -join '; '
}
function ConvertTo-SmtpAddress($Value) {
    $s = ([string]$Value).Trim()
    if ($s -match '(?i)\[SMTP:([^\]\s]+@[^\]\s]+)\]') { $s = $Matches[1] }
    $s = $s -replace '^(?i)smtp:',''
    if ($s -match '^[^\s<>@;]+@[^\s<>@;]+\.[^\s<>@;]+$') { return $s.ToLowerInvariant() }
    return ''
}
function Get-ErrorKind($Record) {
    # Keep raw error details out of reports.
    $message = [string]$Record.Exception.Message
    if ($message -match '(?i)429|throttl|too many requests|server busy') { return 'Throttled' }
    if ($message -match '(?i)403|unauthori|access.*denied|permission|not.*authorized') { return 'AccessDenied' }
    if ($message -match '(?i)not.*found|couldn.t be found|does not exist|404') { return 'NotFound' }
    return 'QueryFailed'
}
function Read-AuditSection([string]$Name,[string]$Command,[scriptblock]$Read,[hashtable]$Context) {
    $started = [datetime]::UtcNow.ToString('o')
    if ($Context.Throttled) {
        $section = [pscustomobject]@{Name=$Name;Status='NotAttempted';Count=$null;ErrorKind='StoppedAfterThrottling';StartedUtc='';Data=@()}
    } elseif (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        $section = [pscustomobject]@{Name=$Name;Status='Unavailable';Count=$null;ErrorKind='CommandUnavailable';StartedUtc=$started;Data=@()}
    } else {
        try {
            $data = @(& $Read 3>&1)
            $warnings = @($data | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            $data = @($data | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
            $section = [pscustomobject]@{Name=$Name;Status=$(if($warnings.Count){'ReadWithWarnings'}else{'ReadSucceeded'});Count=$data.Count;ErrorKind=$(if($warnings.Count){'ProviderWarning'}else{''});StartedUtc=$started;Data=$data}
        } catch {
            $section = [pscustomobject]@{Name=$Name;Status='Failed';Count=$null;ErrorKind=(Get-ErrorKind $_);StartedUtc=$started;Data=@()}
        }
    }
    $Context.Coverage.Add($section)
    if ($section.ErrorKind -eq 'Throttled') { $Context.Throttled = $true }
    return $section
}
function Test-AcceptedDomain([string]$Domain,$Domains) {
    foreach ($d in @($Domains)) {
        $pattern = ([string](Get-Field $d 'DomainName')).ToLowerInvariant()
        if ($Domain -eq $pattern) { return $true }
        $suffix = $pattern -replace '^\*\.',''
        if (($pattern.StartsWith('*.') -or (Get-Field $d 'MatchSubDomains' $false) -eq $true) -and $Domain.EndsWith('.'+$suffix)) { return $true }
    }
    return $false
}
function Resolve-AuditTarget($Value,$DomainSection,[hashtable]$Cache,[hashtable]$Context) {
    $raw = ConvertTo-AuditText $Value
    $address = ConvertTo-SmtpAddress (Get-Field $Value 'Address' $raw)
    if (-not $address) { $address = ConvertTo-SmtpAddress $raw }
    $identity = [string](Get-Field $Value 'RawIdentity' $raw)
    if ($address) { $identity = $address }
    if ([string]::IsNullOrWhiteSpace($identity) -or $identity -match '[*?]') {
        return [pscustomobject]@{Destination=$raw;NextHop='';Classification='Unresolved';Detail='Empty or wildcard recipient identifier';Resolution='Incomplete'}
    }
    if ($Cache.ContainsKey($identity)) { return $Cache[$identity] }
    $domainKnown = $DomainSection.Status -eq 'ReadSucceeded'
    if ($address -and $domainKnown -and -not (Test-AcceptedDomain $address.Split('@')[-1] $DomainSection.Data)) {
        $result = [pscustomobject]@{Destination=$raw;NextHop=$address;Classification='ExternalDomain';Detail='SMTP domain is outside the accepted-domain inventory';Resolution='Resolved'}
    } else {
        $recipient = Read-AuditSection "Recipient:$identity" 'Get-EXORecipient' {
            Get-EXORecipient -Identity $identity -Properties ExternalEmailAddress,PrimarySmtpAddress,RecipientTypeDetails -ErrorAction Stop -WarningAction Continue
        } $Context
        if ($recipient.Status -eq 'ReadSucceeded' -and $recipient.Data.Count -eq 1) {
            $r = $recipient.Data[0]
            $type = [string](Get-Field $r 'RecipientTypeDetails')
            $external = ConvertTo-SmtpAddress (Get-Field $r 'ExternalEmailAddress')
            $primary = ConvertTo-SmtpAddress (Get-Field $r 'PrimarySmtpAddress')
            if ($type -match 'Group') {
                $result = [pscustomobject]@{Destination=$raw;NextHop=$primary;Classification='GroupNotExpanded';Detail='Group membership and subsequent routes require separate review';Resolution='Unexpanded'}
            } elseif ($external) {
                $classification = if (-not $domainKnown) {'DomainUnknown'} elseif (Test-AcceptedDomain $external.Split('@')[-1] $DomainSection.Data) {'AcceptedDomainRoute'} else {'ExternalDomain'}
                $result = [pscustomobject]@{Destination=$raw;NextHop=$external;Classification=$classification;Detail="Recipient type: $type; uses ExternalEmailAddress; later hops not followed";Resolution=$(if($domainKnown){'Resolved'}else{'Incomplete'})}
            } elseif ($type -match 'Mailbox' -and $primary) {
                $result = [pscustomobject]@{Destination=$raw;NextHop=$primary;Classification='MailboxNextHop';Detail='Mailbox recipient resolved; downstream forwarding is not followed';Resolution='Resolved'}
            } else {
                $result = [pscustomobject]@{Destination=$raw;NextHop=$primary;Classification='Unresolved';Detail="Recipient type $type requires further inspection";Resolution='Incomplete'}
            }
        } else {
            $result = [pscustomobject]@{Destination=$raw;NextHop=$address;Classification='Unresolved';Detail=('Recipient query: '+$recipient.Status+' / '+$recipient.ErrorKind);Resolution='Incomplete'}
        }
    }
    $Cache[$identity] = $result
    return $result
}
function New-AuditFinding($Mailbox,[string]$Source,$Rule,[string]$Action,$Target,[string]$ConfiguredState,[string]$Note) {
    [pscustomobject][ordered]@{
        Mailbox=$Mailbox;Source=$Source;RuleName=(Get-Field $Rule 'Name');RuleId=(ConvertTo-AuditText (Get-Field $Rule 'Identity'))
        Priority=(Get-Field $Rule 'Priority');ConfiguredState=$ConfiguredState;Action=$Action
        Destination=$Target.Destination;NextHop=$Target.NextHop;Classification=$Target.Classification;Resolution=$Target.Resolution
        StopProcessingRules=(Get-Field $Rule 'StopProcessingRules');DeliverToMailboxAndForward=(Get-Field $Rule 'DeliverToMailboxAndForward')
        RuleDescription=(Get-Field $Rule 'Description');Notes=($Note+' '+$Target.Detail).Trim();DeliveryEvidence='NotTested'
    }
}
function ConvertTo-SafeCsvCell($Value) {
    $text = ConvertTo-AuditText $Value
    # Prevent Excel from treating exported text as a formula.
    if ($text -match '^[\s\x00-\x1f]*[=+@-]' -or $text -match '^[\t\r\n]') { return "'"+$text }
    return $text
}
function Write-AuditCsv([string]$Path,[object[]]$Rows,[string[]]$Columns) {
    $safe = @($Rows | ForEach-Object {
        $row=$_; $cells=[ordered]@{}
        foreach($column in $Columns){$cells[$column]=ConvertTo-SafeCsvCell (Get-Field $row $column)}
        [pscustomobject]$cells
    })
    if ($safe.Count) { $safe | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8BOM }
    else { [IO.File]::WriteAllText($Path,(($Columns|ForEach-Object{'"'+$_+'"'}) -join ',')+"`r`n",[Text.UTF8Encoding]::new($true)) }
}
function ConvertTo-AuditTable($Rows,[string[]]$Columns) {
    if (@($Rows).Count -eq 0) { return '<p>No rows returned. Check query coverage before interpreting this result.</p>' }
    $builder=[Text.StringBuilder]::new()
    [void]$builder.Append('<div class="table-wrap" tabindex="0" role="region" aria-label="Scrollable audit table"><table><thead><tr>')
    foreach($c in $Columns){[void]$builder.Append('<th>'+[Net.WebUtility]::HtmlEncode($c)+'</th>')}
    [void]$builder.Append('</tr></thead><tbody>')
    foreach($r in @($Rows)){
        [void]$builder.Append('<tr>')
        foreach($c in $Columns){[void]$builder.Append('<td>'+[Net.WebUtility]::HtmlEncode((ConvertTo-AuditText (Get-Field $r $c)))+'</td>')}
        [void]$builder.Append('</tr>')
    }
    [void]$builder.Append('</tbody></table></div>')
    return $builder.ToString()
}
function Export-AuditReport($Report,[string]$OutputDirectory) {
    $directory=Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) ('audit-'+[datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    $columns=@('Mailbox','Source','RuleName','RuleId','Priority','ConfiguredState','Action','Destination','NextHop','Classification','Resolution','StopProcessingRules','DeliverToMailboxAndForward','RuleDescription','Notes','DeliveryEvidence')
    Write-AuditCsv (Join-Path $directory 'forwarding.csv') @($Report.Findings) $columns
    Write-AuditCsv (Join-Path $directory 'coverage.csv') @($Report.Coverage) @('Name','Status','Count','ErrorKind','StartedUtc')
    Write-AuditCsv (Join-Path $directory 'mailboxes.csv') @($Report.Mailboxes) @('Mailbox','MailboxStatus','InboxRulesStatus','RulesReturned','ForwardingRows','Interpretation')
    Write-AuditCsv (Join-Path $directory 'controls.csv') @($Report.Controls) @('Type','Name','State','Priority','Policy','AutoForwardingMode','Domain','AutoForwardEnabled','Scope','Exceptions','Details')
    Write-AuditCsv (Join-Path $directory 'rule-review.csv') @($Report.RuleReview) @('Mailbox','RuleName','RuleId','Enabled','Reason')
    [IO.File]::WriteAllText((Join-Path $directory 'audit.json'),($Report|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    $e={param($s)[Net.WebUtility]::HtmlEncode([string]$s)}
    $html=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Exchange Online External Forwarding Audit</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#18324c;font:16px/1.55 system-ui,sans-serif}main{max-width:1400px;margin:auto;padding:28px}h1{line-height:1.15;max-width:850px;font-size:clamp(28px,4vw,44px)}h2{margin-top:40px}a{color:#075e85}.badge{padding:7px 12px;border:1px solid #c4d5e6;border-radius:18px;display:inline-block;background:white}.note{padding:18px;background:#fff5dc;border-left:5px solid #a86a00}.cards{display:flex;gap:16px;flex-wrap:wrap}.card{background:white;padding:18px;min-width:170px;border-radius:8px;border:1px solid #d3dfeb}.card strong{display:block;font-size:28px}.table-wrap{overflow:auto;background:white;border:1px solid #d3dfeb}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:10px;border-bottom:1px solid #d3dfeb;text-align:left;vertical-align:top;min-width:110px;max-width:430px;overflow-wrap:anywhere}th{background:#e9f1f8}nav{display:flex;gap:16px;flex-wrap:wrap}.muted{color:#526b80}footer{margin-top:35px;font-size:13px}@media(max-width:600px){main{padding:16px}.cards{gap:8px}.card{min-width:145px;flex:1}}</style></head><body><main>
<p class="muted">TIAGO S. CARVALHO · ADMIN TOOLS · v$($Report.Version)</p><h1>Exchange Online External Forwarding Audit</h1>
<p class="badge">$(& $e $Report.Status)</p><p>Collected UTC: $(& $e $Report.GeneratedUtc)<br>Tenant: $(& $e $Report.TenantId)<br>Scope: $(& $e $Report.Scope)</p>
<div class="cards"><div class="card"><strong>$($Report.Mailboxes.Count)</strong>Mailbox checks</div><div class="card"><strong>$($Report.Findings.Count)</strong>Configured destinations</div><div class="card"><strong>$($Report.ExternalCandidates)</strong>Enabled external candidates</div><div class="card"><strong>$($Report.IncompleteSections)</strong>Incomplete queries</div></div>
<p class="note">Configuration inventory only. Delivery was not tested. A successful query means the provider returned successfully within your RBAC scope; it does not prove complete tenant visibility. Disabled and shadowed settings remain visible. Group expansion, forwarding chains, client-only rules and effective per-message policy evaluation require further investigation. Power Automate flows and app-based mail access or forwarding are outside this inventory.</p>
<nav aria-label="Report sections"><a href="#mailboxes">Mailbox coverage</a><a href="#findings">Destinations</a><a href="#controls">Controls</a><a href="#coverage">Query status</a></nav>
<h2 id="mailboxes">1. Mailbox coverage</h2>$(ConvertTo-AuditTable $Report.Mailboxes @('Mailbox','MailboxStatus','InboxRulesStatus','RulesReturned','ForwardingRows','Interpretation'))
<h2 id="findings">2. Configured destinations</h2><p>EnabledExternalCandidates counts only enabled, non-shadowed entries classified ExternalDomain. An enabled Inbox rule still needs a matching message and may be affected by earlier rules.</p>$(ConvertTo-AuditTable $Report.Findings @('Mailbox','Source','RuleName','ConfiguredState','Action','NextHop','Classification','Resolution','Notes'))
<h3>Rules requiring separate inspection</h3><p>Unsupported or incomplete rule objects remain listed here. A familiar rule name alone is not evidence that all of its actions were inspected.</p>$(ConvertTo-AuditTable $Report.RuleReview @('Mailbox','RuleName','RuleId','Enabled','Reason'))
<h2 id="controls">3. Controls and assignment context</h2><p>These are collected settings, not an effective-policy verdict. Assignment conditions, exclusions, priority and group membership must be checked. Automatic is reported literally; it is not converted to Off. Transport-rule recipient actions are shown here, outside the mailbox-destination count.</p>$(ConvertTo-AuditTable $Report.Controls @('Type','Name','State','Priority','Policy','AutoForwardingMode','Domain','AutoForwardEnabled','Scope','Exceptions','Details'))
<h2 id="coverage">4. Query status</h2><p>Failed, unavailable and warning-bearing sections, including recipient lookups, are incomplete. Repeated recipient lookups reuse the first result within this run. Once a read returns a throttling error, later network reads are not attempted; processing of already returned data can continue. Re-run after resolving the specific access or service problem. No automatic remediation is performed.</p>$(ConvertTo-AuditTable $Report.Coverage @('Name','Status','Count','ErrorKind','StartedUtc'))
<footer>Local report. It can contain mailbox addresses, rule descriptions and policy scope. Keep it in your approved administration storage. HTML values are escaped; CSV formula-leading strings are prefixed with an apostrophe. JSON preserves the original selected values.</footer></main></body></html>
"@
    [IO.File]::WriteAllText((Join-Path $directory 'report.html'),$html,[Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{Directory=$directory;Report=(Join-Path $directory 'report.html');Status=$Report.Status;Mailboxes=$Report.Mailboxes.Count;Findings=$Report.Findings.Count;IncompleteSections=$Report.IncompleteSections}
}
function Invoke-ExternalForwardingAudit {
    [CmdletBinding(DefaultParameterSetName='Selected')]
    param(
        [Parameter(Mandatory,ParameterSetName='Selected')][ValidateNotNullOrEmpty()][string[]]$Mailbox,
        [Parameter(Mandatory,ParameterSetName='All')][switch]$AllMailboxes,
        [Parameter(Mandatory)][guid]$ExpectedTenantId,
        [string]$OutputDirectory=(Join-Path (Get-Location) 'forwarding-audit'),
        [ValidateRange(0,5000)][int]$DelayMilliseconds=250
    )
    if($ExpectedTenantId -eq [guid]::Empty){throw 'ExpectedTenantId must identify your tenant.'}
    if(-not $AllMailboxes){foreach($m in @($Mailbox)) { if([string]::IsNullOrWhiteSpace($m) -or -not (ConvertTo-SmtpAddress $m) -or $m -match '[*?]'){throw 'Use exact primary SMTP addresses, without wildcards.'} }}
    $connections=@(Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' })
    if($connections.Count -ne 1){throw 'Use a fresh PowerShell window with exactly one Exchange Online connection.'}
    $connection=$connections[0]
    if([string](Get-Field $connection 'TenantID') -ne [string]$ExpectedTenantId -or (Get-Field $connection 'IsEopSession' $false) -eq $true -or (Get-Field $connection 'ModulePrefix') -ne '' -or (Get-Field $connection 'DelegatedOrganization') -ne ''){throw 'Tenant or connection type does not match. Use one direct, unprefixed Exchange Online connection to the expected tenant.'}
    $coverage=[Collections.Generic.List[object]]::new();$findings=[Collections.Generic.List[object]]::new();$summaries=[Collections.Generic.List[object]]::new();$controls=[Collections.Generic.List[object]]::new();$ruleReview=[Collections.Generic.List[object]]::new();$cache=@{}
    $context=@{Coverage=$coverage;Throttled=$false}
    $domains=Read-AuditSection 'AcceptedDomains' 'Get-AcceptedDomain' {Get-AcceptedDomain -ErrorAction Stop -WarningAction Continue} $context
    if($domains.Status -eq 'ReadSucceeded' -and $domains.Data.Count -eq 0){$domains.Status='Incomplete';$domains.ErrorKind='AcceptedDomainInventoryEmpty'}
    if($AllMailboxes){
        $mailboxSection=Read-AuditSection 'MailboxEnumeration' 'Get-EXOMailbox' {
            Get-EXOMailbox -RecipientTypeDetails UserMailbox,SharedMailbox -ResultSize Unlimited -Properties ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward -ErrorAction Stop -WarningAction Continue
        } $context
        $targets=@($mailboxSection.Data)
    }else{$targets=@($Mailbox | Sort-Object -Unique)}
    foreach($entry in $targets){
        $requested=if($AllMailboxes){[string](Get-Field $entry 'PrimarySmtpAddress')}else{[string]$entry}
        if($DelayMilliseconds){Start-Sleep -Milliseconds $DelayMilliseconds}
        if($AllMailboxes -and -not $context.Throttled){
            $ms=[pscustomobject]@{Name="Mailbox:$requested";Status='ReadSucceeded';Count=1;ErrorKind='';StartedUtc=$mailboxSection.StartedUtc;Data=@($entry)}
            $coverage.Add($ms)
        }else{
            $ms=Read-AuditSection "Mailbox:$requested" 'Get-EXOMailbox' {Get-EXOMailbox -PrimarySmtpAddress $requested -Properties ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward -ErrorAction Stop -WarningAction Continue} $context
        }
        if($ms.Status -eq 'ReadSucceeded' -and ($ms.Data.Count -ne 1 -or [string](Get-Field $ms.Data[0] 'PrimarySmtpAddress') -ne $requested)){$ms.Status='Failed';$ms.ErrorKind='MailboxIdentityMismatch'}
        $before=$findings.Count
        if($ms.Status -eq 'ReadSucceeded'){
            $mb=$ms.Data[0]
            foreach($required in @('ForwardingAddress','ForwardingSmtpAddress','DeliverToMailboxAndForward')){if(-not $mb.PSObject.Properties[$required]){$ms.Status='Incomplete';$ms.ErrorKind='RequiredPropertyMissing'}}
            if($ms.Status -eq 'ReadSucceeded'){
                $fa=Get-Field $mb 'ForwardingAddress';$smtp=Get-Field $mb 'ForwardingSmtpAddress'
                if($fa){$findings.Add((New-AuditFinding $requested 'Mailbox' $mb 'ForwardingAddress' (Resolve-AuditTarget $fa $domains $cache $context) 'Enabled' 'Takes precedence over ForwardingSmtpAddress.'))}
                if($smtp){$state=if($fa){'Shadowed'}else{'Enabled'};$findings.Add((New-AuditFinding $requested 'Mailbox' $mb 'ForwardingSmtpAddress' (Resolve-AuditTarget $smtp $domains $cache $context) $state $(if($fa){'Ignored while ForwardingAddress is populated.'}else{''})))}
            }
        }
        # The pilot failed with Unlimited; flag results that reach this numeric limit.
        $rs=Read-AuditSection "InboxRules:$requested" 'Get-InboxRule' {Get-InboxRule -Mailbox $requested -IncludeHidden -ResultSize 10000 -ErrorAction Stop -WarningAction Continue} $context
        if($rs.Status -eq 'ReadSucceeded' -and $rs.Data.Count -ge 10000){$rs.Status='Incomplete';$rs.ErrorKind='InboxRuleResultLimitReached'}
        foreach($rule in @($rs.Data)){
            $ruleIssues=[Collections.Generic.List[string]]::new()
            foreach($required in @('ForwardTo','RedirectTo','ForwardAsAttachmentTo','Enabled')){if(-not $rule.PSObject.Properties[$required]){$rs.Status='Incomplete';$rs.ErrorKind='RequiredPropertyMissing';$ruleIssues.Add('Missing '+$required)}}
            if((Get-Field $rule 'SupportedByTask' $true) -eq $false){$rs.Status='Incomplete';$rs.ErrorKind='UnsupportedRule';$ruleIssues.Add('SupportedByTask is false')}
            if($ruleIssues.Count){$ruleReview.Add([pscustomobject]@{Mailbox=$requested;RuleName=(Get-Field $rule 'Name');RuleId=(ConvertTo-AuditText (Get-Field $rule 'Identity'));Enabled=(Get-Field $rule 'Enabled');Reason=($ruleIssues -join '; ')})}
            foreach($action in @('ForwardTo','RedirectTo','ForwardAsAttachmentTo')){
                foreach($target in @(Get-Field $rule $action @())){
                    if(-not $target){continue}
                    $enabled=Get-Field $rule 'Enabled' $null
                    $state=if($enabled -eq $true){'Enabled'}elseif($enabled -eq $false){'Disabled'}else{'Unknown'}
                    $findings.Add((New-AuditFinding $requested 'InboxRule' $rule $action (Resolve-AuditTarget $target $domains $cache $context) $state 'Conditions, exceptions and earlier StopProcessingRules can affect execution.'))
                }
            }
        }
        $count=$findings.Count-$before
        $incompleteTargets=@($findings | Select-Object -Skip $before | Where-Object Resolution -eq 'Incomplete').Count
        $interpretation=if($ms.Status -ne 'ReadSucceeded' -or $rs.Status -ne 'ReadSucceeded' -or $incompleteTargets){'Incomplete: do not infer absence'}elseif($count){'Configured destinations found; delivery not tested'}else{'No mailbox/Inbox forwarding found in returned data'}
        $summaries.Add([pscustomobject]@{Mailbox=$requested;MailboxStatus=$ms.Status;InboxRulesStatus=$rs.Status;RulesReturned=$rs.Count;ForwardingRows=$count;Interpretation=$interpretation})
        Write-Progress -Activity 'Read-only forwarding audit' -Status "$($summaries.Count) of $($targets.Count) mailbox checks" -PercentComplete (100*$summaries.Count/[Math]::Max(1,$targets.Count))
        if($context.Throttled){
            foreach($remaining in @($targets | Select-Object -Skip $summaries.Count)){
                $address=if($AllMailboxes){[string](Get-Field $remaining 'PrimarySmtpAddress')}else{[string]$remaining}
                $summaries.Add([pscustomobject]@{Mailbox=$address;MailboxStatus='NotAttempted';InboxRulesStatus='NotAttempted';RulesReturned=$null;ForwardingRows=0;Interpretation='Stopped after throttling; rerun this mailbox later'})
                $null=Read-AuditSection "Mailbox:$address" 'Get-EXOMailbox' {} $context
                $null=Read-AuditSection "InboxRules:$address" 'Get-InboxRule' {} $context
            };break
        }
    }
    Write-Progress -Activity 'Read-only forwarding audit' -Completed
    $policies=Read-AuditSection 'OutboundSpamPolicies' 'Get-HostedOutboundSpamFilterPolicy' {Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop -WarningAction Continue} $context
    $assignments=Read-AuditSection 'OutboundSpamAssignments' 'Get-HostedOutboundSpamFilterRule' {Get-HostedOutboundSpamFilterRule -ErrorAction Stop -WarningAction Continue} $context
    $remote=Read-AuditSection 'RemoteDomains' 'Get-RemoteDomain' {Get-RemoteDomain -ErrorAction Stop -WarningAction Continue} $context
    $transport=Read-AuditSection 'TransportRules' 'Get-TransportRule' {Get-TransportRule -ResultSize Unlimited -ErrorAction Stop -WarningAction Continue} $context
    foreach($p in $policies.Data){$controls.Add([pscustomobject]@{Type='OutboundPolicy';Name=(Get-Field $p 'Name');AutoForwardingMode=(Get-Field $p 'AutoForwardingMode');Details=('IsDefault: '+(Get-Field $p 'IsDefault'))})}
    foreach($a in $assignments.Data){$controls.Add([pscustomobject]@{Type='OutboundAssignment';Name=(Get-Field $a 'Name');State=(Get-Field $a 'State');Priority=(Get-Field $a 'Priority');Policy=(ConvertTo-AuditText (Get-Field $a 'HostedOutboundSpamFilterPolicy'));Scope=('From: '+(ConvertTo-AuditText (Get-Field $a 'From'))+' | FromMemberOf: '+(ConvertTo-AuditText (Get-Field $a 'FromMemberOf'))+' | SenderDomainIs: '+(ConvertTo-AuditText (Get-Field $a 'SenderDomainIs')));Exceptions=('From: '+(ConvertTo-AuditText (Get-Field $a 'ExceptIfFrom'))+' | FromMemberOf: '+(ConvertTo-AuditText (Get-Field $a 'ExceptIfFromMemberOf'))+' | SenderDomainIs: '+(ConvertTo-AuditText (Get-Field $a 'ExceptIfSenderDomainIs')))})}
    foreach($d in $remote.Data){$controls.Add([pscustomobject]@{Type='RemoteDomain';Name=(Get-Field $d 'Name');Domain=([string](Get-Field $d 'DomainName'));AutoForwardEnabled=(Get-Field $d 'AutoForwardEnabled')})}
    foreach($t in $transport.Data){
        $actions=@('RedirectMessageTo','CopyTo','BlindCopyTo','AddToRecipients')|ForEach-Object{$v=ConvertTo-AuditText (Get-Field $t $_);if($v){$_+': '+$v}}
        $controls.Add([pscustomobject]@{Type='TransportRule';Name=(Get-Field $t 'Name');State=(Get-Field $t 'State');Priority=(Get-Field $t 'Priority');Details=('Mode: '+(Get-Field $t 'Mode')+' | '+($actions -join ' | ')+' | '+(Get-Field $t 'Description'))})
    }
    $incomplete=@($coverage|Where-Object Status -ne 'ReadSucceeded').Count
    $unresolved=@($findings|Where-Object Resolution -in @('Incomplete','Unexpanded')).Count
    $report=[pscustomobject][ordered]@{
        Version=$script:Version;GeneratedUtc=[datetime]::UtcNow.ToString('o');TenantId=[string]$ExpectedTenantId
        Scope=$(if($AllMailboxes){'Visible active UserMailbox and SharedMailbox objects; RBAC-limited'}else{'Selected primary SMTP addresses'})
        Status=$(if($incomplete){'Partial collection'}elseif($unresolved){'Queries completed; destinations need review'}else{'Queries completed within selected scope'})
        IncompleteSections=$incomplete;UnresolvedDestinations=$unresolved
        ExternalCandidates=@($findings|Where-Object{$_.ConfiguredState -eq 'Enabled' -and $_.Classification -eq 'ExternalDomain'}).Count
        Mailboxes=@($summaries.ToArray());Findings=@($findings.ToArray());Controls=@($controls.ToArray());RuleReview=@($ruleReview.ToArray())
        Coverage=@($coverage|Select-Object Name,Status,Count,ErrorKind,StartedUtc)
        Limitations=@('Configuration only; no message content or delivery test','RBAC can limit successful results','No group expansion or forwarding-chain traversal','No effective-policy or transport-rule simulation','Client-only rules and on-premises configuration not collected','Power Automate flows and app-based mail access or forwarding not collected')
    }
    if($incomplete){Write-Warning "$incomplete query sections are incomplete. See coverage.csv."}
    Export-AuditReport $report $OutputDirectory
}
Export-ModuleMember -Function Invoke-ExternalForwardingAudit

