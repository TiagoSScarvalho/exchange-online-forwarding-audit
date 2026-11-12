#requires -Version 7.4
# Offline contract tests. Every Exchange query is mocked in the imported module.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../ExternalForwardingAudit.psm1') -Force
$module=Get-Module ExternalForwardingAudit
$testRoot=Join-Path $PSScriptRoot '../artifacts/offline-tests'
$tenant='00000000-0000-0000-0000-000000000001'
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Run-Test([string]$Name,[scriptblock]$Body){& $Body;$results.Add([pscustomobject]@{Name=$Name;Passed=$true});Write-Host "PASS $Name"}
& $module {
    $script:scenario='clean';$script:tenant='00000000-0000-0000-0000-000000000001';$script:reads=0
    $script:calls=[Collections.Generic.List[string]]::new();$script:throttledAt=0
    function script:Add-Query([string]$Name){$script:calls.Add($Name)}
    function script:Stop-Fixture { $script:throttledAt=$script:calls.Count;throw '429 Too many requests' }
    function script:Get-ConnectionInformation { [CmdletBinding()]param();[pscustomobject]@{State='Connected';TenantID=$script:tenant;IsEopSession=$false;ModulePrefix='';DelegatedOrganization=''} }
    function script:Get-AcceptedDomain { [CmdletBinding()]param();Add-Query 'Domains';if($script:scenario -eq 'domainthrottle'){Stop-Fixture};if($script:scenario -eq 'domainsfail'){throw 'access denied'};[pscustomobject]@{DomainName='contoso.com';MatchSubDomains=$false} }
    function script:Get-EXOMailbox { [CmdletBinding()]param($PrimarySmtpAddress,$Properties,$RecipientTypeDetails,$ResultSize)
        Add-Query 'Mailbox'
        if($script:scenario -eq 'mailboxthrottle'){Stop-Fixture}
        if($script:scenario -eq 'mbfail'){throw 'access denied'}
        $addresses=if($PrimarySmtpAddress){@($PrimarySmtpAddress)}else{@('one@contoso.com','two@contoso.com')}
        foreach($a in $addresses){[pscustomobject]@{PrimarySmtpAddress=$a;ForwardingAddress=$(if($script:scenario -in @('precedence','mailboxrecipientthrottle')){'contact@contoso.com'}else{$null});ForwardingSmtpAddress=$(if($script:scenario -eq 'precedence'){'smtp:shadow@outside.example'}else{$null});DeliverToMailboxAndForward=$true}}
    }
    function script:Get-InboxRule { [CmdletBinding()]param($Mailbox,[switch]$IncludeHidden,$ResultSize)
        Add-Query 'Inbox'
        if(-not $IncludeHidden -or $ResultSize -ne 10000){throw 'Collector omitted hidden rules or the explicit numeric result limit'}
        $script:reads++
        if($script:scenario -eq 'rulefail'){throw '403 access denied'}
        if($script:scenario -eq 'throttle'){Stop-Fixture}
        if($script:scenario -eq 'rulelimit'){1..10000|ForEach-Object{[pscustomobject]@{Name='Synthetic';Enabled=$false;ForwardTo=@();RedirectTo=@();ForwardAsAttachmentTo=@();SupportedByTask=$true}};return}
        if($script:scenario -eq 'unsupported'){[pscustomobject]@{Name='Junk E-mail Rule';Identity='synthetic-hidden-rule';Enabled=$true;ForwardTo=@();RedirectTo=@();ForwardAsAttachmentTo=@();SupportedByTask=$false};return}
        if($script:scenario -eq 'clean' -or $script:scenario -eq 'precedence'){return}
        if($script:scenario -eq 'workedexample'){[pscustomobject]@{Name='Supplier copy';Identity='synthetic-supplier-rule';Priority=0;Enabled=$true;ForwardTo=@('contact@contoso.com');RedirectTo=@();ForwardAsAttachmentTo=@();StopProcessingRules=$false;Description='Synthetic example: forwards matching supplier messages';SupportedByTask=$true};return}
        if($script:scenario -eq 'warning'){Write-Warning 'Provider cannot display all data'}
        [pscustomobject]@{Name='=HYPERLINK("https://invalid.example")<script>alert(1)</script>';Identity='rule-1';Priority=0;Enabled=($script:scenario -ne 'disabled');ForwardTo=@('External [SMTP:outside@external.example]');RedirectTo=@('contact@contoso.com');ForwardAsAttachmentTo=@('group@contoso.com');StopProcessingRules=$true;Description='Synthetic fixture only';SupportedByTask=$true}
    }
    function script:Get-EXORecipient { [CmdletBinding()]param($Identity,$Properties)
        Add-Query ('Recipient:'+$Identity)
        if($script:scenario -in @('recipientthrottle','mailboxrecipientthrottle')){Stop-Fixture}
        if($script:scenario -eq 'recipientfail'){throw '403 access denied'}
        if($script:scenario -eq 'recipientwarning'){Write-Warning 'Recipient result may be incomplete'}
        foreach($p in @('ExternalEmailAddress','PrimarySmtpAddress','RecipientTypeDetails')){if($Properties -notcontains $p){throw 'Required recipient property omitted'}}
        if($Identity -eq 'contact@contoso.com'){[pscustomobject]@{RecipientTypeDetails='MailContact';PrimarySmtpAddress=$Identity;ExternalEmailAddress='SMTP:contact@external.example'}}
        elseif($Identity -eq 'group@contoso.com'){[pscustomobject]@{RecipientTypeDetails='MailUniversalDistributionGroup';PrimarySmtpAddress=$Identity;ExternalEmailAddress=$null}}
        else{throw 'recipient not found'}
    }
    function script:Get-HostedOutboundSpamFilterPolicy { [CmdletBinding()]param();Add-Query 'Policy';if($script:scenario -eq 'policythrottle'){Stop-Fixture};[pscustomobject]@{Name='Default';IsDefault=$true;AutoForwardingMode='Automatic'} }
    function script:Get-HostedOutboundSpamFilterRule { [CmdletBinding()]param();Add-Query 'Assignments';return }
    function script:Get-RemoteDomain { [CmdletBinding()]param();Add-Query 'RemoteDomain';[pscustomobject]@{Name='Default';DomainName='*';AutoForwardEnabled=$true} }
    function script:Get-TransportRule { [CmdletBinding()]param($ResultSize);Add-Query 'Transport';return }
}
function Invoke-Fixture([string]$Scenario,[switch]$All){
    & $module {param($s)$script:scenario=$s;$script:reads=0;$script:calls.Clear();$script:throttledAt=0} $Scenario
    $params=@{ExpectedTenantId=$tenant;OutputDirectory=$testRoot;DelayMilliseconds=0}
    if($All){$params.AllMailboxes=$true}else{$params.Mailbox=@('lab@contoso.com')}
    $run=Invoke-ExternalForwardingAudit @params -WarningAction SilentlyContinue
    return [pscustomobject]@{Run=$run;Data=(Get-Content -LiteralPath (Join-Path $run.Directory 'audit.json') -Raw|ConvertFrom-Json);Html=(Get-Content -LiteralPath $run.Report -Raw)}
}
Run-Test 'Complete empty inventory has explicit coverage and CSV headers' {
    $f=Invoke-Fixture clean
    Assert ($f.Data.Findings.Count -eq 0 -and $f.Data.IncompleteSections -eq 0) 'Clean result mismatch'
    Assert ($f.Data.Mailboxes[0].Interpretation -match '^No mailbox/Inbox') 'Empty result not explained'
    Assert ((Get-Content -LiteralPath (Join-Path $f.Run.Directory 'forwarding.csv') -Raw) -match 'DeliveryEvidence') 'Missing empty CSV header'
}
Run-Test 'All scope enumerates visible user and shared mailboxes' {$f=Invoke-Fixture clean -All;Assert ($f.Data.Mailboxes.Count -eq 2) 'All-scope count incorrect'}
Run-Test 'Three Inbox actions include contact resolution and unexpanded groups' {
    $f=Invoke-Fixture actions
    Assert ($f.Data.Findings.Count -eq 3 -and $f.Data.ExternalCandidates -eq 2) 'Action collection mismatch'
    Assert ($f.Data.Findings[1].NextHop -eq 'contact@external.example') 'Mail contact not resolved'
    Assert ($f.Data.Findings[2].Classification -eq 'GroupNotExpanded') 'Group mistaken for internal delivery'
}
Run-Test 'Disabled rules do not count as enabled candidates' {$f=Invoke-Fixture disabled;Assert ($f.Data.ExternalCandidates -eq 0) 'Disabled rule counted'}
Run-Test 'ForwardingAddress takes precedence; SMTP setting retained as shadowed' {
    $f=Invoke-Fixture precedence
    Assert ($f.Data.Findings.Count -eq 2 -and $f.Data.ExternalCandidates -eq 1) 'Precedence count incorrect'
    Assert ($f.Data.Findings[1].ConfiguredState -eq 'Shadowed') 'Precedence not represented'
}
Run-Test 'Access denied is incomplete, never clean' {$f=Invoke-Fixture rulefail;Assert ($f.Data.IncompleteSections -gt 0 -and $f.Data.Mailboxes[0].Interpretation -match '^Incomplete') 'False clean verdict'}
Run-Test 'Mailbox query failure does not hide Inbox-rule result' {$f=Invoke-Fixture mbfail;Assert ($f.Data.IncompleteSections -gt 0 -and $f.Data.Findings.Count -eq 3) 'Partial branch lost'}
Run-Test 'Missing domain inventory cannot classify addresses as external by default' {$f=Invoke-Fixture domainsfail;Assert ($f.Data.IncompleteSections -gt 0 -and $f.Data.ExternalCandidates -eq 0) 'Domain failure guessed external'}
Run-Test 'Provider warnings downgrade coverage' {$f=Invoke-Fixture warning;Assert ($f.Data.Coverage.Where({$_.Status -eq 'ReadWithWarnings'}).Count -eq 1) 'Provider warning hidden'}
Run-Test 'Inbox rule result cap is incomplete, never a complete zero result' {$f=Invoke-Fixture rulelimit;Assert ($f.Data.Coverage.Where({$_.ErrorKind -eq 'InboxRuleResultLimitReached'}).Count -eq 1) 'Rule limit not surfaced'}
Run-Test 'Unsupported rules are retained for inspection without inventing a forwarding finding' {$f=Invoke-Fixture unsupported;Assert ($f.Data.RuleReview.Count -eq 1 -and $f.Data.Findings.Count -eq 0 -and $f.Data.IncompleteSections -eq 1) 'Unsupported rule review missing'}
Run-Test 'Throttle stops remaining mailbox reads and reports not attempted' {
    $f=Invoke-Fixture throttle -All
    Assert ($f.Data.Mailboxes[1].InboxRulesStatus -eq 'NotAttempted') 'Throttle did not stop iteration'
    Assert ((& $module {$script:reads}) -eq 1) 'Retried throttled endpoint'
    Assert ((& $module {$script:calls.Count -eq $script:throttledAt}) -eq $true) 'Network query continued after throttling'
}
Run-Test 'Failed recipient queries are counted and cached without a false complete status' {
    $f=Invoke-Fixture recipientfail -All
    $recipientRows=@($f.Data.Coverage | Where-Object Name -like 'Recipient:*')
    Assert ($recipientRows.Count -eq 2 -and $f.Data.IncompleteSections -eq 2) 'Recipient failures missing or double-counted'
    Assert ($f.Data.Status -eq 'Partial collection') 'Recipient failure reported as completed'
    Assert (@($recipientRows | Where-Object ErrorKind -eq 'AccessDenied').Count -eq 2) 'Failure reason missing'
    Assert (@($f.Data.Mailboxes | Where-Object Interpretation -match '^Incomplete').Count -eq 2) 'Mailbox interpretation ignored failed destinations'
    Assert ((& $module {@($script:calls | Where-Object {$_ -like 'Recipient:*'}).Count}) -eq 2) 'Repeated failed lookups were not cached'
    $csv=@(Import-Csv -LiteralPath (Join-Path $f.Run.Directory 'coverage.csv'))
    Assert (@($csv | Where-Object { $_.Name -like 'Recipient:*' -and $_.Status -eq 'Failed' }).Count -eq 2 -and $f.Html.Contains('Recipient:contact@contoso.com')) 'Recipient coverage missing from exports'
}
Run-Test 'Recipient warnings remain incomplete in the summary' {
    $f=Invoke-Fixture recipientwarning
    Assert ($f.Data.Status -eq 'Partial collection' -and $f.Data.IncompleteSections -eq 2) 'Recipient warning hidden'
    Assert (@($f.Data.Coverage | Where-Object Status -eq 'ReadWithWarnings').Count -eq 2) 'Recipient warning coverage missing'
}
Run-Test 'Recipient throttling stops all later reads and preserves known destinations' {
    $f=Invoke-Fixture recipientthrottle -All
    Assert ($f.Data.Status -eq 'Partial collection' -and $f.Data.IncompleteSections -gt 0) 'Throttle reported as complete'
    Assert (@($f.Data.Coverage | Where-Object { $_.Name -eq 'Recipient:contact@contoso.com' -and $_.ErrorKind -eq 'Throttled' }).Count -eq 1) 'Actual throttle failure missing'
    Assert (@($f.Data.Coverage | Where-Object { $_.Name -eq 'Recipient:group@contoso.com' -and $_.Status -eq 'NotAttempted' }).Count -eq 1) 'Pending recipient query not accounted for'
    Assert ($f.Data.Mailboxes[1].InboxRulesStatus -eq 'NotAttempted') 'Later mailbox not skipped'
    Assert ($f.Data.Findings.Count -eq 3 -and $f.Data.ExternalCandidates -eq 1) 'Already returned destination data lost'
    Assert ((& $module {$script:calls.Count -eq $script:throttledAt}) -eq $true) 'Read executed after recipient throttle'
}
Run-Test 'Mailbox-target lookup throttling skips the current Inbox and later controls' {
    $f=Invoke-Fixture mailboxrecipientthrottle
    Assert ($f.Data.Mailboxes[0].InboxRulesStatus -eq 'NotAttempted' -and $f.Data.Findings.Count -eq 1) 'Current Inbox queried or configured target lost'
    Assert ((& $module {$script:calls.Count -eq $script:throttledAt}) -eq $true) 'Read executed after mailbox-target throttle'
}
Run-Test 'Accepted-domain throttling stops selected mailbox reads' {
    $f=Invoke-Fixture domainthrottle
    Assert ($f.Data.Mailboxes[0].MailboxStatus -eq 'NotAttempted') 'Mailbox queried after domain throttle'
    Assert ((& $module {$script:calls.Count}) -eq 1) 'Further queries after domain throttle'
}
Run-Test 'Mailbox enumeration throttling leaves scope unenumerated' {
    $f=Invoke-Fixture mailboxthrottle -All
    Assert ($f.Data.Mailboxes.Count -eq 0 -and $f.Data.Status -eq 'Partial collection') 'Unenumerated scope treated as complete'
    Assert (@($f.Data.Coverage | Where-Object { $_.Name -eq 'MailboxEnumeration' -and $_.ErrorKind -eq 'Throttled' }).Count -eq 1) 'Enumeration failure missing'
    Assert ((& $module {$script:calls.Count -eq $script:throttledAt}) -eq $true) 'Read executed after enumeration throttle'
}
Run-Test 'Selected-mailbox throttling skips the Inbox query' {
    $f=Invoke-Fixture mailboxthrottle
    Assert ($f.Data.Mailboxes[0].InboxRulesStatus -eq 'NotAttempted') 'Inbox queried after mailbox throttle'
    Assert ((& $module {$script:calls.Count -eq $script:throttledAt}) -eq $true) 'Read executed after mailbox throttle'
}
Run-Test 'Policy throttling stops remaining control reads' {
    $f=Invoke-Fixture policythrottle
    Assert (@($f.Data.Coverage | Where-Object { $_.Name -in @('OutboundSpamAssignments','RemoteDomains','TransportRules') -and $_.Status -eq 'NotAttempted' }).Count -eq 3) 'Skipped control reads not accounted for'
    Assert ((& $module {$script:calls.Count -eq $script:throttledAt}) -eq $true) 'Read executed after policy throttle'
}
Run-Test 'Article worked example resolves one contact to an external next hop' {
    $f=Invoke-Fixture workedexample
    Assert ($f.Data.Findings.Count -eq 1 -and $f.Data.ExternalCandidates -eq 1) 'Worked example count mismatch'
    $row=$f.Data.Findings[0]
    Assert ($row.Source -eq 'InboxRule' -and $row.RuleName -eq 'Supplier copy' -and $row.ConfiguredState -eq 'Enabled' -and $row.Action -eq 'ForwardTo' -and $row.Destination -eq 'contact@contoso.com' -and $row.NextHop -eq 'contact@external.example' -and $row.Classification -eq 'ExternalDomain' -and $row.Resolution -eq 'Resolved' -and $row.DeliveryEvidence -eq 'NotTested') 'Worked example differs from article'
}
Run-Test 'HTML escaping and CSV formula protection' {
    $f=Invoke-Fixture actions
    Assert (-not $f.Html.Contains('<script>alert(1)</script>') -and $f.Html.Contains('&lt;script&gt;')) 'HTML injection possible'
    $rows=Import-Csv -LiteralPath (Join-Path $f.Run.Directory 'forwarding.csv')
    Assert ($rows[0].RuleName.StartsWith("'=")) 'CSV formula not neutralized'
    Assert ($f.Data.Findings[0].RuleName.StartsWith('=')) 'JSON unexpectedly mutated'
}
Run-Test 'Tenant mismatch prevents collection' {
    $blocked=$false
    try{Invoke-ExternalForwardingAudit -Mailbox lab@contoso.com -ExpectedTenantId '00000000-0000-0000-0000-000000000002' -OutputDirectory $testRoot}catch{$blocked=$_.Exception.Message -match 'Tenant or connection'}
    Assert $blocked 'Tenant mismatch not blocked'
}
Run-Test 'Empty and wildcard mailbox input is rejected' {
    foreach($bad in @('','*@contoso.com','not-an-address')){
        $blocked=$false;try{Invoke-ExternalForwardingAudit -Mailbox @($bad) -ExpectedTenantId $tenant -OutputDirectory $testRoot}catch{$blocked=$true};Assert $blocked "Invalid mailbox accepted: $bad"
    }
}
Run-Test 'Collector contains no Exchange mutation commands' {
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../ExternalForwardingAudit.psm1'),[ref]$null,[ref]$null)
    $commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()}|Where-Object{$_})
    Assert (@($commands|Where-Object{$_ -match '^(Set|New|Remove|Enable|Disable)-(Mailbox|InboxRule|TransportRule|Hosted|RemoteDomain|AcceptedDomain)' }).Count -eq 0) 'Exchange mutation found'
}
$results|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $PSScriptRoot '../artifacts/offline-test-results.json') -Encoding utf8
Write-Host "$($results.Count) offline tests passed. No tenant calls were made."
