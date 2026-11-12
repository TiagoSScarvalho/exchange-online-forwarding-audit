#requires -Version 7.4
# Tiago Carvalho | https://www.tiagoscarvalho.com | MIT
<#
.SYNOPSIS
Audits Exchange Online forwarding and exports HTML, CSV and JSON reports.
.DESCRIPTION
Read-only. Connect first; see README.txt for setup, permissions and limitations.
.EXAMPLE
.\Get-ExternalForwardingAudit.ps1 -Mailbox lab@contoso.com -ExpectedTenantId '00000000-0000-0000-0000-000000000001'
#>
[CmdletBinding(DefaultParameterSetName='Selected')]
param(
    [Parameter(Mandatory,ParameterSetName='Selected')]
    [ValidateNotNullOrEmpty()][string[]]$Mailbox,
    [Parameter(Mandatory,ParameterSetName='All')][switch]$AllMailboxes,
    [Parameter(Mandatory)][guid]$ExpectedTenantId,
    [string]$OutputDirectory = (Join-Path (Get-Location) 'forwarding-audit'),
    [ValidateRange(0,5000)][int]$DelayMilliseconds = 250
)
$ErrorActionPreference = 'Stop'
if(-not (Get-Module ExchangeOnlineManagement | Where-Object Version -ge ([version]'3.9.2'))){throw 'Import ExchangeOnlineManagement 3.9.2 or later and connect to Exchange Online first.'}
Import-Module (Join-Path $PSScriptRoot 'ExternalForwardingAudit.psm1') -Force
Invoke-ExternalForwardingAudit @PSBoundParameters
