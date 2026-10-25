#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Active Directory security collector for VulnScanner.

.DESCRIPTION
    Collects directory configuration and risk indicators using only Get-AD*
    cmdlets. It never creates, modifies or deletes directory objects. The JSON
    report can be imported into VulnScanner from the Active Directory page,
    or produced by the Windows agent's AD module.

    Requires the RSAT ActiveDirectory PowerShell module and a domain account
    with read access. Run it on a domain-joined management host, not on a
    workstation you do not control.

.PARAMETER OutputPath
    Where to write the JSON report. Defaults to ad-audit-<domain>-<date>.json
    in the current directory.

.PARAMETER StaleDays
    Age in days used to classify users and computers as stale (default 90).

.PARAMETER NoFile
    Print the JSON to standard output instead of writing a file.

.EXAMPLE
    .\ad_audit.ps1 -OutputPath C:\Temp\ad-audit.json

.EXAMPLE
    .\ad_audit.ps1 -StaleDays 120 -OutputPath .\ad-audit.json
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [ValidateRange(30, 3650)]
    [int]$StaleDays = 90,
    [switch]$NoFile
)

$ErrorActionPreference = "Stop"

function Write-Status([string]$Message) {
    Write-Host "[ad-audit] $Message" -ForegroundColor Cyan
}

function Get-Sample {
    param($Items, [int]$Limit = 12)
    if (-not $Items) { return @() }
    return @($Items | Select-Object -First $Limit -ExpandProperty SamAccountName)
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Status "Reading domain configuration"
    $domain = Get-ADDomain
    $policy = Get-ADDefaultDomainPasswordPolicy
    $cutoff = (Get-Date).AddDays(-1 * $StaleDays)

    $privilegedGroupNames = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
        "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
        "Group Policy Creator Owners", "DnsAdmins", "Cert Publishers",
        "Enterprise Key Admins", "Key Admins", "Exchange Organization Management"
    )

    Write-Status "Expanding privileged group membership (recursive)"
    $privilegedDns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $privilegedGroups = [ordered]@{}
    foreach ($groupName in $privilegedGroupNames) {
        try {
            $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
            $members = @(Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                Where-Object { $_.objectClass -eq "user" })
            $privilegedGroups[$groupName] = [ordered]@{ count = $members.Count }
            foreach ($member in $members) {
                [void]$privilegedDns.Add([string]$member.DistinguishedName)
            }
        } catch {
            # Groups such as Exchange Organization Management only exist in some
            # environments. Missing groups are skipped rather than treated as errors.
        }
    }

    function Test-Privileged {
        param($User)
        return $privilegedDns.Contains([string]$User.DistinguishedName)
    }

    Write-Status "Reading users, computers and groups"
    $users = @(Get-ADUser -Filter * -Properties `
        Enabled, LastLogonDate, PasswordNeverExpires, ServicePrincipalName, `
        AdminCount, PasswordLastSet, whenCreated, TrustedForDelegation, userAccountControl)
    $computers = @(Get-ADComputer -Filter * -Properties `
        Enabled, LastLogonDate, whenCreated, TrustedForDelegation, userAccountControl)
    $groupCount = @(Get-ADGroup -Filter *).Count

    $enabledUsers = @($users | Where-Object { $_.Enabled })
    $staleUsers = @($enabledUsers | Where-Object {
        $_.SamAccountName -notin @("krbtgt", "Guest") -and
        (($_.LastLogonDate -and $_.LastLogonDate -lt $cutoff) -or
         (-not $_.LastLogonDate -and $_.whenCreated -and $_.whenCreated -lt $cutoff))
    })
    $stalePrivileged = @($staleUsers | Where-Object { Test-Privileged $_ })
    $neverExpires = @($enabledUsers | Where-Object { $_.PasswordNeverExpires })
    $neverExpiresPrivileged = @($neverExpires | Where-Object { Test-Privileged $_ })
    $adminNonPrivileged = @($enabledUsers | Where-Object {
        $_.AdminCount -eq 1 -and -not (Test-Privileged $_)
    })

    $kerberoastable = @($enabledUsers | Where-Object {
        $_.SamAccountName -ne "krbtgt" -and $_.ServicePrincipalName -and @($_.ServicePrincipalName).Count -gt 0
    })
    $kerberoastablePrivileged = @($kerberoastable | Where-Object { Test-Privileged $_ })

    Write-Status "Checking AS-REP roastable accounts and delegation"
    $asrepFilter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $asrepUsers = @(Get-ADUser -LDAPFilter $asrepFilter -Properties Enabled, ServicePrincipalName, DistinguishedName |
        Where-Object { $_.Enabled })
    $asrepPrivileged = @($asrepUsers | Where-Object { Test-Privileged $_ })

    $unconstrained = @()
    $unconstrained += @($enabledUsers | Where-Object { $_.TrustedForDelegation })
    $unconstrained += @($computers | Where-Object {
        $_.Enabled -and $_.TrustedForDelegation -and -not ($_.userAccountControl -band 8192)
    })
    $unconstrainedNames = @($unconstrained | ForEach-Object { $_.SamAccountName })

    $staleComputers = @($computers | Where-Object {
        $_.Enabled -and
        (($_.LastLogonDate -and $_.LastLogonDate -lt $cutoff) -or
         (-not $_.LastLogonDate -and $_.whenCreated -and $_.whenCreated -lt $cutoff))
    })

    $guestEnabled = $false
    try {
        $guest = Get-ADUser -Filter "ObjectSID -eq '$($domain.DomainSID.Value)-501'" -Properties Enabled -ErrorAction Stop
        if ($guest) { $guestEnabled = [bool]$guest.Enabled }
    } catch { }

    $krbtgtAge = $null
    try {
        $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
        if ($krbtgt.PasswordLastSet) {
            $krbtgtAge = [int]((Get-Date) - $krbtgt.PasswordLastSet).TotalDays
        }
    } catch { }

    $recycleBinEnabled = $false
    try {
        $feature = Get-ADOptionalFeature -Filter 'Name -like "Recycle Bin Feature"' -ErrorAction Stop
        if ($feature -and $feature.EnabledScopes -and @($feature.EnabledScopes).Count -gt 0) {
            $recycleBinEnabled = $true
        }
    } catch { }

    $machineQuota = $null
    try {
        if ($null -ne $domain.MachineAccountQuota) {
            $machineQuota = [int]$domain.MachineAccountQuota
        }
    } catch { }

    $report = [ordered]@{
        collector = "VulnScanner ad_audit.ps1"
        collected_at = (Get-Date).ToUniversalTime().ToString("o")
        stale_days = $StaleDays
        domain = [ordered]@{
            name = $domain.DNSRoot
            forest = $domain.Forest
            domain_controller = $domain.PDCEmulator
            functional_level = [string]$domain.DomainMode
            machine_account_quota = $machineQuota
            recycle_bin_enabled = $recycleBinEnabled
        }
        password_policy = [ordered]@{
            min_length = $policy.MinPasswordLength
            complexity = [bool]$policy.ComplexityEnabled
            lockout_threshold = $policy.LockoutThreshold
            lockout_duration_minutes = $policy.LockoutDuration.TotalMinutes
            lockout_observation_minutes = $policy.LockoutObservationWindow.TotalMinutes
            max_age_days = $policy.MaxPasswordAge.TotalDays
        }
        counts = [ordered]@{
            users = $users.Count
            enabled_users = $enabledUsers.Count
            computers = $computers.Count
            groups = $groupCount
        }
        guest_enabled = $guestEnabled
        krbtgt_password_age_days = $krbtgtAge
        stale_users = [ordered]@{
            count = $staleUsers.Count
            privileged = $stalePrivileged.Count
            sample = (Get-Sample $staleUsers)
        }
        stale_computers = $staleComputers.Count
        never_expires = [ordered]@{
            count = $neverExpires.Count
            privileged = $neverExpiresPrivileged.Count
        }
        kerberoastable = [ordered]@{
            count = $kerberoastable.Count
            privileged = $kerberoastablePrivileged.Count
            sample = (Get-Sample $kerberoastable)
        }
        asrep_roastable = [ordered]@{
            count = $asrepUsers.Count
            privileged = $asrepPrivileged.Count
            sample = (Get-Sample $asrepUsers)
        }
        unconstrained_delegation = [ordered]@{
            count = $unconstrained.Count
            accounts = @($unconstrainedNames | Select-Object -First 20)
        }
        admin_count = [ordered]@{
            count = $adminNonPrivileged.Count
            non_privileged = (Get-Sample $adminNonPrivileged)
        }
        privileged_groups = $privilegedGroups
    }

    $json = $report | ConvertTo-Json -Depth 8
    if ($NoFile) {
        Write-Output $json
    } else {
        if (-not $OutputPath) {
            $safeDomain = ($domain.DNSRoot -replace "[^A-Za-z0-9._-]", "_")
            $OutputPath = Join-Path (Get-Location) ("ad-audit-{0}-{1}.json" -f $safeDomain, (Get-Date -Format "yyyyMMdd-HHmmss"))
        }
        $directory = Split-Path -Parent $OutputPath
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
        Write-Status "Report written to $OutputPath"
        Write-Status "Import it in VulnScanner: Active Directory > Import report."
    }
    exit 0
} catch {
    Write-Error "Active Directory audit failed: $($_.Exception.Message)"
    Write-Error "Ensure RSAT ActiveDirectory is installed and the account can read the domain."
    exit 1
}
