#Requires -Version 5.1
<#
.SYNOPSIS
    Native Windows endpoint agent for VulnScanner.

.DESCRIPTION
    Runs on Windows client and server editions without Python. The agent polls
    the VulnScanner server over outbound HTTP(S), performs checks locally and
    uploads the results. It can also run delegated TCP network scans from the
    endpoint's network position.

    The installer (install-windows-agent.ps1) registers this script as a
    scheduled task. You can run it manually with:

        .\VulnScannerAgent.ps1 -Action Status
        .\VulnScannerAgent.ps1 -Action Run
        .\VulnScannerAgent.ps1 -Action Configure -Server https://scanner.example.com

.PARAMETER Action
    Enroll, Configure, Run, Status or Scan.

.PARAMETER Server
    VulnScanner server URL, for example https://scanner.example.com.

.PARAMETER Token
    One-time enrollment token (Enroll) or an updated agent token (Configure).

.PARAMETER Name
    Friendly agent name. Defaults to the computer name.

.PARAMETER ConfigPath
    Agent configuration file. Defaults to
    C:\ProgramData\VulnScanner Agent\agent.json.

.PARAMETER PollInterval
    Seconds between job polls (minimum 5).

.PARAMETER Insecure
    Do not verify the server TLS certificate. Use only for a self-signed lab.

.PARAMETER VerifyTls
    Explicitly verify the server TLS certificate.

.PARAMETER Enroll
    With Configure, enroll again using Server and Token.

.PARAMETER Once
    With Run, poll once and exit.

.PARAMETER Modules
    Comma-separated modules for an offline Scan: system,ports,network,ad.

.PARAMETER Target
    Network target for the network module (host, IP or IPv4 CIDR).

.PARAMETER Ports
    Custom ports for the network module, for example 22,80,443 or 1-1024.

.PARAMETER Profile
    Network port profile: common, web, top1000 or all.

.PARAMETER TimeoutMs
    TCP connect timeout in milliseconds for delegated network scans.

.PARAMETER Workers
    Maximum concurrent TCP probes for delegated network scans.

.PARAMETER Output
    Write offline Scan JSON to this file instead of standard output.
#>
[CmdletBinding()]
param(
    [ValidateSet("Enroll", "Configure", "Run", "Status", "Scan")]
    [string]$Action = "Run",
    [string]$Server = "",
    [string]$Token = "",
    [string]$Name = $env:COMPUTERNAME,
    [string]$ConfigPath = "",
    [int]$PollInterval = 0,
    [switch]$Insecure,
    [switch]$VerifyTls,
    [switch]$Enroll,
    [switch]$Once,
    [string]$Modules = "system,ports",
    [string]$Target = "",
    [string]$Ports = "",
    [string]$Profile = "common",
    [int]$TimeoutMs = 600,
    [int]$Workers = 200,
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"
$AgentVersion = "1.1.0"
$script:AgentRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath) {
    $programData = $env:ProgramData
    if (-not $programData) { $programData = Join-Path $env:SystemDrive "ProgramData" }
    $ConfigPath = Join-Path $programData "VulnScanner Agent\agent.json"
}
$script:ServiceNames = @{
    21 = "ftp"; 22 = "ssh"; 23 = "telnet"; 25 = "smtp"; 53 = "dns";
    80 = "http"; 110 = "pop3"; 111 = "rpcbind"; 135 = "msrpc"; 139 = "netbios";
    143 = "imap"; 161 = "snmp"; 389 = "ldap"; 443 = "https"; 445 = "smb";
    465 = "smtps"; 587 = "submission"; 631 = "ipp"; 636 = "ldaps"; 873 = "rsync";
    993 = "imaps"; 995 = "pop3s"; 1080 = "socks"; 1433 = "mssql"; 1521 = "oracle";
    1723 = "pptp"; 2049 = "nfs"; 2181 = "zookeeper"; 2375 = "docker";
    2376 = "docker-tls"; 3000 = "http"; 3306 = "mysql"; 3389 = "rdp";
    4443 = "https"; 5000 = "http"; 5432 = "postgresql"; 5601 = "kibana";
    5672 = "amqp"; 5900 = "vnc"; 5984 = "couchdb"; 6379 = "redis";
    6443 = "kubernetes"; 7001 = "weblogic"; 8000 = "http"; 8008 = "http";
    8080 = "http-proxy"; 8081 = "http"; 8443 = "https-alt"; 8888 = "http";
    9000 = "http"; 9090 = "http"; 9200 = "elasticsearch"; 9300 = "elasticsearch";
    10000 = "webmin"; 11211 = "memcached"; 27017 = "mongodb"; 27018 = "mongodb"
}
$script:CommonPorts = @(
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049,
    2181, 2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432, 5601, 5672, 5900,
    5984, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 11211, 27017, 27018
)
$script:WebPorts = @(80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443)

function Write-Log {
    param([string]$Message)
    Write-Host ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message)
}

function Get-DefaultConfigPath {
    return $ConfigPath
}

function ConvertTo-AgentHashtable {
    param($InputObject)
    $table = [ordered]@{}
    if ($null -eq $InputObject) { return $table }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) { $table[[string]$key] = $InputObject[$key] }
        return $table
    }
    foreach ($property in $InputObject.PSObject.Properties) {
        $table[$property.Name] = $property.Value
    }
    return $table
}

function Protect-AgentPath {
    param([string]$Path, [switch]$Directory)
    if ($env:OS -ne "Windows_NT") { return }
    try {
        if ($Directory) {
            & icacls $Path /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" | Out-Null
        } else {
            & icacls $Path /inheritance:r /grant:r "SYSTEM:F" "BUILTIN\Administrators:F" | Out-Null
        }
    } catch {
        Write-Log "Could not tighten permissions on $Path : $($_.Exception.Message)"
    }
}

function Read-AgentConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "No agent configuration at $Path. Run the installer or use -Action Enroll."
    }
    try {
        return ConvertTo-AgentHashtable (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
    } catch {
        throw "Could not read the agent configuration at $Path : $($_.Exception.Message)"
    }
}

function Save-AgentConfig {
    param([hashtable]$Config, [string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Protect-AgentPath -Path $parent -Directory
    }
    $json = $Config | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
    Protect-AgentPath -Path $Path
    return $Path
}

function Set-TlsMode {
    param([bool]$Verify)
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        } catch { }
    }
    if ($Verify) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    } else {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($sender, $certificate, $chain, $errors)
            return $true
        }
    }
}

function Invoke-VsApi {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [string]$Method = "GET",
        [Parameter(Mandatory = $true)][string]$Path,
        $Payload = $null,
        [int]$TimeoutSec = 45
    )
    $server = [string]$Config["server"]
    if (-not $server) { throw "The agent has no server URL configured." }
    $verify = $true
    if ($Config.Contains("verify_tls")) { $verify = [bool]$Config["verify_tls"] }
    Set-TlsMode -Verify $verify
    $headers = @{
        "User-Agent" = "VulnScanner-Agent/$AgentVersion"
        "Accept" = "application/json"
    }
    if ($Config["token"]) { $headers["X-Agent-Token"] = [string]$Config["token"] }
    $request = @{
        Uri = $server.TrimEnd("/") + $Path
        Method = $Method
        Headers = $headers
        TimeoutSec = $TimeoutSec
        UseBasicParsing = $true
    }
    if ($null -ne $Payload) {
        $request["Body"] = ($Payload | ConvertTo-Json -Depth 20 -Compress)
        $request["ContentType"] = "application/json"
    }
    if (-not $verify -and $PSVersionTable.PSVersion.Major -ge 7) {
        $request["SkipCertificateCheck"] = $true
    }
    try {
        $response = Invoke-WebRequest @request
        $content = [string]$response.Content
        if ([string]::IsNullOrWhiteSpace($content)) { return @{} }
        return ($content | ConvertFrom-Json)
    } catch {
        $message = $_.Exception.Message
        try {
            if ($_.Exception.Response) {
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $body = $reader.ReadToEnd()
                    if ($body) { $message = $body }
                }
            }
        } catch { }
        throw "Server request failed: $message"
    }
}

function Get-SystemInformation {
    $info = [ordered]@{
        hostname = [Environment]::MachineName
        platform = "Windows"
        os = "Windows"
        os_release = [Environment]::OSVersion.VersionString
        version = [Environment]::OSVersion.Version.ToString()
        arch = $env:PROCESSOR_ARCHITECTURE
        user = [Environment]::UserName
        agent_version = $AgentVersion
        agent_kind = "powershell"
        powershell = $PSVersionTable.PSVersion.ToString()
        collected_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $info["os_release"] = [string]$os.Caption
        $info["distro_name"] = [string]$os.Caption
        $info["version"] = [string]$os.Version
        $info["windows_build"] = [string]$os.BuildNumber
        $info["last_boot"] = ([datetime]$os.LastBootUpTime).ToUniversalTime().ToString("o")
        $productType = [int]$os.ProductType
        if ($productType -eq 1) { $info["windows_product_type"] = "client" }
        elseif ($productType -eq 2 -or $productType -eq 3) { $info["windows_product_type"] = "server" }
        else { $info["windows_product_type"] = "unknown" }
    } catch { }
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $info["manufacturer"] = [string]$computer.Manufacturer
        $info["model"] = [string]$computer.Model
        $info["domain"] = [string]$computer.Domain
    } catch { }
    return $info
}

function Get-Capabilities {
    $capabilities = @("system", "ports", "network")
    $adPath = Join-Path $script:AgentRoot "ad_audit.ps1"
    if (Test-Path -LiteralPath $adPath) { $capabilities += "ad" }
    return $capabilities
}

function New-LocalCheck {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Severity,
        [string]$Description,
        [string]$Evidence,
        [string]$Remediation,
        [string]$Cwe = ""
    )
    return [ordered]@{
        severity = $Severity
        title = $Title
        category = "host"
        description = $Description
        evidence = $Evidence
        remediation = $Remediation
        cwe = $Cwe
        location = $env:COMPUTERNAME
        resource = $Id
        key = "windows-agent:$Id"
    }
}

function Get-LocalChecks {
    $checks = New-Object System.Collections.ArrayList

    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $disabled = @($profiles | Where-Object { -not $_.Enabled })
        if ($disabled.Count -gt 0) {
            $names = ($disabled | ForEach-Object { $_.Name }) -join ", "
            [void]$checks.Add((New-LocalCheck -Id "firewall-disabled" -Title "Windows Firewall is disabled" `
                -Severity "high" -Description "One or more Windows Firewall profiles are disabled." `
                -Evidence "Disabled profiles: $names" `
                -Remediation "Enable Windows Firewall for Domain, Private and Public profiles or enforce it with Group Policy." `
                -Cwe "CWE-284"))
        }
    } catch { }

    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        if (-not $defender.RealTimeProtectionEnabled) {
            [void]$checks.Add((New-LocalCheck -Id "defender-realtime-off" -Title "Microsoft Defender real-time protection is disabled" `
                -Severity "high" -Description "Malware protection is not actively scanning files and processes." `
                -Evidence "RealTimeProtectionEnabled = False" `
                -Remediation "Enable real-time protection and investigate why it was disabled." `
                -Cwe "CWE-693"))
        }
        if ($null -ne $defender.AntivirusSignatureAge -and [int]$defender.AntivirusSignatureAge -gt 7) {
            [void]$checks.Add((New-LocalCheck -Id "defender-signatures-old" -Title "Defender signatures are out of date" `
                -Severity "medium" -Description "Antivirus signatures are more than seven days old." `
                -Evidence "AntivirusSignatureAge = $($defender.AntivirusSignatureAge) day(s)" `
                -Remediation "Run Windows Update or update Defender signatures." `
                -Cwe "CWE-1104"))
        }
    } catch { }

    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smb.EnableSMB1Protocol) {
            [void]$checks.Add((New-LocalCheck -Id "smb1-enabled" -Title "SMBv1 is enabled" `
                -Severity "high" -Description "SMBv1 is obsolete and has well-known remote code execution vulnerabilities." `
                -Evidence "EnableSMB1Protocol = True" `
                -Remediation "Disable SMBv1 unless a documented legacy system requires it." `
                -Cwe "CWE-1104"))
        }
        if (-not $smb.RequireSecuritySignature) {
            [void]$checks.Add((New-LocalCheck -Id "smb-signing-off" -Title "SMB signing is not required" `
                -Severity "medium" -Description "Unsigned SMB traffic can be modified by an attacker on the network." `
                -Evidence "RequireSecuritySignature = False" `
                -Remediation "Require SMB signing for server and client traffic." `
                -Cwe "CWE-345"))
        }
    } catch { }

    try {
        $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop
        if ([int]$rdp.fDenyTSConnections -eq 0) {
            [void]$checks.Add((New-LocalCheck -Id "rdp-enabled" -Title "Remote Desktop is enabled" `
                -Severity "medium" -Description "RDP is reachable if the firewall or network permits it and is a common ransomware entry point." `
                -Evidence "fDenyTSConnections = 0" `
                -Remediation "Disable RDP if it is not required; otherwise require NLA, MFA and network allow-lists." `
                -Cwe "CWE-284"))
        }
    } catch { }

    try {
        $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop
        if ([int]$uac.EnableLUA -eq 0) {
            [void]$checks.Add((New-LocalCheck -Id "uac-disabled" -Title "User Account Control is disabled" `
                -Severity "medium" -Description "Administrative actions are not prompted, which weakens privilege boundaries." `
                -Evidence "EnableLUA = 0" `
                -Remediation "Enable UAC and require elevation for administrative tasks." `
                -Cwe "CWE-269"))
        }
    } catch { }

    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        if ($guest.Enabled) {
            [void]$checks.Add((New-LocalCheck -Id "guest-enabled" -Title "The built-in Guest account is enabled" `
                -Severity "medium" -Description "The Guest account provides unauthenticated or weakly authenticated access." `
                -Evidence "Guest account Enabled = True" `
                -Remediation "Disable the Guest account." `
                -Cwe "CWE-284"))
        }
    } catch { }

    try {
        $winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction Stop
        if ($winlogon.DefaultPassword) {
            [void]$checks.Add((New-LocalCheck -Id "autologon-password" -Title "Automatic logon stores a password" `
                -Severity "critical" -Description "A plaintext or weakly protected autologon password can be recovered from the registry." `
                -Evidence "DefaultPassword is configured under Winlogon" `
                -Remediation "Remove automatic logon credentials and use a managed service account or credential vault." `
                -Cwe "CWE-522"))
        }
    } catch { }

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        if (-not $secureBoot) {
            [void]$checks.Add((New-LocalCheck -Id "secure-boot-off" -Title "Secure Boot is disabled" `
                -Severity "medium" -Description "Boot-time integrity checks are not enforced." `
                -Evidence "Confirm-SecureBootUEFI = False" `
                -Remediation "Enable Secure Boot in the firmware if the hardware and OS support it." `
                -Cwe "CWE-693"))
        }
    } catch { }

    try {
        $latest = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($latest -and $latest.InstalledOn) {
            $age = ((Get-Date) - [datetime]$latest.InstalledOn).Days
            if ($age -gt 90) {
                [void]$checks.Add((New-LocalCheck -Id "updates-stale" -Title "No recent Windows update was found" `
                    -Severity "medium" -Description "The newest installed update is more than 90 days old." `
                    -Evidence "Newest update: $($latest.HotFixID) installed $($latest.InstalledOn.ToString('yyyy-MM-dd')) ($age days ago)" `
                    -Remediation "Check Windows Update and patch the host regularly." `
                    -Cwe "CWE-1104"))
            }
        }
    } catch { }

    try {
        $dns = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if (-not $dns -or [int]$dns.EnableMulticast -ne 0) {
            [void]$checks.Add((New-LocalCheck -Id "llmnr-enabled" -Title "LLMNR name resolution is enabled" `
                -Severity "low" -Description "LLMNR can be abused for credential relay and spoofing attacks." `
                -Evidence "EnableMulticast policy is not set to 0" `
                -Remediation "Disable LLMNR with Group Policy unless a legacy application requires it." `
                -Cwe "CWE-350"))
        }
    } catch { }

    try {
        $logging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        if (-not $logging -or [int]$logging.EnableScriptBlockLogging -ne 1) {
            [void]$checks.Add((New-LocalCheck -Id "powershell-logging-off" -Title "PowerShell script block logging is not enabled" `
                -Severity "low" -Description "Security teams lose visibility into malicious or accidental PowerShell activity." `
                -Evidence "EnableScriptBlockLogging is not set to 1" `
                -Remediation "Enable PowerShell script block logging through Group Policy." `
                -Cwe "CWE-778"))
        }
    } catch { }

    return @($checks)
}

function Get-ListeningPorts {
    $entries = New-Object System.Collections.ArrayList
    $processNames = @{}
    try {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $processNames[[int]$_.Id] = $_.ProcessName }
    } catch { }

    $usedFallback = $false
    try {
        Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            $pidValue = [int]$_.OwningProcess
            $portValue = [int]$_.LocalPort
            $service = ""
            if ($script:ServiceNames.ContainsKey($portValue)) { $service = $script:ServiceNames[$portValue] }
            [void]$entries.Add([ordered]@{
                address = [string]$_.LocalAddress
                port = $portValue
                protocol = "tcp"
                process = [string]$processNames[$pidValue]
                pid = $pidValue
                service = $service
            })
        }
        Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $pidValue = [int]$_.OwningProcess
            $portValue = [int]$_.LocalPort
            $service = ""
            if ($script:ServiceNames.ContainsKey($portValue)) { $service = $script:ServiceNames[$portValue] }
            [void]$entries.Add([ordered]@{
                address = [string]$_.LocalAddress
                port = $portValue
                protocol = "udp"
                process = [string]$processNames[$pidValue]
                pid = $pidValue
                service = $service
            })
        }
    } catch {
        $usedFallback = $true
    }

    if ($usedFallback -or $entries.Count -eq 0) {
        try {
            $netstat = & netstat -ano 2>$null
            foreach ($line in @($netstat)) {
                if ($line -match "^\s*(TCP|UDP)\s+(\S+)\s+\S+\s+(\S+)\s+(\d+)\s*$") {
                    $protocol = $Matches[1].ToLower()
                    $local = $Matches[2]
                    $state = $Matches[3]
                    $pidValue = [int]$Matches[4]
                    if ($protocol -eq "tcp" -and $state -notmatch "LISTEN") { continue }
                    $index = $local.LastIndexOf(":")
                    if ($index -lt 1) { continue }
                    $address = $local.Substring(0, $index).Trim("[", "]")
                    $portText = $local.Substring($index + 1)
                    if ($portText -notmatch "^\d+$") { continue }
                    $portValue = [int]$portText
                    $service = ""
                    if ($script:ServiceNames.ContainsKey($portValue)) { $service = $script:ServiceNames[$portValue] }
                    [void]$entries.Add([ordered]@{
                        address = $address
                        port = $portValue
                        protocol = $protocol
                        process = [string]$processNames[$pidValue]
                        pid = $pidValue
                        service = $service
                    })
                }
            }
        } catch { }
    }

    $seen = @{}
    $result = New-Object System.Collections.ArrayList
    foreach ($entry in $entries) {
        $key = "{0}|{1}|{2}" -f $entry["protocol"], $entry["address"], $entry["port"]
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            [void]$result.Add($entry)
        }
    }
    return @($result)
}

function Expand-AgentTarget {
    param([string]$Value)
    $Value = ("" + $Value).Trim()
    if (-not $Value) { throw "A network scan target is required." }
    if ($Value.Contains("/")) {
        $parts = $Value.Split("/")
        if ($parts.Count -ne 2) { throw "Invalid CIDR range: $Value" }
        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$address)) {
            throw "Invalid CIDR address: $Value"
        }
        if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Only IPv4 CIDR ranges are supported by the Windows agent."
        }
        $prefix = 0
        if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) {
            throw "Invalid CIDR prefix: $Value"
        }
        $octets = $address.GetAddressBytes()
        $ipValue = [uint64]$octets[0] * 16777216 + [uint64]$octets[1] * 65536 + [uint64]$octets[2] * 256 + [uint64]$octets[3]
        $size = [uint64][math]::Pow(2, 32 - $prefix)
        $mask = [uint64](4294967296 - $size)
        $network = [uint64]($ipValue -band $mask)
        $broadcast = [uint64]($network + $size - 1)
        $start = $network
        $end = $broadcast
        if ($prefix -le 30) {
            $start = $network + 1
            $end = $broadcast - 1
        }
        $count = $end - $start + 1
        if ($count -lt 1 -or $count -gt 256) {
            throw "Network contains $count address(es); the Windows agent limit is 256."
        }
        $hosts = New-Object System.Collections.ArrayList
        for ($value = $start; $value -le $end; $value++) {
            $bytes = [System.BitConverter]::GetBytes([uint32]$value)
            [Array]::Reverse($bytes)
            [void]$hosts.Add((New-Object System.Net.IPAddress(,$bytes)).IPAddressToString)
        }
        return @($hosts)
    }

    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($Value, [ref]$parsed)) {
        return @($Value)
    }
    try {
        $resolved = @([System.Net.Dns]::GetHostAddresses($Value) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            Select-Object -First 10 |
            ForEach-Object { $_.IPAddressToString })
    } catch {
        throw "Could not resolve host '$Value': $($_.Exception.Message)"
    }
    if ($resolved.Count -eq 0) { throw "Could not resolve host '$Value' to an IPv4 address." }
    return $resolved
}

function Resolve-AgentPorts {
    param([string]$CustomPorts, [string]$PortProfile)
    if ($CustomPorts) {
        $named = $CustomPorts.Trim().ToLowerInvariant()
        if ($named -in @("common", "web", "top1000", "all")) {
            return Resolve-AgentPorts -CustomPorts "" -PortProfile $named
        }
        $set = New-Object System.Collections.Generic.HashSet[int]
        foreach ($part in $CustomPorts.Split(",")) {
            $item = $part.Trim()
            if (-not $item) { continue }
            if ($item.Contains("-")) {
                $range = $item.Split("-")
                if ($range.Count -ne 2) { throw "Invalid port range: $item" }
                $start = 0
                $end = 0
                if (-not [int]::TryParse($range[0], [ref]$start) -or -not [int]::TryParse($range[1], [ref]$end)) {
                    throw "Invalid port range: $item"
                }
                if ($start -lt 1 -or $end -gt 65535 -or $start -gt $end) { throw "Invalid port range: $item" }
                if (($end - $start) -gt 5000) { throw "Port ranges are limited to 5000 ports." }
                for ($port = $start; $port -le $end; $port++) { [void]$set.Add($port) }
            } else {
                $port = 0
                if (-not [int]::TryParse($item, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
                    throw "Invalid port: $item"
                }
                [void]$set.Add($port)
            }
        }
        if ($set.Count -eq 0) { throw "No ports supplied." }
        $ports = @($set)
        [Array]::Sort($ports)
        return $ports
    }
    switch ($PortProfile.ToLowerInvariant()) {
        "web" { return $script:WebPorts }
        "top1000" { return @(1..1000) }
        "all" { return @(1..10000) }
        default { return $script:CommonPorts }
    }
}

function Add-PortScannerType {
    if ("VulnScanner.PortScanner" -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace VulnScanner
{
    public static class PortScanner
    {
        public static string[] Scan(string[] hosts, int[] ports, int timeoutMs, int workers)
        {
            if (hosts == null || ports == null || hosts.Length == 0 || ports.Length == 0)
            {
                return new string[0];
            }
            ConcurrentBag<string> found = new ConcurrentBag<string>();
            int total = hosts.Length * ports.Length;
            ParallelOptions options = new ParallelOptions();
            options.MaxDegreeOfParallelism = Math.Max(1, Math.Min(workers, 600));
            Parallel.For(0, total, options, delegate(int index)
            {
                string host = hosts[index / ports.Length];
                int port = ports[index % ports.Length];
                TcpClient client = new TcpClient();
                try
                {
                    IAsyncResult result = client.BeginConnect(host, port, null, null);
                    if (result.AsyncWaitHandle.WaitOne(Math.Max(50, timeoutMs)))
                    {
                        try
                        {
                            client.EndConnect(result);
                            found.Add(host + "\t" + port.ToString());
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
                finally
                {
                    try { client.Close(); } catch { }
                }
            });
            return found.ToArray();
        }
    }
}
'@
}

function Invoke-NetworkScan {
    param(
        [string]$ScanTarget,
        [string]$CustomPorts,
        [string]$PortProfile,
        [int]$ConnectTimeoutMs,
        [int]$MaxWorkers
    )
    $started = (Get-Date).ToUniversalTime().ToString("o")
    $hosts = @(Expand-AgentTarget -Value $ScanTarget)
    $portList = @(Resolve-AgentPorts -CustomPorts $CustomPorts -PortProfile $PortProfile)
    Add-PortScannerType
    $lines = [VulnScanner.PortScanner]::Scan([string[]]$hosts, [int[]]$portList, [int]$ConnectTimeoutMs, [int]$MaxWorkers)
    $open = New-Object System.Collections.ArrayList
    foreach ($line in @($lines)) {
        $parts = ([string]$line).Split("`t")
        if ($parts.Count -ne 2) { continue }
        $portValue = [int]$parts[1]
        $service = ""
        if ($script:ServiceNames.ContainsKey($portValue)) { $service = $script:ServiceNames[$portValue] }
        [void]$open.Add([ordered]@{
            host = $parts[0]
            port = $portValue
            service = $service
            banner = ""
        })
    }
    $sorted = @($open | Sort-Object -Property host, port)
    return [ordered]@{
        target = $ScanTarget
        hosts = @($hosts)
        host_count = $hosts.Count
        ports_scanned = $portList.Count
        open_ports = $sorted
        started_at = $started
        finished_at = (Get-Date).ToUniversalTime().ToString("o")
    }
}

function Invoke-AdAudit {
    $path = Join-Path $script:AgentRoot "ad_audit.ps1"
    if (-not (Test-Path -LiteralPath $path)) {
        throw "ad_audit.ps1 is not installed next to VulnScannerAgent.ps1."
    }
    $json = & $path -NoFile
    if ($json -is [array]) { $json = $json -join "`n" }
    if (-not $json) { throw "The Active Directory collector returned no report." }
    return ($json | ConvertFrom-Json)
}

function Invoke-AgentJob {
    param($Job)
    $payload = $Job.payload
    if ($payload -is [string]) { $payload = $payload | ConvertFrom-Json }
    $modules = @()
    if ($payload.modules) { $modules = @($payload.modules) }
    if ($modules.Count -eq 0) { $modules = @("system", "packages", "ports") }
    $options = $payload.options
    $result = [ordered]@{
        system = Get-SystemInformation
        packages = @()
        listening_ports = @()
        secrets = @()
        checks = @()
        source_findings = @()
        modules = $modules
        agent_version = $AgentVersion
        agent_kind = "powershell"
    }
    $warnings = New-Object System.Collections.ArrayList

    if ($modules -contains "system") {
        try { $result["checks"] = @(Get-LocalChecks) }
        catch { [void]$warnings.Add("System checks failed: $($_.Exception.Message)") }
    }
    if ($modules -contains "ports") {
        try { $result["listening_ports"] = @(Get-ListeningPorts) }
        catch { [void]$warnings.Add("Port inventory failed: $($_.Exception.Message)") }
    }
    if ($modules -contains "network") {
        try {
            $target = [string]$payload.target
            $customPorts = ""
            $profile = "common"
            $timeoutMs = $TimeoutMs
            $maxWorkers = $Workers
            if ($options) {
                if ($options.ports) { $customPorts = [string]$options.ports }
                if ($options.profile) { $profile = [string]$options.profile }
                if ($null -ne $options.connect_timeout) {
                    try { $timeoutMs = [int]([double]$options.connect_timeout * 1000) } catch { }
                }
                if ($options.workers) {
                    try { $maxWorkers = [int]$options.workers } catch { }
                }
            }
            $timeoutMs = [Math]::Max(100, [Math]::Min($timeoutMs, 3000))
            $maxWorkers = [Math]::Max(10, [Math]::Min($maxWorkers, 600))
            $result["network"] = Invoke-NetworkScan -ScanTarget $target -CustomPorts $customPorts `
                -PortProfile $profile -ConnectTimeoutMs $timeoutMs -MaxWorkers $maxWorkers
        } catch {
            [void]$warnings.Add("Network scan failed: $($_.Exception.Message)")
        }
    }
    if ($modules -contains "ad") {
        try { $result["ad"] = Invoke-AdAudit }
        catch {
            $result["ad_error"] = $_.Exception.Message
            [void]$warnings.Add("Active Directory audit failed: $($_.Exception.Message)")
        }
    }
    if ($warnings.Count -gt 0) {
        $result["warnings"] = @($warnings)
        $result["error"] = ($warnings -join "; ")
    }
    return $result
}

function Send-AgentResult {
    param($Config, [string]$JobId, $Result, [string]$Status = "completed", [string]$ErrorMessage = "")
    Invoke-VsApi -Config $Config -Method "POST" -Path "/api/agent/jobs/$JobId/result" -Payload ([ordered]@{
        status = $Status
        results = $Result
        error = $ErrorMessage
    }) -TimeoutSec 120 | Out-Null
}

function Get-PendingPath {
    $directory = Split-Path -Parent $ConfigPath
    return (Join-Path $directory "pending-result.json")
}

function Save-PendingResult {
    param([string]$JobId, $Result, [string]$Status, [string]$ErrorMessage)
    $path = Get-PendingPath
    $parent = Split-Path -Parent $path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [ordered]@{
        job_id = $JobId
        result = $Result
        status = $Status
        error = $ErrorMessage
    } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8
}

function Retry-PendingResult {
    param($Config)
    $path = Get-PendingPath
    if (-not (Test-Path -LiteralPath $path)) { return $true }
    try {
        $pending = ConvertTo-AgentHashtable (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
        Send-AgentResult -Config $Config -JobId $pending["job_id"] -Result $pending["result"] `
            -Status ([string]$pending["status"]) -ErrorMessage ([string]$pending["error"])
        Remove-Item -LiteralPath $path -Force
        Write-Log "Uploaded the previously pending result for job $($pending["job_id"])."
        return $true
    } catch {
        Write-Log "Pending result still cannot be uploaded: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-Heartbeat {
    param($Config)
    $info = Get-SystemInformation
    return Invoke-VsApi -Config $Config -Method "POST" -Path "/api/agent/heartbeat" -Payload ([ordered]@{
        platform = "Windows"
        version = $AgentVersion
        hostname = $info["hostname"]
        capabilities = @(Get-Capabilities)
    }) -TimeoutSec 20
}

function Invoke-PollOnce {
    param($Config)
    try {
        Invoke-Heartbeat -Config $Config | Out-Null
    } catch {
        Write-Log "Heartbeat failed: $($_.Exception.Message)"
        return $false
    }
    Retry-PendingResult -Config $Config | Out-Null
    try {
        $response = Invoke-VsApi -Config $Config -Method "POST" -Path "/api/agent/jobs/next" -Payload @{} -TimeoutSec 30
    } catch {
        Write-Log "Could not fetch a job: $($_.Exception.Message)"
        return $false
    }
    $job = $response.job
    if (-not $job) { return $false }
    $jobId = [string]$job.id
    Write-Log "Starting job $jobId (scan #$($job.scan_id))."
    try {
        $result = Invoke-AgentJob -Job $job
        $jobModules = @($job.payload.modules)
        if ($result["error"] -and ($jobModules -contains "network") -and -not $result["network"]) {
            throw $result["error"]
        }
        if ($result["error"] -and $result["ad_error"] -and -not $result["network"] -and -not $result["checks"]) {
            throw $result["error"]
        }
        Send-AgentResult -Config $Config -JobId $jobId -Result $result -Status "completed"
        Write-Log "Job $jobId completed."
    } catch {
        $message = "$($_.Exception.Message)"
        Write-Log "Job $jobId failed: $message"
        try {
            Send-AgentResult -Config $Config -JobId $jobId -Result ([ordered]@{ error = $message }) `
                -Status "failed" -ErrorMessage $message.Substring(0, [Math]::Min(3000, $message.Length))
        } catch {
            Save-PendingResult -JobId $jobId -Result ([ordered]@{ error = $message }) -Status "failed" `
                -ErrorMessage $message.Substring(0, [Math]::Min(3000, $message.Length))
        }
    }
    return $true
}

function Invoke-RunLoop {
    param($Config, [int]$Interval, [bool]$RunOnce)
    Write-Log "VulnScanner Windows agent $AgentVersion starting; server=$($Config["server"]) name=$($Config["name"])"
    if ($RunOnce) {
        Invoke-PollOnce -Config $Config | Out-Null
        return
    }
    while ($true) {
        try {
            $didWork = Invoke-PollOnce -Config $Config
            if ($didWork) { Start-Sleep -Seconds 2 } else { Start-Sleep -Seconds $Interval }
        } catch [System.Management.Automation.Host.ControlC] {
            return
        } catch {
            Write-Log "Agent loop error: $($_.Exception.Message)"
            Start-Sleep -Seconds ([Math]::Min($Interval * 2, 120))
        }
    }
}

function Invoke-Enroll {
    param([string]$EnrollServer, [string]$EnrollToken, [string]$AgentName, [bool]$VerifyCertificate, [int]$Interval)
    if (-not $EnrollServer) { throw "-Server is required for enrollment." }
    if (-not $EnrollToken) { throw "-Token is required for enrollment." }
    $EnrollServer = $EnrollServer.TrimEnd("/")
    if ($EnrollServer -notmatch "^https?://") { throw "-Server must start with http:// or https://" }
    $info = Get-SystemInformation
    $tempConfig = [ordered]@{ server = $EnrollServer; token = $null; verify_tls = $VerifyCertificate }
    Write-Log "Enrolling '$AgentName' with $EnrollServer."
    $response = Invoke-VsApi -Config $tempConfig -Method "POST" -Path "/api/agent/enroll" -Payload ([ordered]@{
        enrollment_token = $EnrollToken
        name = $AgentName
        platform = "Windows"
        version = $AgentVersion
        hostname = $info["hostname"]
        capabilities = @(Get-Capabilities)
    }) -TimeoutSec 30
    $config = [ordered]@{
        server = $EnrollServer
        token = [string]$response.token
        agent_id = [string]$response.agent_id
        name = [string]$response.name
        customer_id = $response.customer_id
        group_id = $response.group_id
        asset_id = $response.asset_id
        verify_tls = $VerifyCertificate
        poll_interval = $(if ($Interval -gt 0) { $Interval } else { [int]$response.poll_interval })
        enrolled_at = (Get-Date).ToUniversalTime().ToString("o")
        agent_kind = "powershell"
    }
    $saved = Save-AgentConfig -Config $config -Path $ConfigPath
    Write-Log "Enrolled as agent $($response.agent_id) ($($response.name))."
    Write-Log "Configuration saved to $saved."
}

function Invoke-Configure {
    param([string]$ConfigureServer, [string]$ConfigureToken, [string]$AgentName, [bool]$SetTls, [bool]$VerifyCertificate, [int]$Interval, [bool]$ReEnroll)
    if ($ReEnroll) {
        Invoke-Enroll -EnrollServer $ConfigureServer -EnrollToken $ConfigureToken -AgentName $AgentName `
            -VerifyCertificate $VerifyCertificate -Interval $Interval
        return
    }
    if (Test-Path -LiteralPath $ConfigPath) {
        $config = Read-AgentConfig -Path $ConfigPath
    } else {
        $config = [ordered]@{}
    }
    if ($ConfigureServer) {
        $ConfigureServer = $ConfigureServer.TrimEnd("/")
        if ($ConfigureServer -notmatch "^https?://") { throw "-Server must start with http:// or https://" }
        $config["server"] = $ConfigureServer
    }
    if ($AgentName) { $config["name"] = $AgentName }
    if ($Interval -gt 0) { $config["poll_interval"] = [Math]::Max(5, [Math]::Min($Interval, 3600)) }
    if ($SetTls) { $config["verify_tls"] = $VerifyCertificate }
    if ($ConfigureToken) {
        if ($ConfigureToken -notmatch "^vs_agent_") { throw "That does not look like an agent token." }
        $config["token"] = $ConfigureToken
    }
    if (-not $config["server"]) { throw "-Server is required when creating a new agent configuration." }
    $saved = Save-AgentConfig -Config $config -Path $ConfigPath
    Write-Log "Updated agent configuration at $saved."
    if (-not $config["token"]) {
        Write-Log "No agent token is configured yet. Enroll the agent before starting the service."
    }
}

function Invoke-Status {
    param($Config)
    $masked = [ordered]@{}
    foreach ($key in $Config.Keys) {
        if ($key -eq "token" -and $Config[$key]) {
            $value = [string]$Config[$key]
            if ($value.Length -gt 16) { $masked[$key] = $value.Substring(0, 10) + "..." } else { $masked[$key] = "***" }
        } else {
            $masked[$key] = $Config[$key]
        }
    }
    $masked | ConvertTo-Json -Depth 10
    try {
        Invoke-Heartbeat -Config $Config | ConvertTo-Json -Depth 10
        return 0
    } catch {
        Write-Log "Server unreachable: $($_.Exception.Message)"
        return 1
    }
}

function Invoke-OfflineScan {
    $moduleList = @($Modules.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $job = [ordered]@{
        payload = [ordered]@{
            modules = $moduleList
            target = $Target
            options = [ordered]@{
                ports = $Ports
                profile = $Profile
            }
        }
    }
    $result = Invoke-AgentJob -Job $job
    $json = $result | ConvertTo-Json -Depth 20
    if ($Output) {
        [System.IO.File]::WriteAllText($Output, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Log "Wrote result to $Output."
    } else {
        Write-Output $json
    }
}

$verifyCertificate = $true
if ($Insecure) { $verifyCertificate = $false }
if ($VerifyTls) { $verifyCertificate = $true }

try {
    switch ($Action) {
        "Enroll" {
            $interval = $PollInterval
            Invoke-Enroll -EnrollServer $Server -EnrollToken $Token -AgentName $Name `
                -VerifyCertificate $verifyCertificate -Interval $interval
        }
        "Configure" {
            $setTls = $Insecure -or $VerifyTls
            Invoke-Configure -ConfigureServer $Server -ConfigureToken $Token -AgentName $Name `
                -SetTls $setTls -VerifyCertificate $verifyCertificate -Interval $PollInterval -ReEnroll $Enroll
        }
        "Status" {
            $config = Read-AgentConfig -Path $ConfigPath
            exit (Invoke-Status -Config $config)
        }
        "Scan" {
            Invoke-OfflineScan
        }
        default {
            $config = Read-AgentConfig -Path $ConfigPath
            $interval = 30
            if ($config["poll_interval"]) { $interval = [Math]::Max(5, [int]$config["poll_interval"]) }
            if ($PollInterval -gt 0) { $interval = [Math]::Max(5, $PollInterval) }
            Invoke-RunLoop -Config $config -Interval $interval -RunOnce ([bool]$Once)
        }
    }
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
