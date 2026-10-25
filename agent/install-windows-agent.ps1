#Requires -Version 5.1
<#
.SYNOPSIS
    Install, configure or remove the native Windows VulnScanner agent.

.DESCRIPTION
    Downloads the PowerShell agent from the VulnScanner server, enrolls it with
    a one-time token and registers an auto-restarting scheduled task. The agent
    runs on Windows client and server editions and does not require Python.

    The agent only makes outbound HTTP(S) requests. No inbound firewall rule is
    required. Run this script in an elevated PowerShell window.

    With no parameters the installer prompts for the server, token, agent name
    and TLS choice. Pass -Configure later to change the server, token, poll
    interval, TLS verification or service account without reinstalling.

.EXAMPLE
    .\install-windows-agent.ps1

.EXAMPLE
    .\install-windows-agent.ps1 -Server https://scanner.example.com -Token vs_enroll_...

.EXAMPLE
    .\install-windows-agent.ps1 -Configure -Server https://scanner.example.com -PollInterval 60

.EXAMPLE
    .\install-windows-agent.ps1 -Configure -Insecure

.EXAMPLE
    .\install-windows-agent.ps1 -Uninstall

.EXAMPLE
    .\install-windows-agent.ps1 -Uninstall -Purge
#>
[CmdletBinding()]
param(
    [string]$Server = "",
    [string]$Token = "",
    [string]$Name = "",
    [string]$InstallDir = (Join-Path $env:ProgramFiles "VulnScanner Agent"),
    [string]$StateDir = (Join-Path $env:ProgramData "VulnScanner Agent"),
    [string]$ConfigPath = "",
    [ValidateRange(0, 3600)]
    [int]$PollInterval = 0,
    [switch]$Insecure,
    [switch]$VerifyTls,
    [string]$ServiceAccount = "SYSTEM",
    [switch]$SkipAdCollector,
    [switch]$NoService,
    [switch]$Configure,
    [switch]$EnrollAgain,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$Interactive,
    [switch]$ForceDownload
)

$ErrorActionPreference = "Stop"
$AgentVersion = "1.1.0"
$TaskName = "VulnScanner Agent"
$AgentFileName = "VulnScannerAgent.ps1"
$AdFileName = "ad_audit.ps1"

function Write-Status {
    param([string]$Message, [string]$Color = "Gray")
    Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message) -ForegroundColor $Color
}

function Write-Fail {
    param([string]$Message)
    Write-Host "ERROR: $Message" -ForegroundColor Red
}

function Assert-Administrator {
    if ($env:OS -ne "Windows_NT") {
        throw "This installer must run on Windows."
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell window (Run as Administrator)."
    }
}

function Get-WindowsEditionInfo {
    $info = [ordered]@{
        caption = [Environment]::OSVersion.VersionString
        product_type = "unknown"
        domain = ""
        is_domain_joined = $false
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $info["caption"] = [string]$os.Caption
        $info["version"] = [string]$os.Version
        $info["build"] = [string]$os.BuildNumber
        switch ([int]$os.ProductType) {
            1 { $info["product_type"] = "client" }
            2 { $info["product_type"] = "server" }
            3 { $info["product_type"] = "server-core" }
        }
    } catch { }
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $info["domain"] = [string]$computer.Domain
        $info["is_domain_joined"] = [bool]$computer.PartOfDomain
    } catch { }
    return $info
}

function Show-Plan {
    param([string]$ActionName, [string]$TargetServer, [string]$TargetName)
    $os = Get-WindowsEditionInfo
    $edition = switch ($os["product_type"]) {
        "client" { "Windows client" }
        "server" { "Windows Server" }
        "server-core" { "Windows Server Core" }
        default { "Windows" }
    }
    Write-Status "VulnScanner Windows agent installer"
    Write-Status ("Host     : {0} ({1})" -f $env:COMPUTERNAME, $edition)
    Write-Status ("OS       : {0}" -f $os["caption"])
    if ($os["is_domain_joined"]) {
        Write-Status ("Domain   : {0}" -f $os["domain"])
    }
    Write-Status ("Action   : {0}" -f $ActionName)
    if ($TargetServer) { Write-Status ("Server   : {0}" -f $TargetServer) }
    if ($TargetName) { Write-Status ("Agent    : {0}" -f $TargetName) }
    Write-Status ("Install  : {0}" -f $InstallDir)
    Write-Status ("State    : {0}" -f (Split-Path -Parent (Get-AgentConfigPath)))
}

function Get-AgentConfigPath {
    if ($ConfigPath) { return $ConfigPath }
    return (Join-Path $StateDir "agent.json")
}

function Protect-InstallerPath {
    param([string]$Path, [switch]$Directory)
    try {
        if ($Directory) {
            & icacls $Path /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" 2>$null | Out-Null
        } else {
            & icacls $Path /inheritance:r /grant:r "SYSTEM:F" "BUILTIN\Administrators:F" 2>$null | Out-Null
        }
    } catch {
        Write-Status "Could not tighten permissions on $Path : $($_.Exception.Message)" "Yellow"
    }
}

function Test-BuiltInServiceAccount {
    param([string]$Account)
    return ($Account -match "^(SYSTEM|LocalSystem|NT AUTHORITY\\(SYSTEM|LocalService|NetworkService))$")
}

function Grant-ServiceAccountAccess {
    param([string]$Account)
    if (Test-BuiltInServiceAccount $Account) { return }
    try {
        # The agent reads its script and configuration and writes pending
        # results, so a custom (non-built-in) task account needs explicit ACLs.
        & icacls $InstallDir /grant:r "${Account}:(OI)(CI)RX" 2>$null | Out-Null
        & icacls $StateDir /grant:r "${Account}:(OI)(CI)M" 2>$null | Out-Null
        $config = Get-AgentConfigPath
        if (Test-Path -LiteralPath $config) {
            & icacls $config /grant:r "${Account}:R" 2>$null | Out-Null
        }
    } catch {
        Write-Status "Could not grant $Account access to the agent files: $($_.Exception.Message)" "Yellow"
        Write-Status "The scheduled task may not be able to read its configuration." "Yellow"
    }
}

function Set-TlsCallback {
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

function Get-ServerBase {
    param([string]$Value)
    $value = ("" + $Value).Trim().TrimEnd("/")
    if (-not $value) { throw "A VulnScanner server URL is required." }
    if ($value -notmatch "^https?://") {
        throw "The server URL must start with http:// or https:// (for example https://scanner.example.com)."
    }
    return $value
}

function Invoke-Download {
    param([string]$Url, [string]$Destination, [bool]$Verify)
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Set-TlsCallback -Verify $Verify
    $request = @{
        Uri = $Url
        OutFile = $Destination
        UseBasicParsing = $true
        TimeoutSec = 60
    }
    if (-not $Verify -and $PSVersionTable.PSVersion.Major -ge 7) {
        $request["SkipCertificateCheck"] = $true
    }
    Invoke-WebRequest @request
}

function Install-AgentFiles {
    param([string]$BaseUrl, [bool]$Verify)
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Protect-InstallerPath -Path $InstallDir -Directory
    }
    if (-not (Test-Path -LiteralPath $StateDir)) {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
        Protect-InstallerPath -Path $StateDir -Directory
    }

    $agentPath = Join-Path $InstallDir $AgentFileName
    $agentUrl = "$BaseUrl/agent/$AgentFileName"
    $downloadAgent = $ForceDownload -or -not (Test-Path -LiteralPath $agentPath)
    if (-not $downloadAgent) {
        try {
            $localVersion = (Select-String -LiteralPath $agentPath -Pattern '^\$AgentVersion\s*=\s*"([^"]+)"' -ErrorAction Stop |
                Select-Object -First 1).Matches.Groups[1].Value
            $downloadAgent = ($localVersion -ne $AgentVersion)
        } catch {
            $downloadAgent = $true
        }
    }
    if ($downloadAgent) {
        Write-Status "Downloading $agentUrl" "Cyan"
        $tempPath = "$agentPath.download"
        Invoke-Download -Url $agentUrl -Destination $tempPath -Verify $Verify
        Move-Item -LiteralPath $tempPath -Destination $agentPath -Force
        Write-Status "Installed $agentFileName" "Green"
    } else {
        Write-Status "Using the existing agent at $agentPath (use -ForceDownload to refresh)."
    }
    Protect-InstallerPath -Path $agentPath

    if (-not $SkipAdCollector) {
        $adPath = Join-Path $InstallDir $AdFileName
        $downloadAd = $ForceDownload -or -not (Test-Path -LiteralPath $adPath)
        if ($downloadAd) {
            try {
                Invoke-Download -Url "$BaseUrl/agent/$AdFileName" -Destination "$adPath.download" -Verify $Verify
                Move-Item -LiteralPath "$adPath.download" -Destination $adPath -Force
                Protect-InstallerPath -Path $adPath
                Write-Status "Installed the optional Active Directory collector." "Green"
            } catch {
                Write-Status "Could not download $AdFileName (the AD module will be unavailable): $($_.Exception.Message)" "Yellow"
            }
        }
    }
    return $agentPath
}

function Invoke-AgentScript {
    param([string]$AgentPath, [string[]]$Arguments)
    & $AgentPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "The agent command failed with exit code $LASTEXITCODE."
    }
}

function Register-AgentTask {
    param([string]$AgentPath)
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Status "Replacing the existing scheduled task." "Yellow"
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    $escapedAgent = '"' + $AgentPath + '"'
    $escapedConfig = '"' + (Get-AgentConfigPath) + '"'
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $escapedAgent -Action Run -ConfigPath $escapedConfig"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    $builtIn = $ServiceAccount -match "^(SYSTEM|LocalSystem|NT AUTHORITY\\(SYSTEM|LocalService|NetworkService))$"
    if ($builtIn) {
        $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal -Description "Polls the VulnScanner server outbound and runs endpoint checks." | Out-Null
    } else {
        Write-Status "The task will run as $ServiceAccount." "Cyan"
        $secure = Read-Host -Prompt "Password for $ServiceAccount" -AsSecureString
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        )
        try {
            if (-not $plain) { throw "A password is required for $ServiceAccount." }
            Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
                -Settings $settings -User $ServiceAccount -Password $plain -RunLevel Highest `
                -Description "Polls the VulnScanner server outbound and runs endpoint checks." | Out-Null
        } finally {
            $plain = $null
        }
    }
    Write-Status "Registered scheduled task '$TaskName' running as $ServiceAccount." "Green"
}

function Start-AgentTask {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq "Running") {
        Write-Status "The agent service is running." "Green"
    } else {
        Write-Status "The task was registered but is not running yet. Check Task Scheduler for details." "Yellow"
    }
}

function Stop-AgentTask {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Status "Removed scheduled task '$TaskName'." "Green"
    }
}

function Read-InstallValue {
    param(
        [string]$Prompt,
        [string]$Default = "",
        [switch]$Required,
        [switch]$Secret
    )
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { "" }
        if ($Secret) {
            $value = Read-Host -Prompt ($Prompt + $suffix) -AsSecureString
            $value = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($value)
            )
        } else {
            $value = Read-Host -Prompt ($Prompt + $suffix)
        }
        if (-not $value) { $value = $Default }
        if ($value -or -not $Required) { return $value }
        Write-Host "A value is required." -ForegroundColor Yellow
    }
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $hint = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host -Prompt "$Prompt $hint"
    if (-not $answer) { return $Default }
    return ($answer.Trim().ToLowerInvariant() -in @("y", "yes"))
}

function Get-InteractiveSettings {
    $settings = [ordered]@{
        Server = $Server
        Token = $Token
        Name = $Name
        VerifyTls = (-not $Insecure)
        PollInterval = $PollInterval
        ServiceAccount = $ServiceAccount
    }
    if (-not $settings.Server) {
        $settings.Server = Read-InstallValue -Prompt "VulnScanner server URL" -Default "https://scanner.example.com" -Required
    }
    $settings.Server = Get-ServerBase $settings.Server
    if (-not $settings.Token) {
        $settings.Token = Read-InstallValue -Prompt "One-time enrollment token or agent token" -Required -Secret
    }
    if (-not $Name -or $Name -eq $env:COMPUTERNAME) {
        $settings.Name = Read-InstallValue -Prompt "Agent name" -Default $env:COMPUTERNAME -Required
    }
    if (-not $Insecure -and -not $VerifyTls) {
        $settings.VerifyTls = Read-YesNo -Prompt "Verify the server TLS certificate?" -Default $true
    }
    $intervalDefault = if ($PollInterval -gt 0) { $PollInterval } else { 30 }
    $interval = Read-InstallValue -Prompt "Poll interval in seconds" -Default ([string]$intervalDefault)
    $parsedInterval = 0
    if ([int]::TryParse($interval, [ref]$parsedInterval) -and $parsedInterval -ge 5) {
        $settings.PollInterval = $parsedInterval
    }
    return $settings
}

function Invoke-Configure {
    param([bool]$DownloadFiles, [bool]$UseInteractive)
    if ($UseInteractive) {
        $values = Get-InteractiveSettings
        $script:Server = $values.Server
        $script:Token = $values.Token
        $script:Name = $values.Name
        $script:PollInterval = $values.PollInterval
        if (-not $values.VerifyTls) { $script:Insecure = $true }
        if ($values.VerifyTls) { $script:VerifyTls = $true }
    }
    $baseUrl = ""
    if ($Server) { $baseUrl = Get-ServerBase $Server }
    $config = Get-AgentConfigPath
    if (-not (Test-Path -LiteralPath $config) -and -not (Test-Path -LiteralPath (Join-Path $InstallDir $AgentFileName))) {
        if (-not $baseUrl) {
            throw "No agent is installed yet. Run this installer with -Server and -Token first."
        }
    }
    if ($DownloadFiles -and $baseUrl) {
        if (-not (Test-Path -LiteralPath $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Protect-InstallerPath -Path $InstallDir -Directory
        }
        [void](Install-AgentFiles -BaseUrl $baseUrl -Verify (-not $Insecure))
    }
    $agentPath = Join-Path $InstallDir $AgentFileName
    if (-not (Test-Path -LiteralPath $agentPath)) {
        throw "The agent script is missing at $agentPath. Run the installer again with -Server."
    }
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $config))) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $config) -Force | Out-Null
        Protect-InstallerPath -Path (Split-Path -Parent $config) -Directory
    }
    if ($EnrollAgain -and (-not $baseUrl -or -not $Token)) {
        throw "-EnrollAgain requires -Server and a fresh one-time -Token."
    }
    $arguments = @("-Action", "Configure", "-ConfigPath", $config, "-PollInterval", [string]$PollInterval)
    if ($baseUrl) { $arguments += @("-Server", $baseUrl) }
    if ($Token) { $arguments += @("-Token", $Token) }
    if ($Name) { $arguments += @("-Name", $Name) }
    if ($Insecure) { $arguments += "-Insecure" }
    elseif ($VerifyTls) { $arguments += "-VerifyTls" }
    if ($EnrollAgain) {
        $arguments = @("-Action", "Enroll", "-ConfigPath", $config, "-Server", $baseUrl,
            "-Token", $Token, "-Name", $Name, "-PollInterval", [string]$PollInterval)
        if ($Insecure) { $arguments += "-Insecure" }
        elseif ($VerifyTls) { $arguments += "-VerifyTls" }
    } elseif (-not (Test-Path -LiteralPath $config)) {
        if (-not ($baseUrl -and $Token)) {
            throw "Creating a new configuration requires -Server and -Token."
        }
        $arguments = @("-Action", "Enroll", "-ConfigPath", $config, "-Server", $baseUrl,
            "-Token", $Token, "-Name", $Name, "-PollInterval", [string]$PollInterval)
        if ($Insecure) { $arguments += "-Insecure" }
        elseif ($VerifyTls) { $arguments += "-VerifyTls" }
    }
    Write-Status "Applying agent configuration." "Cyan"
    Invoke-AgentScript -AgentPath $agentPath -Arguments $arguments
    Protect-InstallerPath -Path $config
    if (-not $NoService) {
        Grant-ServiceAccountAccess -Account $ServiceAccount
        Register-AgentTask -AgentPath $agentPath
        Start-AgentTask
    } else {
        Write-Status "Service registration skipped (-NoService)." "Yellow"
    }
}

function Invoke-Install {
    param([bool]$UseInteractive)
    if ($UseInteractive) {
        $values = Get-InteractiveSettings
        $script:Server = $values.Server
        $script:Token = $values.Token
        $script:Name = $values.Name
        $script:PollInterval = $values.PollInterval
        if (-not $values.VerifyTls) { $script:Insecure = $true }
        if ($values.VerifyTls) { $script:VerifyTls = $true }
    }
    $baseUrl = Get-ServerBase $Server
    if (-not $Token) { throw "-Token is required to enroll the agent." }
    if ($Token -notmatch "^vs_(enroll|agent)_") {
        throw "The token does not look like a VulnScanner enrollment or agent token."
    }
    if (-not $Name) { $script:Name = $env:COMPUTERNAME }
    $usingAgentToken = $Token -match "^vs_agent_"
    $actionName = "Install and enroll"
    if ($usingAgentToken) { $actionName = "Install with an existing agent token" }
    Show-Plan -ActionName $actionName -TargetServer $baseUrl -TargetName $Name
    $agentPath = Install-AgentFiles -BaseUrl $baseUrl -Verify (-not $Insecure)
    $config = Get-AgentConfigPath

    if ($usingAgentToken) {
        # Reinstalling with an existing token skips enrolment. The server
        # already knows the agent, so only the local configuration is written.
        Write-Status "Applying the existing agent token without re-enrolling." "Cyan"
        $enrollArguments = @("-Action", "Configure", "-ConfigPath", $config, "-Server", $baseUrl,
            "-Token", $Token, "-Name", $Name, "-PollInterval", [string]$PollInterval)
    } else {
        Write-Status "Enrolling the endpoint." "Cyan"
        $enrollArguments = @("-Action", "Enroll", "-ConfigPath", $config, "-Server", $baseUrl,
            "-Token", $Token, "-Name", $Name, "-PollInterval", [string]$PollInterval)
    }
    if ($Insecure) { $enrollArguments += "-Insecure" }
    elseif ($VerifyTls) { $enrollArguments += "-VerifyTls" }
    Invoke-AgentScript -AgentPath $agentPath -Arguments $enrollArguments
    Protect-InstallerPath -Path $config
    Protect-InstallerPath -Path $StateDir -Directory
    Protect-InstallerPath -Path $InstallDir -Directory

    if ($NoService) {
        Write-Status "Installation complete. Start the agent manually with:" "Green"
        Write-Status ("  powershell -ExecutionPolicy Bypass -File `"{0}`" -Action Run -ConfigPath `"{1}`"" -f $agentPath, $config)
        return
    }
    Grant-ServiceAccountAccess -Account $ServiceAccount
    Register-AgentTask -AgentPath $agentPath
    Start-AgentTask
    Write-Status "Installation complete." "Green"
    Write-Status ("  Agent   : {0}" -f $Name)
    Write-Status ("  Server  : {0}" -f $baseUrl)
    Write-Status ("  Files   : {0}" -f $InstallDir)
    Write-Status ("  Config  : {0}" -f $config)
    Write-Status ("  Task    : {0} ({1})" -f $TaskName, $ServiceAccount)
    Write-Status "Use -Configure later to change the server, token, poll interval or TLS setting."
}

function Invoke-Uninstall {
    param([bool]$RemoveState)
    Show-Plan -ActionName ($(if ($RemoveState) { "Uninstall and purge" } else { "Uninstall" }))
    Stop-AgentTask
    if (Test-Path -LiteralPath $InstallDir) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
        Write-Status "Removed $InstallDir." "Green"
    }
    if ($RemoveState) {
        if (Test-Path -LiteralPath $StateDir) {
            Remove-Item -LiteralPath $StateDir -Recurse -Force
            Write-Status "Removed state and configuration in $StateDir." "Green"
        }
        if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath) -and $ConfigPath -notlike "$StateDir*") {
            Remove-Item -LiteralPath $ConfigPath -Force
            Write-Status "Removed $ConfigPath." "Green"
        }
    } else {
        Write-Status "The enrollment configuration in $StateDir was kept. Use -Purge to remove it." "Yellow"
    }
    Write-Status "Uninstall complete. Revoke the agent in the VulnScanner UI if it is no longer needed." "Green"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

try {
    Assert-Administrator

    if ($Uninstall) {
        Invoke-Uninstall -RemoveState ([bool]$Purge)
        exit 0
    }

    $needsInteractive = $Interactive -or (-not $Configure -and (-not $Server -or -not $Token))
    if ($Configure) {
        Invoke-Configure -DownloadFiles ([bool]$Server) -UseInteractive $needsInteractive
    } else {
        Invoke-Install -UseInteractive $needsInteractive
    }
    exit 0
} catch {
    Write-Fail $_.Exception.Message
    exit 1
}
