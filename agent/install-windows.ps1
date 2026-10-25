#Requires -Version 5.1
<#
.SYNOPSIS
    Install the VulnScanner endpoint agent as a Windows scheduled task.

.DESCRIPTION
    Downloads the standard-library Python agent from the VulnScanner server,
    enrolls it with a one-time token and registers an auto-restarting scheduled
    task that runs as SYSTEM. No inbound firewall rule is required: the agent
    polls the server over outbound HTTPS.

    Run PowerShell as Administrator.

.EXAMPLE
    .\install-windows.ps1 -Server https://scanner.example.com -Token vs_enroll_...

.EXAMPLE
    .\install-windows.ps1 -Server https://scanner.example.com -Token vs_enroll_... -Insecure
#>
param(
    [string]$Server = "",
    [string]$Token = "",
    [string]$Name = $env:COMPUTERNAME,
    [string]$InstallDir = (Join-Path $env:ProgramFiles "VulnScanner Agent"),
    [string]$StateDir = (Join-Path $env:ProgramData "VulnScanner Agent"),
    [string]$ConfigPath = "",
    [string]$Python = "",
    [switch]$Insecure,
    [switch]$NoService,
    [switch]$Uninstall,
    [switch]$Purge
)

$ErrorActionPreference = "Stop"
$TaskName = "VulnScanner Agent"
$AgentFile = Join-Path $InstallDir "vulnscanner_agent.py"
if (-not $ConfigPath) { $ConfigPath = Join-Path $StateDir "agent.json" }

function Write-Log([string]$Message) {
    Write-Host "[vulnscanner] $Message"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated PowerShell window (Run as Administrator)."
    }
}

function Get-Python {
    if ($Python) {
        if (-not (Test-Path -LiteralPath $Python)) { throw "Python was not found at '$Python'." }
        return @{ Exe = (Resolve-Path -LiteralPath $Python).Path; Prefix = @() }
    }
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) { return @{ Exe = $python.Source; Prefix = @() } }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) { return @{ Exe = $py.Source; Prefix = @("-3") } }
    throw "Python 3.8+ was not found. Install Python from python.org and select 'Add Python to PATH', then retry."
}

function Invoke-Python {
    param(
        [hashtable]$PythonInfo,
        [string[]]$Arguments
    )
    $all = @($PythonInfo.Prefix) + $Arguments
    & $PythonInfo.Exe @all
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE."
    }
}

function Set-RestrictedAcl([string]$Path, [bool]$Directory) {
    if ($Directory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -LiteralPath $Path -AclObject $acl
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "Read", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "Read", "Allow")))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

Assert-Administrator

if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Removed scheduled task '$TaskName'."
    }
    if (Test-Path -LiteralPath $InstallDir) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
        Write-Log "Removed $InstallDir."
    }
    if ($Purge -and (Test-Path -LiteralPath $StateDir)) {
        Remove-Item -LiteralPath $StateDir -Recurse -Force
        Write-Log "Removed state directory $StateDir."
    } elseif (Test-Path -LiteralPath $StateDir) {
        Write-Log "Configuration and pending results were kept in $StateDir (use -Purge to remove)."
    }
    exit 0
}

if (-not $Server) { throw "-Server is required. Example: -Server https://scanner.example.com" }
$Server = $Server.TrimEnd("/")
if ($Server -notmatch '^https?://') { throw "-Server must start with http:// or https://" }

Write-Log "Checking Python"
$pythonInfo = Get-Python
Invoke-Python -PythonInfo $pythonInfo -Arguments @("-c", "import sys; assert sys.version_info >= (3,8), 'Python 3.8+ required'")

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

$localAgent = Join-Path $PSScriptRoot "vulnscanner_agent.py"
if ((Test-Path -LiteralPath $localAgent) -and ((Resolve-Path -LiteralPath $localAgent).Path -ne (Join-Path $InstallDir "vulnscanner_agent.py"))) {
    Copy-Item -LiteralPath $localAgent -Destination $AgentFile -Force
    Write-Log "Copied local agent from $localAgent"
} else {
    $uri = "$Server/agent/vulnscanner_agent.py"
    Write-Log "Downloading $uri"
    Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $AgentFile
}
$firstLine = Get-Content -LiteralPath $AgentFile -TotalCount 1
if (-not $firstLine.StartsWith("#!")) { throw "The downloaded file does not look like the VulnScanner agent." }
Invoke-Python -PythonInfo $pythonInfo -Arguments @("-m", "py_compile", $AgentFile)

if ($NoService) {
    Write-Log "Installed agent files only (-NoService)."
}

if ($Token) {
    Write-Log "Enrolling agent '$Name' with $Server"
    $enrollArgs = @($AgentFile, "--config", $ConfigPath, "enroll", "--server", $Server, "--token", $Token, "--name", $Name)
    if ($Insecure) { $enrollArgs += "--insecure" }
    Invoke-Python -PythonInfo $pythonInfo -Arguments $enrollArgs
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Enrollment succeeded but no configuration was written to $ConfigPath." }
    Set-RestrictedAcl -Path $ConfigPath -Directory $false
    Write-Log "Enrollment complete."
} else {
    Write-Log "No -Token supplied. The agent is installed but not enrolled."
    $prefix = ($pythonInfo.Prefix -join " ")
    Write-Log "Create a token in the VulnScanner UI, then run:"
    Write-Log "  `"$($pythonInfo.Exe)`" $prefix `"$AgentFile`" --config `"$ConfigPath`" enroll --server $Server --token <TOKEN> --name `"$Name`""
    if (-not $NoService) {
        Write-Log "Register the task after enrollment with:"
        Write-Log "  schtasks /Create /TN `"$TaskName`" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR `"`"$($pythonInfo.Exe)`" $prefix `"$AgentFile`" --config `"$ConfigPath`" run`""
    }
    exit 0
}

Set-RestrictedAcl -Path $StateDir -Directory $true

if ($NoService) {
    Write-Log "Run the agent manually: `"$($pythonInfo.Exe)`" $($pythonInfo.Prefix -join ' ') `"$AgentFile`" --config `"$ConfigPath`" run"
    exit 0
}

Write-Log "Registering scheduled task '$TaskName' (runs as SYSTEM at startup)"
$arguments = (@($pythonInfo.Prefix) + @("`"$AgentFile`"", "--config", "`"$ConfigPath`"", "run")) -join " "
$action = New-ScheduledTaskAction -Execute $pythonInfo.Exe -Argument $arguments -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$old = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($old) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3

$task = Get-ScheduledTask -TaskName $TaskName
$info = Get-ScheduledTaskInfo -TaskName $TaskName
Write-Log "Task state: $($task.State); last result: $($info.LastTaskResult)"
Write-Log "Installation complete. The agent polls the server; no inbound firewall rule is needed."
Write-Log "Troubleshooting: run the agent manually with the command above, or inspect Task Scheduler."
