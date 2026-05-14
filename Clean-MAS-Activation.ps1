<# 
.SYNOPSIS
    DeActive by MyPC - conservative cleanup for MAS/KMS-style activation artifacts.

.DESCRIPTION
    Removes clearly identified non-standard activation persistence/configuration from
    Windows and Microsoft Office so a technician can move a machine back to legitimate
    Windows/Office activation.

    This script does not activate Windows or Office, does not install or contact KMS
    servers, and deliberately does not clear event logs, Defender history, Prefetch,
    Amcache, ShimCache, SRUM, or other forensic artifacts.

.NOTES
    Requires Windows PowerShell 5.1 or later and Administrator rights.
    Default log path: C:\ProgramData\LegitActivationCleaner\Logs
    Default backup path: C:\ProgramData\LegitActivationCleaner\Backups
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$DryRun,

    [switch]$CreateRestorePoint,
    [switch]$SkipOffice,
    [switch]$SkipWindows,
    [switch]$SkipOhookCleanup,
    [switch]$VerboseLog,
    [switch]$ExportReport,
    [switch]$Force,
    [switch]$NoRestartServices,
    [switch]$ForceWindowsProductKeyRemoval,
    [switch]$InstallPostRebootSweep,
    [switch]$PostRebootSweep
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolName = 'DeActive by MyPC'
$script:Version = '1.2.0'
$script:RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:ProgramDataRoot = Join-Path $env:ProgramData 'LegitActivationCleaner'
$script:LogRoot = Join-Path $script:ProgramDataRoot 'Logs'
$script:BackupRoot = Join-Path (Join-Path $script:ProgramDataRoot 'Backups') $script:RunId
$script:ReportRoot = Join-Path $script:ProgramDataRoot 'Reports'
$script:LogPath = $null
$script:DryRunMode = [bool]($DryRun -or $WhatIfPreference)
# Convert script-level -WhatIf into the tool's own dry-run mode. This keeps
# logging, backups, and report generation usable while all destructive work is
# still blocked by Invoke-SafeAction / Invoke-ExternalCommandSafe.
$WhatIfPreference = $false
$script:HadWarnings = $false
$script:FatalError = $false
$script:DetectedScheduledTasks = @()
$script:DetectedMASFileArtifacts = @()
$script:DetectedOhookArtifacts = @()

$script:Report = [ordered]@{
    ToolName = $script:ToolName
    Version = $script:Version
    ScriptName = 'Clean-MAS-Activation.ps1'
    RunId = $script:RunId
    StartTime = (Get-Date).ToString('o')
    EndTime = $null
    DryRun = $script:DryRunMode
    Force = [bool]$Force
    Parameters = [ordered]@{
        CreateRestorePoint = [bool]$CreateRestorePoint
        SkipOffice = [bool]$SkipOffice
        SkipWindows = [bool]$SkipWindows
        SkipOhookCleanup = [bool]$SkipOhookCleanup
        VerboseLog = [bool]$VerboseLog
        ExportReport = [bool]$ExportReport
        Force = [bool]$Force
        NoRestartServices = [bool]$NoRestartServices
        ForceWindowsProductKeyRemoval = [bool]$ForceWindowsProductKeyRemoval
        InstallPostRebootSweep = [bool]$InstallPostRebootSweep
        PostRebootSweep = [bool]$PostRebootSweep
    }
    OS = [ordered]@{}
    WindowsActivationBefore = @()
    WindowsActivationAfter = @()
    WindowsKeysRemoved = New-Object System.Collections.ArrayList
    OfficeProducts = New-Object System.Collections.ArrayList
    OfficeKeysRemoved = New-Object System.Collections.ArrayList
    ScheduledTasksRemoved = New-Object System.Collections.ArrayList
    RegistryValuesRemoved = New-Object System.Collections.ArrayList
    RegistryKeysRemoved = New-Object System.Collections.ArrayList
    FilesRemovedOrRenamed = New-Object System.Collections.ArrayList
    ServicesRestarted = New-Object System.Collections.ArrayList
    DetectedArtifacts = New-Object System.Collections.ArrayList
    Actions = New-Object System.Collections.ArrayList
    Skipped = New-Object System.Collections.ArrayList
    Warnings = New-Object System.Collections.ArrayList
    Errors = New-Object System.Collections.ArrayList
    ReportFiles = New-Object System.Collections.ArrayList
    NextSteps = New-Object System.Collections.ArrayList
}

function Test-IsAdministrator {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-RunStorage {
    [CmdletBinding()]
    param()

    foreach ($path in @($script:ProgramDataRoot, $script:LogRoot, $script:BackupRoot, $script:ReportRoot)) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        }
    }

    $script:LogPath = Join-Path $script:LogRoot ("LegitActivationCleaner-{0}.log" -f $script:RunId)
    New-Item -Path $script:LogPath -ItemType File -Force | Out-Null
}

function Add-ReportAction {
    [CmdletBinding()]
    param(
        [string]$Category,
        [string]$Action,
        [string]$Target,
        [string]$Status,
        [string]$Detail,
        [object]$Data
    )

    $entry = [pscustomobject]@{
        Time = (Get-Date).ToString('o')
        Category = $Category
        Action = $Action
        Target = $Target
        Status = $Status
        Detail = $Detail
        Data = $Data
    }
    $null = $script:Report.Actions.Add($entry)
}

function Add-ReportListItem {
    [CmdletBinding()]
    param(
        [string]$ListName,
        [object]$Item
    )

    if ($script:Report.Contains($ListName) -and $script:Report[$ListName] -is [System.Collections.IList]) {
        $null = $script:Report[$ListName].Add($Item)
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'VERBOSE')]
        [string]$Level = 'INFO'
    )

    if ($Level -eq 'VERBOSE' -and -not $VerboseLog) {
        $writeConsole = $false
    } else {
        $writeConsole = $true
    }

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    if ($script:LogPath) {
        try {
            Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
        } catch {
            Write-Host "Failed to write log file: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    if ($Level -eq 'WARN') {
        $script:HadWarnings = $true
        $null = $script:Report.Warnings.Add([pscustomobject]@{
            Time = (Get-Date).ToString('o')
            Message = $Message
        })
    } elseif ($Level -eq 'ERROR') {
        $script:HadWarnings = $true
        $null = $script:Report.Errors.Add([pscustomobject]@{
            Time = (Get-Date).ToString('o')
            Message = $Message
        })
    }

    if ($writeConsole) {
        $color = switch ($Level) {
            'WARN' { 'Yellow' }
            'ERROR' { 'Red' }
            'SUCCESS' { 'Green' }
            'VERBOSE' { 'DarkGray' }
            default { 'Gray' }
        }
        Write-Host $line -ForegroundColor $color
    }
}

function Write-Step {
    [CmdletBinding()]
    param(
        [int]$Number,
        [string]$Name
    )

    $text = '{0}. {1}' -f $Number, $Name
    Write-Host ''
    Write-Host $text -ForegroundColor Cyan
    Write-Log -Message $text -Level 'INFO'
}

function Show-OfficeCloseWarning {
    [CmdletBinding()]
    param()

    if ($SkipOffice) {
        return
    }

    $message = 'Close all Microsoft Office apps before cleanup: Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher, Project, Visio, Teams/OneDrive Office file sessions, and any open Office setup/repair window.'
    Write-Host ''
    Write-Host "WARNING: $message" -ForegroundColor Yellow
    Write-Log -Message $message -Level 'WARN'
}

function Invoke-SafeAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,

        [string]$Category = 'General',
        [string]$Target = '',
        [object]$Data = $null,
        [switch]$Fatal
    )

    if ($script:DryRunMode) {
        Write-Log -Message "Would do: $Description" -Level 'INFO'
        Add-ReportAction -Category $Category -Action $Description -Target $Target -Status 'WouldDo' -Detail 'Dry-run/WhatIf mode; no change was made.' -Data $Data
        return $null
    }

    try {
        Write-Log -Message "Doing: $Description" -Level 'INFO'
        $result = & $Action
        Write-Log -Message "Done: $Description" -Level 'SUCCESS'
        Add-ReportAction -Category $Category -Action $Description -Target $Target -Status 'Done' -Detail '' -Data $Data
        return $result
    } catch {
        $message = "Failed: $Description. $($_.Exception.Message)"
        Write-Log -Message $message -Level 'ERROR'
        Add-ReportAction -Category $Category -Action $Description -Target $Target -Status 'Failed' -Detail $_.Exception.Message -Data $Data
        if ($Fatal) {
            throw
        }
        return $null
    }
}

function ConvertTo-SafeFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $safe = $Name -replace '[\\/:*?"<>|]+', '_'
    $safe = $safe -replace '\s+', '_'
    return $safe.Trim('_')
}

function ConvertTo-RegExePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $p = ($RegistryPath -replace '/', '\').Trim()
    $p = $p -replace '^Registry::', ''

    if ($p -match '^HKLM:\\(.+)$') { return "HKLM\$($Matches[1])" }
    if ($p -match '^HKCU:\\(.+)$') { return "HKCU\$($Matches[1])" }
    if ($p -match '^HKU:\\(.+)$') { return "HKU\$($Matches[1])" }
    if ($p -match '^HKCR:\\(.+)$') { return "HKCR\$($Matches[1])" }
    if ($p -match '^HKEY_LOCAL_MACHINE\\') { return $p }
    if ($p -match '^HKEY_CURRENT_USER\\') { return $p }
    if ($p -match '^HKEY_USERS\\') { return $p }
    if ($p -match '^HKLM\\') { return $p }
    if ($p -match '^HKCU\\') { return $p }
    if ($p -match '^HKU\\') { return $p }
    if ($p -match '^HKCR\\') { return $p }

    throw "Unsupported registry path for reg.exe export: $RegistryPath"
}

function Invoke-ExternalCommandSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [string]$Category = 'ExternalCommand',
        [string]$Target = '',
        [switch]$ReadOnly,
        [switch]$AllowFailure
    )

    $quotedArgs = @($Arguments | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
    })
    $commandForLog = ('{0} {1}' -f $FilePath, ($quotedArgs -join ' ')).Trim()

    if ($script:DryRunMode -and -not $ReadOnly) {
        Write-Log -Message "Would run: $commandForLog" -Level 'INFO'
        Add-ReportAction -Category $Category -Action $Description -Target $Target -Status 'WouldRun' -Detail $commandForLog -Data $null
        return [pscustomobject]@{
            ExitCode = $null
            Output = @()
            SkippedDryRun = $true
        }
    }

    try {
        Write-Log -Message "Running: $commandForLog" -Level 'INFO'
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }
        $lines = @($output | ForEach-Object { $_.ToString() })
        foreach ($line in $lines) {
            Write-Log -Message "Output: $line" -Level 'VERBOSE'
        }

        $status = if ($exitCode -eq 0) { 'Done' } else { 'ExitCodeNonZero' }
        Add-ReportAction -Category $Category -Action $Description -Target $Target -Status $status -Detail $commandForLog -Data ([pscustomobject]@{
            ExitCode = $exitCode
            Output = $lines
        })

        if ($exitCode -ne 0 -and -not $AllowFailure) {
            Write-Log -Message "$Description exited with code $exitCode." -Level 'WARN'
        }

        return [pscustomobject]@{
            ExitCode = $exitCode
            Output = $lines
            SkippedDryRun = $false
        }
    } catch {
        $message = "$Description failed. $($_.Exception.Message)"
        if ($AllowFailure) {
            Write-Log -Message $message -Level 'WARN'
            return [pscustomobject]@{
                ExitCode = -1
                Output = @($_.Exception.Message)
                SkippedDryRun = $false
            }
        }

        Write-Log -Message $message -Level 'ERROR'
        Add-ReportAction -Category $Category -Action $Description -Target $Target -Status 'Failed' -Detail $_.Exception.Message -Data $null
        return [pscustomobject]@{
            ExitCode = -1
            Output = @($_.Exception.Message)
            SkippedDryRun = $false
        }
    }
}

function New-SystemRestorePointSafe {
    [CmdletBinding()]
    param()

    if (-not $CreateRestorePoint) {
        Write-Log -Message 'System restore point was not requested.' -Level 'VERBOSE'
        return
    }

    if ($script:DryRunMode) {
        Write-Log -Message 'Would do: Create a System Restore Point' -Level 'INFO'
        Add-ReportAction -Category 'RestorePoint' -Action 'Create a System Restore Point' -Target 'System Restore' -Status 'WouldDo' -Detail 'Dry-run/WhatIf mode; no restore point was created.' -Data $null
        return
    }

    try {
        Write-Log -Message 'Doing: Create a System Restore Point' -Level 'INFO'
        Checkpoint-Computer -Description ("LegitActivationCleaner {0}" -f $script:RunId) -RestorePointType 'MODIFY_SETTINGS'
        Write-Log -Message 'Done: Create a System Restore Point' -Level 'SUCCESS'
        Add-ReportAction -Category 'RestorePoint' -Action 'Create a System Restore Point' -Target 'System Restore' -Status 'Done' -Detail '' -Data $null
    } catch {
        $message = "System Restore Point could not be created: $($_.Exception.Message)"
        Write-Log -Message $message -Level 'WARN'
        Add-ReportAction -Category 'RestorePoint' -Action 'Create a System Restore Point' -Target 'System Restore' -Status 'Skipped' -Detail $_.Exception.Message -Data $null
    }
}

function Export-RegistryKeySafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [string]$Reason = 'Registry backup'
    )

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        Write-Log -Message "Registry key does not exist, backup skipped: $RegistryPath" -Level 'VERBOSE'
        return $null
    }

    $regExePath = ConvertTo-RegExePath -RegistryPath $RegistryPath
    $safeName = ConvertTo-SafeFileName -Name $regExePath
    $destination = Join-Path $script:BackupRoot ("{0}-{1}.reg" -f $safeName, $script:RunId)

    if ($script:DryRunMode) {
        Write-Log -Message "Would export registry key before modification: $regExePath -> $destination" -Level 'INFO'
        Add-ReportAction -Category 'RegistryBackup' -Action $Reason -Target $RegistryPath -Status 'WouldDo' -Detail $destination -Data $null
        return $destination
    }

    $result = Invoke-ExternalCommandSafe -FilePath "$env:SystemRoot\System32\reg.exe" -Arguments @('export', $regExePath, $destination, '/y') -Description "Export registry key: $regExePath" -Category 'RegistryBackup' -Target $RegistryPath -AllowFailure
    if ($result.ExitCode -eq 0) {
        Write-Log -Message "Registry backup written: $destination" -Level 'SUCCESS'
        return $destination
    }

    Write-Log -Message "Registry backup failed for $RegistryPath. The related modification will be skipped." -Level 'WARN'
    return $null
}

function Remove-RegistryValuesSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyPath,

        [Parameter(Mandatory = $true)]
        [string[]]$ValueNames,

        [string]$Category = 'Registry'
    )

    if (-not (Test-Path -LiteralPath $KeyPath)) {
        Write-Log -Message "Registry key not found: $KeyPath" -Level 'VERBOSE'
        return
    }

    $existing = New-Object System.Collections.ArrayList
    foreach ($name in $ValueNames) {
        try {
            $property = Get-ItemProperty -LiteralPath $KeyPath -Name $name -ErrorAction Stop
            if ($null -ne $property) {
                $null = $existing.Add($name)
            }
        } catch {
            Write-Log -Message "Registry value not present: $KeyPath\$name" -Level 'VERBOSE'
        }
    }

    if ($existing.Count -eq 0) {
        Write-Log -Message "No targeted registry values found under $KeyPath" -Level 'INFO'
        return
    }

    $backup = Export-RegistryKeySafe -RegistryPath $KeyPath -Reason 'Backup before removing KMS-related values'
    if (-not $script:DryRunMode -and -not $backup) {
        Write-Log -Message "Skipping registry value cleanup because backup failed: $KeyPath" -Level 'WARN'
        return
    }

    foreach ($name in $existing) {
        $localName = [string]$name
        $data = [pscustomobject]@{
            KeyPath = $KeyPath
            ValueName = $localName
            Backup = $backup
        }
        Invoke-SafeAction -Description "Remove registry value $KeyPath\$localName" -Category $Category -Target "$KeyPath\$localName" -Data $data -Action {
            Remove-ItemProperty -LiteralPath $KeyPath -Name $localName -ErrorAction Stop
        } | Out-Null

        Add-ReportListItem -ListName 'RegistryValuesRemoved' -Item ([pscustomobject]@{
            KeyPath = $KeyPath
            ValueName = $localName
            Backup = $backup
            Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'Removed' }
        })
    }
}

function Remove-RegistryKeySafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyPath,

        [string]$Reason = 'Remove registry key'
    )

    if (-not (Test-Path -LiteralPath $KeyPath)) {
        Write-Log -Message "Registry key not found: $KeyPath" -Level 'VERBOSE'
        return
    }

    $backup = Export-RegistryKeySafe -RegistryPath $KeyPath -Reason "Backup before: $Reason"
    if (-not $script:DryRunMode -and -not $backup) {
        Write-Log -Message "Skipping registry key removal because backup failed: $KeyPath" -Level 'WARN'
        return
    }

    Invoke-SafeAction -Description ('{0}: {1}' -f $Reason, $KeyPath) -Category 'Registry' -Target $KeyPath -Data ([pscustomobject]@{
        KeyPath = $KeyPath
        Backup = $backup
    }) -Action {
        Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction Stop
    } | Out-Null

    Add-ReportListItem -ListName 'RegistryKeysRemoved' -Item ([pscustomobject]@{
        KeyPath = $KeyPath
        Backup = $backup
        Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'Removed' }
    })
}

function Get-CimOrWmiObjectSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClassName,

        [string]$Filter = $null
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Filter)) {
            return @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop)
        }
        return @(Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction Stop)
    } catch {
        Write-Log -Message "CIM query failed for $ClassName; trying WMI fallback. $($_.Exception.Message)" -Level 'VERBOSE'
    }

    try {
        if ([string]::IsNullOrWhiteSpace($Filter)) {
            return @(Get-WmiObject -Class $ClassName -ErrorAction Stop)
        }
        return @(Get-WmiObject -Class $ClassName -Filter $Filter -ErrorAction Stop)
    } catch {
        Write-Log -Message ("WMI fallback failed for {0}: {1}" -f $ClassName, $_.Exception.Message) -Level 'WARN'
        return @()
    }
}

function Get-WindowsOSInfo {
    [CmdletBinding()]
    param()

    $info = [ordered]@{
        ComputerName = $env:COMPUTERNAME
        UserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }

    try {
        $os = @(Get-CimOrWmiObjectSafe -ClassName Win32_OperatingSystem) | Select-Object -First 1
        if ($os) {
            $info.Caption = $os.Caption
            $info.Version = $os.Version
            $info.BuildNumber = $os.BuildNumber
            $info.OSArchitecture = $os.OSArchitecture
        }
    } catch {
        Write-Log -Message "Unable to read Win32_OperatingSystem: $($_.Exception.Message)" -Level 'WARN'
    }

    try {
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $info.ProductName = $cv.ProductName
        $info.EditionID = $cv.EditionID
        if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') {
            $info.DisplayVersion = $cv.DisplayVersion
        }
        if ($cv.PSObject.Properties.Name -contains 'ReleaseId') {
            $info.ReleaseId = $cv.ReleaseId
        }
    } catch {
        Write-Log -Message "Unable to read Windows CurrentVersion registry: $($_.Exception.Message)" -Level 'WARN'
    }

    return $info
}

function Get-WindowsActivationState {
    [CmdletBinding()]
    param()

    $statusMap = @{
        0 = 'Unlicensed'
        1 = 'Licensed'
        2 = 'OOB Grace'
        3 = 'OOT Grace'
        4 = 'Non-Genuine Grace'
        5 = 'Notification'
        6 = 'Extended Grace'
    }

    $items = @()
    try {
        $windowsAppId = '55c92734-d682-4d71-983e-d6ec3f16059f'
        $products = @(Get-CimOrWmiObjectSafe -ClassName SoftwareLicensingProduct -Filter "ApplicationID='$windowsAppId' AND PartialProductKey IS NOT NULL")
        foreach ($product in $products) {
            $channel = $null
            if ($product.PSObject.Properties.Name -contains 'ProductKeyChannel') {
                $channel = $product.ProductKeyChannel
            }
            $items += [pscustomobject]@{
                ActivationID = $product.ID
                ApplicationID = $product.ApplicationID
                Name = $product.Name
                Description = $product.Description
                LicenseStatus = $product.LicenseStatus
                LicenseStatusText = if ($statusMap.ContainsKey([int]$product.LicenseStatus)) { $statusMap[[int]$product.LicenseStatus] } else { 'Unknown' }
                PartialProductKey = $product.PartialProductKey
                ProductKeyChannel = $channel
                GracePeriodRemaining = $product.GracePeriodRemaining
            }
        }
    } catch {
        Write-Log -Message "Unable to read Windows activation state: $($_.Exception.Message)" -Level 'WARN'
    }

    return @($items)
}

function Test-WindowsActivationLooksKms {
    [CmdletBinding()]
    param(
        [object[]]$ActivationState
    )

    foreach ($item in @($ActivationState)) {
        $text = '{0} {1} {2}' -f $item.Name, $item.Description, $item.ProductKeyChannel
        if ($text -match '(?i)\bKMS\b|VOLUME_KMSCLIENT|GVLK|Volume:GVLK') {
            return $true
        }
    }
    return $false
}

function Get-TaskActionText {
    [CmdletBinding()]
    param(
        [object]$Task
    )

    $parts = @()
    foreach ($action in @($Task.Actions)) {
        $execute = $null
        $arguments = $null
        if ($action.PSObject.Properties.Name -contains 'Execute') { $execute = $action.Execute }
        if ($action.PSObject.Properties.Name -contains 'Arguments') { $arguments = $action.Arguments }
        $parts += ('{0} {1}' -f $execute, $arguments).Trim()
    }
    return ($parts -join ' ; ')
}

function Get-ScheduledTaskCandidatesViaCom {
    [CmdletBinding()]
    param(
        [string[]]$ExactNames,
        [string[]]$Keywords
    )

    $candidates = @()

    function Get-ComTaskActionText {
        param([string]$XmlText)
        try {
            [xml]$xml = $XmlText
            $parts = @()
            foreach ($exec in @($xml.Task.Actions.Exec)) {
                $parts += ('{0} {1}' -f $exec.Command, $exec.Arguments).Trim()
            }
            return ($parts -join ' ; ')
        } catch {
            return ''
        }
    }

    function Walk-ComTaskFolder {
        param(
            [object]$Folder,
            [string]$FolderPath
        )

        foreach ($task in @($Folder.GetTasks(0))) {
            $taskName = [string]$task.Name
            $taskPath = [string]$FolderPath
            if (-not $taskPath.EndsWith('\')) {
                $taskPath += '\'
            }
            $xmlText = [string]$task.Xml
            $actionText = Get-ComTaskActionText -XmlText $xmlText
            $combined = ('{0} {1} {2} {3}' -f $taskPath, $taskName, $actionText, $xmlText)
            $matches = @()

            if ($ExactNames -contains $taskName) {
                $matches += "ExactName:$taskName"
            }

            foreach ($keyword in $Keywords) {
                if ($combined.IndexOf($keyword, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $matches += "Keyword:$keyword"
                }
            }

            if ($matches.Count -gt 0) {
                $script:candidates += [pscustomobject]@{
                    TaskName = $taskName
                    TaskPath = $taskPath
                    Actions = $actionText
                    Match = ($matches | Select-Object -Unique) -join ', '
                    Source = 'ScheduleServiceCom'
                    Xml = $xmlText
                }
            }
        }

        foreach ($child in @($Folder.GetFolders(0))) {
            Walk-ComTaskFolder -Folder $child -FolderPath $child.Path
        }
    }

    try {
        $script:candidates = @()
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        Walk-ComTaskFolder -Folder ($service.GetFolder('\')) -FolderPath '\'
        $candidates = @($script:candidates)
        Remove-Variable -Name candidates -Scope Script -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Scheduled Task COM fallback failed: $($_.Exception.Message)" -Level 'WARN'
    }

    return @($candidates)
}

function Get-MASScheduledTaskCandidates {
    [CmdletBinding()]
    param()

    $exactNames = @(
        'Activation-Renewal',
        'Activation-Run_Once',
        'Online_KMS_Activation_Script-Renewal',
        'Online_KMS_Activation_Script-Run_Once'
    )
    $keywords = @(
        'Activation-Renewal',
        'Online_KMS_Activation',
        'R@1n-KMS',
        'AutoKMS',
        'KMSAuto',
        'KMS_VL_ALL'
    )

    $candidates = @()
    try {
        if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            throw 'Get-ScheduledTask is not available on this Windows edition/version.'
        }
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $tasks) {
            $taskName = [string]$task.TaskName
            $taskPath = [string]$task.TaskPath
            $actionText = Get-TaskActionText -Task $task
            $combined = ('{0} {1} {2}' -f $taskPath, $taskName, $actionText)
            $matches = @()

            if ($exactNames -contains $taskName) {
                $matches += "ExactName:$taskName"
            }

            foreach ($keyword in $keywords) {
                if ($combined.IndexOf($keyword, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $matches += "Keyword:$keyword"
                }
            }

            if ($matches.Count -gt 0) {
                $candidates += [pscustomobject]@{
                    TaskName = $taskName
                    TaskPath = $taskPath
                    Actions = $actionText
                    Match = ($matches | Select-Object -Unique) -join ', '
                    Source = 'ScheduledTasksModule'
                    TaskObject = $task
                }
            }
        }
    } catch {
        Write-Log -Message "Unable to enumerate Scheduled Tasks with module; trying COM fallback. $($_.Exception.Message)" -Level 'VERBOSE'
        $candidates = @(Get-ScheduledTaskCandidatesViaCom -ExactNames $exactNames -Keywords $keywords)
    }

    return @($candidates)
}

function Export-ScheduledTaskXmlSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [string]$TaskPath
    )

    $backupDir = Join-Path $script:BackupRoot 'ScheduledTasks'
    if ($script:DryRunMode) {
        Write-Log -Message "Would export Scheduled Task XML before removal: $TaskPath$TaskName" -Level 'INFO'
        return $backupDir
    }

    try {
        if (-not (Test-Path -LiteralPath $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }
        $safeName = ConvertTo-SafeFileName -Name ("{0}{1}" -f $TaskPath, $TaskName)
        $destination = Join-Path $backupDir ("{0}.xml" -f $safeName)
        $xml = Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
        Set-Content -LiteralPath $destination -Value $xml -Encoding Unicode -Force
        Write-Log -Message "Scheduled Task backup written: $destination" -Level 'SUCCESS'
        return $destination
    } catch {
        Write-Log -Message "Failed to export Scheduled Task $TaskPath$TaskName. $($_.Exception.Message)" -Level 'WARN'
        return $null
    }
}

function Export-ScheduledTaskXmlFromTextSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [string]$TaskPath,

        [Parameter(Mandatory = $true)]
        [string]$XmlText
    )

    $backupDir = Join-Path $script:BackupRoot 'ScheduledTasks'
    if ($script:DryRunMode) {
        Write-Log -Message "Would export Scheduled Task XML before removal: $TaskPath$TaskName" -Level 'INFO'
        return $backupDir
    }

    try {
        if (-not (Test-Path -LiteralPath $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }
        $safeName = ConvertTo-SafeFileName -Name ("{0}{1}" -f $TaskPath, $TaskName)
        $destination = Join-Path $backupDir ("{0}.xml" -f $safeName)
        Set-Content -LiteralPath $destination -Value $XmlText -Encoding Unicode -Force
        Write-Log -Message "Scheduled Task backup written: $destination" -Level 'SUCCESS'
        return $destination
    } catch {
        Write-Log -Message "Failed to write Scheduled Task XML backup for $TaskPath$TaskName. $($_.Exception.Message)" -Level 'WARN'
        return $null
    }
}

function Remove-ScheduledTasksRelatedToMAS {
    [CmdletBinding()]
    param(
        [object[]]$Candidates = $script:DetectedScheduledTasks
    )

    if (-not $Candidates -or $Candidates.Count -eq 0) {
        Write-Log -Message 'No Scheduled Tasks with clear MAS/KMS indicators were found.' -Level 'INFO'
        return
    }

    foreach ($candidate in @($Candidates)) {
        $taskName = [string]$candidate.TaskName
        $taskPath = [string]$candidate.TaskPath
        $taskTarget = '{0}{1}' -f $taskPath, $taskName
        if (($candidate.PSObject.Properties.Name -contains 'Xml') -and $candidate.Xml) {
            $backup = Export-ScheduledTaskXmlFromTextSafe -TaskName $taskName -TaskPath $taskPath -XmlText ([string]$candidate.Xml)
        } else {
            $backup = Export-ScheduledTaskXmlSafe -TaskName $taskName -TaskPath $taskPath
        }
        if (-not $script:DryRunMode -and -not $backup) {
            Write-Log -Message "Skipping task removal because XML backup failed: $taskTarget" -Level 'WARN'
            continue
        }

        $data = [pscustomobject]@{
            TaskName = $taskName
            TaskPath = $taskPath
            Actions = $candidate.Actions
            Match = $candidate.Match
            Backup = $backup
        }

        if (($candidate.PSObject.Properties.Name -contains 'Source') -and $candidate.Source -eq 'ScheduleServiceCom') {
            $schtasks = Join-Path $env:SystemRoot 'System32\schtasks.exe'
            Invoke-ExternalCommandSafe -FilePath $schtasks -Arguments @('/Delete', '/TN', $taskTarget, '/F') -Description "Remove Scheduled Task $taskTarget" -Category 'ScheduledTask' -Target $taskTarget -AllowFailure | Out-Null
        } else {
            Invoke-SafeAction -Description "Remove Scheduled Task $taskTarget" -Category 'ScheduledTask' -Target $taskTarget -Data $data -Action {
                Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
            } | Out-Null
        }

        Add-ReportListItem -ListName 'ScheduledTasksRemoved' -Item ([pscustomobject]@{
            TaskName = $taskName
            TaskPath = $taskPath
            Actions = $candidate.Actions
            Match = $candidate.Match
            Backup = $backup
            Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'Removed' }
        })
    }
}

function Remove-RunEntriesRelatedToMAS {
    [CmdletBinding()]
    param()

    $registryKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($sid in @(Get-LoadedUserSids)) {
        $registryKeys += @(
            "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run",
            "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
    }

    foreach ($keyPath in ($registryKeys | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $keyPath)) {
            Write-Log -Message "Startup registry key not found: $keyPath" -Level 'VERBOSE'
            continue
        }

        try {
            $item = Get-ItemProperty -LiteralPath $keyPath -ErrorAction Stop
            $properties = @($item.PSObject.Properties | Where-Object {
                $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$'
            })
        } catch {
            Write-Log -Message ("Unable to read startup registry key {0}: {1}" -f $keyPath, $_.Exception.Message) -Level 'WARN'
            continue
        }

        foreach ($property in $properties) {
            $valueName = [string]$property.Name
            $valueData = [string]$property.Value
            $match = Test-MASPersistenceText -Text ("$valueName $valueData")
            if (-not $match.IsMatch) {
                continue
            }

            $backup = Export-RegistryKeySafe -RegistryPath $keyPath -Reason 'Backup before removing MAS/KMS startup registry value'
            if (-not $script:DryRunMode -and -not $backup) {
                Write-Log -Message "Skipping startup registry value removal because backup failed: $keyPath\$valueName" -Level 'WARN'
                continue
            }

            Invoke-SafeAction -Description "Remove MAS/KMS startup registry value $keyPath\$valueName" -Category 'StartupRegistry' -Target "$keyPath\$valueName" -Data ([pscustomobject]@{
                KeyPath = $keyPath
                ValueName = $valueName
                ValueData = $valueData
                Match = $match.Reason
                Backup = $backup
            }) -Action {
                Remove-ItemProperty -LiteralPath $keyPath -Name $valueName -ErrorAction Stop
            } | Out-Null

            Add-ReportListItem -ListName 'RegistryValuesRemoved' -Item ([pscustomobject]@{
                KeyPath = $keyPath
                ValueName = $valueName
                ValueData = $valueData
                Reason = $match.Reason
                Backup = $backup
                Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'Removed' }
            })
        }
    }
}

function Get-ShortcutDescriptionSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([IO.Path]::GetExtension($Path) -ine '.lnk') {
        return ''
    }

    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($Path)
        return ('{0} {1} {2}' -f $shortcut.TargetPath, $shortcut.Arguments, $shortcut.Description)
    } catch {
        Write-Log -Message "Unable to inspect shortcut target: $Path. $($_.Exception.Message)" -Level 'VERBOSE'
        return ''
    }
}

function Remove-StartupFolderItemsRelatedToMAS {
    [CmdletBinding()]
    param()

    $folders = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    )

    foreach ($profile in @(Get-UserProfilesSafe)) {
        if ($profile.LocalPath) {
            $folders += (Join-Path ([string]$profile.LocalPath) 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
        }
    }

    foreach ($folder in ($folders | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $folder)) {
            Write-Log -Message "Startup folder not found: $folder" -Level 'VERBOSE'
            continue
        }

        try {
            $items = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop)
        } catch {
            Write-Log -Message ("Unable to enumerate startup folder {0}: {1}" -f $folder, $_.Exception.Message) -Level 'WARN'
            continue
        }

        foreach ($item in $items) {
            if ($item.Name.IndexOf('.LegitActivationCleaner.', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                continue
            }

            $shortcutText = Get-ShortcutDescriptionSafe -Path $item.FullName
            $match = Test-MASPersistenceText -Text ("$($item.Name) $($item.FullName) $shortcutText")
            if (-not $match.IsMatch) {
                continue
            }

            if ($Force) {
                Invoke-SafeAction -Description "Remove MAS/KMS startup folder item $($item.FullName)" -Category 'StartupFolder' -Target $item.FullName -Data ([pscustomobject]@{
                    Path = $item.FullName
                    Match = $match.Reason
                }) -Action {
                    Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
                } | Out-Null

                Add-ReportListItem -ListName 'FilesRemovedOrRenamed' -Item ([pscustomobject]@{
                    Path = $item.FullName
                    Operation = 'Remove'
                    ItemType = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                    Reason = $match.Reason
                    Confidence = 'StartupFolderPersistence'
                    Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'Removed' }
                })
            } else {
                $destination = Rename-PathToBackupSafe -Path $item.FullName -Reason $match.Reason -Category 'StartupFolder'
                Add-ReportListItem -ListName 'FilesRemovedOrRenamed' -Item ([pscustomobject]@{
                    Path = $item.FullName
                    Destination = $destination
                    Operation = 'RenameToBak'
                    ItemType = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                    Reason = $match.Reason
                    Confidence = 'StartupFolderPersistence'
                    Mode = if ($script:DryRunMode) { 'WouldRename' } else { 'Renamed' }
                })
            }
        }
    }
}

function Remove-ServicesRelatedToMAS {
    [CmdletBinding()]
    param()

    $services = @(Get-CimOrWmiObjectSafe -ClassName Win32_Service)
    if ($services.Count -eq 0) {
        Write-Log -Message 'No services could be enumerated for MAS/KMS service cleanup.' -Level 'VERBOSE'
        return
    }

    foreach ($service in $services) {
        $combined = ('{0} {1} {2}' -f $service.Name, $service.DisplayName, $service.PathName)
        $match = Test-MASPersistenceText -Text $combined
        if (-not $match.IsMatch) {
            continue
        }

        $serviceName = [string]$service.Name
        $serviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        $backup = $null
        if (Test-Path -LiteralPath $serviceRegPath) {
            $backup = Export-RegistryKeySafe -RegistryPath $serviceRegPath -Reason 'Backup before removing MAS/KMS service'
            if (-not $script:DryRunMode -and -not $backup) {
                Write-Log -Message "Skipping service removal because backup failed: $serviceName" -Level 'WARN'
                continue
            }
        }

        if ($service.State -eq 'Running') {
            Invoke-SafeAction -Description "Stop MAS/KMS service $serviceName" -Category 'ServicePersistence' -Target $serviceName -Data $service -Action {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
            } | Out-Null
        }

        $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
        Invoke-ExternalCommandSafe -FilePath $sc -Arguments @('delete', $serviceName) -Description "Delete MAS/KMS service $serviceName" -Category 'ServicePersistence' -Target $serviceName -AllowFailure | Out-Null

        Add-ReportListItem -ListName 'RegistryKeysRemoved' -Item ([pscustomobject]@{
            KeyPath = $serviceRegPath
            ServiceName = $serviceName
            DisplayName = $service.DisplayName
            PathName = $service.PathName
            Reason = $match.Reason
            Backup = $backup
            Mode = if ($script:DryRunMode) { 'WouldDeleteService' } else { 'DeleteServiceAttempted' }
        })
    }
}

function Test-IsUnderPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    if ([string]::IsNullOrWhiteSpace($Root)) {
        return $false
    }

    try {
        $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
        return $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Test-MASArtifactName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $highConfidence = @(
        'AutoKMS',
        'KMSAuto',
        'KMS_VL_ALL',
        'Activation-Renewal',
        'Online_KMS_Activation',
        'Online_KMS_Activation_Script',
        'R@1n-KMS'
    )

    foreach ($keyword in $highConfidence) {
        if ($Name.IndexOf($keyword, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return [pscustomobject]@{
                IsMatch = $true
                Confidence = 'High'
                Reason = "Name contains $keyword"
            }
        }
    }

    if ($Name -match '(?i)(^|[._\-\s])MAS([._\-\s]|$)') {
        return [pscustomobject]@{
            IsMatch = $true
            Confidence = 'Medium'
            Reason = 'Name contains standalone MAS token'
        }
    }

    return [pscustomobject]@{
        IsMatch = $false
        Confidence = 'None'
        Reason = ''
    }
}

function Test-MASPersistenceText {
    [CmdletBinding()]
    param(
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return [pscustomobject]@{ IsMatch = $false; Reason = '' }
    }

    $keywords = @(
        'Activation-Renewal',
        'Online_KMS_Activation',
        'Online_KMS_Activation_Script',
        'R@1n-KMS',
        'AutoKMS',
        'KMSAuto',
        'KMS_VL_ALL'
    )

    foreach ($keyword in $keywords) {
        if ($Text.IndexOf($keyword, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return [pscustomobject]@{ IsMatch = $true; Reason = "Contains $keyword" }
        }
    }

    return [pscustomobject]@{ IsMatch = $false; Reason = '' }
}

function Test-IsSafeActivationArtifactDeletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $full = [IO.Path]::GetFullPath($Path)
    } catch {
        return $false
    }

    $blockedFragments = @(
        '\Windows\System32\winevt\Logs',
        '\Windows\Prefetch',
        '\Windows\AppCompat',
        '\Windows\System32\sru',
        '\Windows\System32\config',
        '\ProgramData\Microsoft\Windows Defender\Scans\History'
    )
    foreach ($fragment in $blockedFragments) {
        if ($full.IndexOf($fragment, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $false
        }
    }

    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $publicDesktop = Join-Path $env:PUBLIC 'Desktop'
    $windowsTemp = Join-Path $env:SystemRoot 'Temp'
    $allowedRoots = @(
        $env:ProgramData,
        $env:ProgramFiles,
        $programFilesX86,
        $windowsTemp,
        $publicDesktop
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($root in $allowedRoots) {
        if (Test-IsUnderPath -Path $full -Root $root) {
            return $true
        }
    }

    $allowedExactWindowsPaths = @(
        (Join-Path $env:SystemRoot 'Online_KMS_Activation_Script')
    )
    foreach ($exact in $allowedExactWindowsPaths) {
        if ($full.TrimEnd('\').Equals(([IO.Path]::GetFullPath($exact)).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Add-MASFileCandidate {
    [CmdletBinding()]
    param(
        [System.Collections.ArrayList]$List,
        [string]$Path,
        [string]$Reason,
        [string]$Confidence
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Name.IndexOf('.LegitActivationCleaner.', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Write-Log -Message "Skipping prior LegitActivationCleaner backup artifact: $Path" -Level 'VERBOSE'
        return
    }
    if (-not (Test-IsSafeActivationArtifactDeletion -Path $Path)) {
        Write-Log -Message "Detected possible artifact outside safe cleanup scope; skipped: $Path" -Level 'WARN'
        Add-ReportListItem -ListName 'Skipped' -Item ([pscustomobject]@{
            Category = 'FileArtifact'
            Target = $Path
            Reason = 'Outside safe cleanup scope'
        })
        return
    }

    $already = $false
    foreach ($existing in $List) {
        if ([string]::Equals($existing.Path, $item.FullName, [StringComparison]::OrdinalIgnoreCase)) {
            $already = $true
            break
        }
    }
    if (-not $already) {
        $null = $List.Add([pscustomobject]@{
            Path = $item.FullName
            Name = $item.Name
            ItemType = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
            Reason = $Reason
            Confidence = $Confidence
        })
    }
}

function Get-MASFileCandidates {
    [CmdletBinding()]
    param()

    $candidates = New-Object System.Collections.ArrayList
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $publicDesktop = Join-Path $env:PUBLIC 'Desktop'
    $windowsTemp = Join-Path $env:SystemRoot 'Temp'

    $specificPaths = @(
        (Join-Path $env:ProgramFiles 'Activation-Renewal'),
        (Join-Path $env:ProgramData 'Activation-Renewal'),
        (Join-Path $env:ProgramData 'Online_KMS_Activation'),
        (Join-Path $env:ProgramData 'Online_KMS_Activation.cmd'),
        (Join-Path $env:SystemRoot 'Online_KMS_Activation_Script')
    )
    foreach ($path in $specificPaths) {
        Add-MASFileCandidate -List $candidates -Path $path -Reason 'Known MAS/KMS artifact path' -Confidence 'High'
    }

    $scanRoots = @(
        $env:ProgramData,
        $env:ProgramFiles,
        $programFilesX86,
        $windowsTemp,
        $publicDesktop
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }

    foreach ($root in $scanRoots) {
        try {
            $children = Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop
            foreach ($child in $children) {
                $match = Test-MASArtifactName -Name $child.Name
                if ($match.IsMatch) {
                    if ($root.Equals($publicDesktop, [StringComparison]::OrdinalIgnoreCase)) {
                        $allowedShortcutExtensions = @('.lnk', '.cmd', '.bat', '.ps1', '.url')
                        if (-not $child.PSIsContainer -and ($allowedShortcutExtensions -notcontains $child.Extension)) {
                            continue
                        }
                    }
                    Add-MASFileCandidate -List $candidates -Path $child.FullName -Reason $match.Reason -Confidence $match.Confidence
                }
            }
        } catch {
            Write-Log -Message "Unable to scan $root for activation artifacts: $($_.Exception.Message)" -Level 'WARN'
        }
    }

    return @($candidates)
}

function Remove-MASFilesAndFolders {
    [CmdletBinding()]
    param(
        [object[]]$Candidates = $script:DetectedMASFileArtifacts
    )

    if (-not $Candidates -or $Candidates.Count -eq 0) {
        Write-Log -Message 'No high-confidence MAS/KMS files or folders were found in scoped locations.' -Level 'INFO'
        return
    }

    foreach ($candidate in @($Candidates)) {
        if ($candidate.Confidence -ne 'High' -and -not $Force) {
            Write-Log -Message "Skipping medium-confidence artifact without -Force: $($candidate.Path)" -Level 'WARN'
            Add-ReportListItem -ListName 'Skipped' -Item ([pscustomobject]@{
                Category = 'FileArtifact'
                Target = $candidate.Path
                Reason = 'Medium-confidence match; rerun with -Force to remove'
            })
            continue
        }

        if (-not (Test-IsSafeActivationArtifactDeletion -Path $candidate.Path)) {
            Write-Log -Message "Unsafe file cleanup target blocked: $($candidate.Path)" -Level 'WARN'
            continue
        }

        $data = [pscustomobject]@{
            Path = $candidate.Path
            ItemType = $candidate.ItemType
            Reason = $candidate.Reason
            Confidence = $candidate.Confidence
        }

        if ($Force) {
            Invoke-SafeAction -Description "Remove activation artifact $($candidate.Path)" -Category 'FileArtifact' -Target $candidate.Path -Data $data -Action {
                Remove-Item -LiteralPath $candidate.Path -Recurse -Force -ErrorAction Stop
            } | Out-Null

            Add-ReportListItem -ListName 'FilesRemovedOrRenamed' -Item ([pscustomobject]@{
                Path = $candidate.Path
                Operation = 'Remove'
                ItemType = $candidate.ItemType
                Reason = $candidate.Reason
                Confidence = $candidate.Confidence
                Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'Removed' }
            })
        } else {
            $destination = Rename-PathToBackupSafe -Path $candidate.Path -Reason $candidate.Reason -Category 'FileArtifact'
            Add-ReportListItem -ListName 'FilesRemovedOrRenamed' -Item ([pscustomobject]@{
                Path = $candidate.Path
                Destination = $destination
                Operation = 'RenameToBak'
                ItemType = $candidate.ItemType
                Reason = $candidate.Reason
                Confidence = $candidate.Confidence
                Mode = if ($script:DryRunMode) { 'WouldRename' } else { 'Renamed' }
            })
        }
    }
}

function Clear-WindowsKMSConfiguration {
    [CmdletBinding()]
    param()

    $rootKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
    $valueNames = @(
        'KeyManagementServiceName',
        'KeyManagementServicePort',
        'DisableDnsPublishing',
        'DisableKeyManagementServiceHostCaching'
    )

    $keyPaths = @($rootKeyPath)
    if (Test-Path -LiteralPath $rootKeyPath) {
        try {
            $keyPaths += @(Get-ChildItem -LiteralPath $rootKeyPath -ErrorAction Stop | ForEach-Object {
                Join-Path $rootKeyPath $_.PSChildName
            })
        } catch {
            Write-Log -Message "Unable to enumerate SoftwareProtectionPlatform subkeys: $($_.Exception.Message)" -Level 'WARN'
        }
    }

    foreach ($keyPath in ($keyPaths | Select-Object -Unique)) {
        Remove-RegistryValuesSafe -KeyPath $keyPath -ValueNames $valueNames -Category 'WindowsKMSRegistry'
    }
}

function Clear-WindowsLastProductKeyError {
    [CmdletBinding()]
    param()

    $keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
    $valueNames = @(
        'LastProductKeyPid',
        'LastProductKeyError',
        'LastProductKey',
        'LastProductKeyType'
    )

    Remove-RegistryValuesSafe -KeyPath $keyPath -ValueNames $valueNames -Category 'WindowsActivationUiState'
}

function Clear-OfficeKMSConfiguration {
    [CmdletBinding()]
    param()

    $valueNames = @(
        'KeyManagementServiceName',
        'KeyManagementServicePort',
        'DisableDnsPublishing',
        'DisableKeyManagementServiceHostCaching'
    )

    $keyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OfficeSoftwareProtectionPlatform'
    )

    foreach ($keyPath in $keyPaths) {
        Remove-RegistryValuesSafe -KeyPath $keyPath -ValueNames $valueNames -Category 'OfficeKMSRegistry'
    }
}

function Remove-StaleWindowsESUProductKeys {
    [CmdletBinding()]
    param(
        [object[]]$ActivationStateBefore,
        [string]$SlmgrPath,
        [string]$CscriptPath
    )

    $staleEsuProducts = @($ActivationStateBefore | Where-Object {
        $_.ActivationID -and
        $_.PartialProductKey -and
        ([int]$_.LicenseStatus -ne 1) -and
        (('{0} {1}' -f $_.Name, $_.Description) -match '(?i)\bESU\b|Client-ESU')
    })

    if ($staleEsuProducts.Count -eq 0) {
        Write-Log -Message 'No stale unlicensed Windows ESU add-on product keys were found.' -Level 'INFO'
        return
    }

    foreach ($product in $staleEsuProducts) {
        $activationId = [string]$product.ActivationID
        $lastFive = [string]$product.PartialProductKey
        Invoke-ExternalCommandSafe -FilePath $CscriptPath -Arguments @('//NoLogo', $SlmgrPath, '/upk', $activationId) -Description "Uninstall stale Windows ESU add-on key ending $lastFive" -Category 'WindowsLicensing' -Target "slmgr /upk $activationId" -AllowFailure | Out-Null
        Add-ReportListItem -ListName 'WindowsKeysRemoved' -Item ([pscustomobject]@{
            ActivationID = $activationId
            Name = $product.Name
            Description = $product.Description
            LastFive = $lastFive
            LicenseStatus = $product.LicenseStatus
            ProductKeyChannel = $product.ProductKeyChannel
            Reason = 'Unlicensed Windows ESU add-on key'
            Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'RemoveAttempted' }
        })
    }
}

function Clear-WindowsProductKey {
    [CmdletBinding()]
    param(
        [object[]]$ActivationStateBefore
    )

    $slmgr = Join-Path $env:SystemRoot 'System32\slmgr.vbs'
    $cscript = Join-Path $env:SystemRoot 'System32\cscript.exe'
    if (-not (Test-Path -LiteralPath $slmgr)) {
        Write-Log -Message "slmgr.vbs not found: $slmgr" -Level 'WARN'
        return
    }

    $backupFailures = 0
    foreach ($keyPath in @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    )) {
        if (Test-Path -LiteralPath $keyPath) {
            $backup = Export-RegistryKeySafe -RegistryPath $keyPath -Reason 'Backup before slmgr product-key cleanup'
            if (-not $script:DryRunMode -and -not $backup) {
                $backupFailures++
            }
        }
    }
    if ($backupFailures -gt 0) {
        Write-Log -Message 'Skipping slmgr product-key cleanup because one or more registry backups failed.' -Level 'WARN'
        return
    }

    Remove-StaleWindowsESUProductKeys -ActivationStateBefore $ActivationStateBefore -SlmgrPath $slmgr -CscriptPath $cscript

    $looksKms = Test-WindowsActivationLooksKms -ActivationState $ActivationStateBefore
    if ($looksKms -or $Force -or $ForceWindowsProductKeyRemoval) {
        if (-not $script:DryRunMode) {
            Write-Log -Message 'Warning before Windows key removal: slmgr /upk will uninstall the installed Windows product key from the local licensing store. A valid digital license is not removed, but Windows may require activation refresh or a valid key afterward.' -Level 'WARN'
        }
        Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $slmgr, '/upk') -Description 'Uninstall Windows product key with slmgr /upk' -Category 'WindowsLicensing' -Target 'slmgr /upk' -AllowFailure | Out-Null
    } else {
        Write-Log -Message 'Windows activation does not clearly look like KMS/GVLK; skipped slmgr /upk. Use -ForceWindowsProductKeyRemoval if the installed key must be removed.' -Level 'INFO'
        Add-ReportListItem -ListName 'Skipped' -Item ([pscustomobject]@{
            Category = 'WindowsLicensing'
            Target = 'slmgr /upk'
            Reason = 'Activation channel did not clearly look like KMS/GVLK'
        })
    }

    Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $slmgr, '/cpky') -Description 'Clear Windows product key from registry with slmgr /cpky' -Category 'WindowsLicensing' -Target 'slmgr /cpky' -AllowFailure | Out-Null
    Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $slmgr, '/ckms') -Description 'Clear Windows KMS host with slmgr /ckms' -Category 'WindowsLicensing' -Target 'slmgr /ckms' -AllowFailure | Out-Null
    Clear-WindowsLastProductKeyError
}

function Find-OfficeOSPP {
    [CmdletBinding()]
    param()

    $programFiles = $env:ProgramFiles
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')

    $paths = @(
        (Join-Path $programFiles 'Microsoft Office\Office14\ospp.vbs'),
        (Join-Path $programFiles 'Microsoft Office\Office15\ospp.vbs'),
        (Join-Path $programFiles 'Microsoft Office\Office16\ospp.vbs'),
        (Join-Path $programFiles 'Microsoft Office\root\Office16\ospp.vbs')
    )

    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $paths += @(
            (Join-Path $programFilesX86 'Microsoft Office\Office14\ospp.vbs'),
            (Join-Path $programFilesX86 'Microsoft Office\Office15\ospp.vbs'),
            (Join-Path $programFilesX86 'Microsoft Office\Office16\ospp.vbs'),
            (Join-Path $programFilesX86 'Microsoft Office\root\Office16\ospp.vbs')
        )
    }

    $found = @()
    foreach ($path in ($paths | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path) {
            $found += (Get-Item -LiteralPath $path -Force).FullName
        }
    }

    return @($found | Select-Object -Unique)
}

function Get-OfficeInstalledKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OSPPPath
    )

    $cscript = Join-Path $env:SystemRoot 'System32\cscript.exe'
    if (-not (Test-Path -LiteralPath $OSPPPath)) {
        Write-Log -Message "ospp.vbs not found: $OSPPPath" -Level 'WARN'
        return @()
    }

    $result = Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $OSPPPath, '/dstatusall') -Description "Read Office license status from $OSPPPath" -Category 'OfficeLicensing' -Target $OSPPPath -ReadOnly -AllowFailure
    $lines = @($result.Output)
    $products = New-Object System.Collections.ArrayList
    $current = [ordered]@{
        OSPPPath = $OSPPPath
        LicenseName = $null
        LicenseDescription = $null
        LicenseStatus = $null
        LastFive = $null
    }

    function Add-CurrentOfficeBlock {
        if ($current.LicenseName -or $current.LicenseDescription -or $current.LicenseStatus -or $current.LastFive) {
            $null = $products.Add([pscustomobject]@{
                OSPPPath = $current.OSPPPath
                LicenseName = $current.LicenseName
                LicenseDescription = $current.LicenseDescription
                LicenseStatus = $current.LicenseStatus
                LastFive = $current.LastFive
            })
            $current.LicenseName = $null
            $current.LicenseDescription = $null
            $current.LicenseStatus = $null
            $current.LastFive = $null
        }
    }

    foreach ($line in $lines) {
        if ($line -match '^\s*LICENSE NAME:\s*(.+)\s*$') {
            Add-CurrentOfficeBlock
            $current.LicenseName = $Matches[1].Trim()
            continue
        }
        if ($line -match '^\s*LICENSE DESCRIPTION:\s*(.+)\s*$') {
            $current.LicenseDescription = $Matches[1].Trim()
            continue
        }
        if ($line -match '^\s*LICENSE STATUS:\s*(.+)\s*$') {
            $current.LicenseStatus = $Matches[1].Trim()
            continue
        }
        if ($line -match '^\s*Last 5 characters of installed product key:\s*([A-Z0-9]{5})\s*$') {
            $current.LastFive = $Matches[1].Trim().ToUpperInvariant()
            continue
        }
    }
    Add-CurrentOfficeBlock

    foreach ($product in $products) {
        Add-ReportListItem -ListName 'OfficeProducts' -Item $product
    }

    return @($products)
}

function Clear-OfficeProductKeys {
    [CmdletBinding()]
    param()

    $osppPaths = @(Find-OfficeOSPP)
    if ($osppPaths.Count -eq 0) {
        Write-Log -Message 'No ospp.vbs installation was found. Office MSI/C2R product key cleanup skipped.' -Level 'INFO'
        Add-ReportListItem -ListName 'Skipped' -Item ([pscustomobject]@{
            Category = 'OfficeLicensing'
            Target = 'ospp.vbs'
            Reason = 'No ospp.vbs found'
        })
        return
    }

    $cscript = Join-Path $env:SystemRoot 'System32\cscript.exe'
    foreach ($osppPath in $osppPaths) {
        $products = @(Get-OfficeInstalledKeys -OSPPPath $osppPath)
        $keys = @($products | Where-Object { $_.LastFive } | Select-Object -ExpandProperty LastFive -Unique)

        if ($keys.Count -gt 0) {
            $backupFailures = 0
            foreach ($keyPath in @(
                'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OfficeSoftwareProtectionPlatform'
            )) {
                if (Test-Path -LiteralPath $keyPath) {
                    $backup = Export-RegistryKeySafe -RegistryPath $keyPath -Reason 'Backup before Office product-key cleanup'
                    if (-not $script:DryRunMode -and -not $backup) {
                        $backupFailures++
                    }
                }
            }
            if ($backupFailures -gt 0) {
                Write-Log -Message "Skipping Office product-key cleanup for $osppPath because one or more registry backups failed." -Level 'WARN'
                continue
            }
        }

        foreach ($lastFive in $keys) {
            Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $osppPath, ("/unpkey:{0}" -f $lastFive)) -Description "Uninstall Office product key ending $lastFive" -Category 'OfficeLicensing' -Target "$osppPath /unpkey:$lastFive" -AllowFailure | Out-Null
            Add-ReportListItem -ListName 'OfficeKeysRemoved' -Item ([pscustomobject]@{
                OSPPPath = $osppPath
                LastFive = $lastFive
                Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'RemoveAttempted' }
            })
        }

        Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $osppPath, '/remhst') -Description "Remove Office KMS host with ospp.vbs /remhst" -Category 'OfficeLicensing' -Target "$osppPath /remhst" -AllowFailure | Out-Null
    }
}

function Test-IsSafeOfficeLicensePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    } catch {
        return $false
    }

    $machineLicense = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'Microsoft\Office\Licenses')).TrimEnd('\')
    if ($full.Equals($machineLicense, [StringComparison]::OrdinalIgnoreCase) -or (Test-IsUnderPath -Path $full -Root $machineLicense)) {
        return $true
    }

    $machineOfficeData = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'Microsoft\Office\Data')).TrimEnd('\')
    if ($full.Equals($machineOfficeData, [StringComparison]::OrdinalIgnoreCase) -or (Test-IsUnderPath -Path $full -Root $machineOfficeData)) {
        return $true
    }

    $usersRoot = Join-Path $env:SystemDrive 'Users'
    if (-not (Test-IsUnderPath -Path $full -Root $usersRoot)) {
        return $false
    }

    $allowedSuffixes = @(
        '\AppData\Local\Microsoft\Office\Licenses',
        '\AppData\Local\Microsoft\Office\16.0\Licensing',
        '\AppData\Local\Microsoft\Office\15.0\Licensing',
        '\AppData\Local\Microsoft\Office\14.0\Licensing',
        '\AppData\Local\Microsoft\Office\12.0\Licensing'
    )
    foreach ($suffix in $allowedSuffixes) {
        if ($full.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase) -or $full.IndexOf($suffix + '\', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }

    return $false
}

function Remove-OfficeLicenseDirectorySafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Reason
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log -Message "Office license cache path not found: $Path" -Level 'VERBOSE'
        return
    }
    if (-not (Test-IsSafeOfficeLicensePath -Path $Path)) {
        Write-Log -Message "Unsafe Office license cache cleanup target blocked: $Path" -Level 'WARN'
        return
    }
    $targetItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $itemType = if ($targetItem.PSIsContainer) { 'Directory' } else { 'File' }

    if ($Force) {
        Invoke-SafeAction -Description "Remove Office license cache: $Path" -Category 'OfficeLicenseCache' -Target $Path -Data ([pscustomobject]@{
            Path = $Path
            Reason = $Reason
        }) -Action {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        } | Out-Null

        Add-ReportListItem -ListName 'FilesRemovedOrRenamed' -Item ([pscustomobject]@{
            Path = $Path
            Operation = 'Remove'
            ItemType = $itemType
            Reason = $Reason
            Confidence = 'TargetedOfficeLicenseCache'
            Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'Removed' }
        })
    } else {
        $destination = Rename-PathToBackupSafe -Path $Path -Reason $Reason -Category 'OfficeLicenseCache'
        Add-ReportListItem -ListName 'FilesRemovedOrRenamed' -Item ([pscustomobject]@{
            Path = $Path
            Destination = $destination
            Operation = 'RenameToBak'
            ItemType = $itemType
            Reason = $Reason
            Confidence = 'TargetedOfficeLicenseCache'
            Mode = if ($script:DryRunMode) { 'WouldRename' } else { 'Renamed' }
        })
    }
}

function Get-UserProfilesSafe {
    [CmdletBinding()]
    param()

    $profiles = @()
    try {
        $profiles = @(Get-CimOrWmiObjectSafe -ClassName Win32_UserProfile |
            Where-Object {
                -not $_.Special -and
                $_.LocalPath -and
                (Test-Path -LiteralPath $_.LocalPath) -and
                $_.LocalPath.StartsWith((Join-Path $env:SystemDrive 'Users'), [StringComparison]::OrdinalIgnoreCase)
            } |
            Select-Object @{Name = 'SID'; Expression = { $_.SID } }, @{Name = 'LocalPath'; Expression = { $_.LocalPath } }, @{Name = 'Loaded'; Expression = { $_.Loaded } })
    } catch {
        Write-Log -Message "Unable to query Win32_UserProfile, falling back to C:\Users directory scan: $($_.Exception.Message)" -Level 'WARN'
    }

    if (-not $profiles -or $profiles.Count -eq 0) {
        $skipNames = @('Default', 'Default User', 'Public', 'All Users')
        $usersRoot = Join-Path $env:SystemDrive 'Users'
        if (Test-Path -LiteralPath $usersRoot) {
            $profiles = @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $skipNames -notcontains $_.Name } |
                Select-Object @{Name = 'SID'; Expression = { $null } }, @{Name = 'LocalPath'; Expression = { $_.FullName } }, @{Name = 'Loaded'; Expression = { $false } })
        }
    }

    return @($profiles)
}

function Get-LoadedUserSids {
    [CmdletBinding()]
    param()

    $sids = @()
    try {
        $sids = @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction Stop |
            ForEach-Object { $_.PSChildName } |
            Where-Object { $_ -match '^S-1-5-21-\d+-\d+-\d+-\d+$' })
    } catch {
        Write-Log -Message "Unable to enumerate loaded HKU hives: $($_.Exception.Message)" -Level 'WARN'
    }
    return @($sids)
}

function Remove-OfficeUserRegistryLicensing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HiveRoot,

        [string]$UserLabel
    )

    $relativePaths = @(
        'Software\Microsoft\Office\16.0\Common\Licensing\Resiliency',
        'Software\Microsoft\Office\16.0\Common\Licensing',
        'Software\Microsoft\Office\15.0\Common\Licensing',
        'Software\Microsoft\Office\14.0\Common\Licensing',
        'Software\Microsoft\Office\12.0\Common\Licensing\Resiliency',
        'Software\Microsoft\Office\12.0\Common\Licensing'
    )

    foreach ($relative in $relativePaths) {
        $keyPath = $HiveRoot.TrimEnd('\') + '\' + $relative
        if (Test-Path -LiteralPath $keyPath) {
            Remove-RegistryKeySafe -KeyPath $keyPath -Reason "Remove Office user licensing registry cache for $UserLabel"
        } else {
            Write-Log -Message "Office user registry licensing key not found: $keyPath" -Level 'VERBOSE'
        }
    }
}

function Remove-OfficeLicenseCaches {
    [CmdletBinding()]
    param()

    $machineWide = Join-Path $env:ProgramData 'Microsoft\Office\Licenses'
    Remove-OfficeLicenseDirectorySafe -Path $machineWide -Reason 'Machine-wide Office license cache'
    Remove-OfficeLicenseDirectorySafe -Path (Join-Path $env:ProgramData 'Microsoft\Office\Data') -Reason 'Machine-wide legacy Office 2007/2010 licensing data cache'

    $profiles = @(Get-UserProfilesSafe)
    foreach ($profile in $profiles) {
        $localPath = [string]$profile.LocalPath
        if ([string]::IsNullOrWhiteSpace($localPath)) {
            continue
        }

        $cachePaths = @(
            (Join-Path $localPath 'AppData\Local\Microsoft\Office\Licenses'),
            (Join-Path $localPath 'AppData\Local\Microsoft\Office\16.0\Licensing'),
            (Join-Path $localPath 'AppData\Local\Microsoft\Office\15.0\Licensing'),
            (Join-Path $localPath 'AppData\Local\Microsoft\Office\14.0\Licensing'),
            (Join-Path $localPath 'AppData\Local\Microsoft\Office\12.0\Licensing')
        )

        foreach ($cachePath in $cachePaths) {
            Remove-OfficeLicenseDirectorySafe -Path $cachePath -Reason "Per-user Office license cache for $localPath"
        }
    }

    $loadedSids = @(Get-LoadedUserSids)
    foreach ($sid in $loadedSids) {
        Remove-OfficeUserRegistryLicensing -HiveRoot "Registry::HKEY_USERS\$sid" -UserLabel $sid
    }

    foreach ($profile in $profiles) {
        $sid = [string]$profile.SID
        $localPath = [string]$profile.LocalPath
        if ([string]::IsNullOrWhiteSpace($sid) -or $loadedSids -contains $sid) {
            continue
        }

        if (-not $Force) {
            Write-Log -Message "User hive is not loaded; registry cleanup skipped without -Force: $localPath ($sid)" -Level 'INFO'
            Add-ReportListItem -ListName 'Skipped' -Item ([pscustomobject]@{
                Category = 'OfficeUserRegistry'
                Target = "$localPath ($sid)"
                Reason = 'User hive not loaded; -Force not specified'
            })
            continue
        }

        $ntUser = Join-Path $localPath 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $ntUser)) {
            Write-Log -Message "NTUSER.DAT not found; user hive cleanup skipped: $localPath" -Level 'WARN'
            continue
        }

        $mountName = 'LAC_TEMP_{0}' -f ($sid -replace '[^A-Za-z0-9_]', '_')
        $reg = Join-Path $env:SystemRoot 'System32\reg.exe'
        $loadResult = Invoke-ExternalCommandSafe -FilePath $reg -Arguments @('load', "HKU\$mountName", $ntUser) -Description "Load user registry hive for Office licensing cleanup: $localPath" -Category 'OfficeUserRegistry' -Target $localPath -AllowFailure

        if ($script:DryRunMode) {
            continue
        }
        if ($loadResult.ExitCode -ne 0) {
            Write-Log -Message "Could not load user hive; cleanup skipped: $localPath" -Level 'WARN'
            continue
        }

        try {
            Remove-OfficeUserRegistryLicensing -HiveRoot "Registry::HKEY_USERS\$mountName" -UserLabel $localPath
        } finally {
            Invoke-ExternalCommandSafe -FilePath $reg -Arguments @('unload', "HKU\$mountName") -Description "Unload user registry hive: $localPath" -Category 'OfficeUserRegistry' -Target $localPath -AllowFailure | Out-Null
        }
    }
}

function Get-FileMetadataSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $hash = $null
    if (-not $item.PSIsContainer) {
        try {
            $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            Write-Log -Message "Unable to hash $($item.FullName): $($_.Exception.Message)" -Level 'WARN'
        }
    }

    $companyName = $null
    $fileVersion = $null
    try {
        $companyName = $item.VersionInfo.CompanyName
        $fileVersion = $item.VersionInfo.FileVersion
    } catch {
        $companyName = $null
        $fileVersion = $null
    }

    $isReparse = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    return [pscustomobject]@{
        Path = $item.FullName
        Name = $item.Name
        Length = if ($item.PSIsContainer) { $null } else { $item.Length }
        SHA256 = $hash
        Attributes = $item.Attributes.ToString()
        IsReparsePoint = [bool]$isReparse
        CompanyName = $companyName
        FileVersion = $fileVersion
        LastWriteTime = $item.LastWriteTime.ToString('o')
    }
}

function Get-OhookDirectories {
    [CmdletBinding()]
    param()

    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $dirs = @(
        (Join-Path $env:ProgramFiles 'Microsoft Office\root\vfs\System'),
        (Join-Path $env:ProgramFiles 'Microsoft Office\root\vfs\SystemX86'),
        (Join-Path $env:ProgramFiles 'Common Files\Microsoft Shared\OfficeSoftwareProtectionPlatform')
    )
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $dirs += @(
            (Join-Path $programFilesX86 'Microsoft Office\root\vfs\System'),
            (Join-Path $programFilesX86 'Microsoft Office\root\vfs\SystemX86'),
            (Join-Path $programFilesX86 'Common Files\Microsoft Shared\OfficeSoftwareProtectionPlatform')
        )
    }
    return @($dirs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Test-IsSafeOhookTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    foreach ($root in Get-OhookDirectories) {
        if ((Test-Path -LiteralPath $root) -and (Test-IsUnderPath -Path $Path -Root $root)) {
            return $true
        }
    }
    return $false
}

function Get-OhookCandidates {
    [CmdletBinding()]
    param()

    $fileNames = @('sppc.dll', 'sppcs.dll', 'OSPPC.DLL')
    $candidates = @()
    foreach ($dir in Get-OhookDirectories) {
        if (-not (Test-Path -LiteralPath $dir)) {
            continue
        }
        foreach ($fileName in $fileNames) {
            $path = Join-Path $dir $fileName
            if (-not (Test-Path -LiteralPath $path)) {
                continue
            }

            $metadata = Get-FileMetadataSafe -Path $path
            $company = [string]$metadata.CompanyName
            $isMicrosoft = ($company -match '(?i)^Microsoft Corporation$')
            $isOfficeVfs = ($dir -match '(?i)\\Microsoft Office\\root\\vfs\\')
            $isSuspicious = $false
            $recommendedAction = 'LogOnly'
            $reason = 'Detected target DLL; no clear Ohook indicator'

            if ($fileName -ieq 'sppcs.dll') {
                $isSuspicious = $true
                if ($metadata.IsReparsePoint) {
                    $recommendedAction = 'RemoveSymlink'
                    $reason = 'sppcs.dll exists as a reparse point/symlink'
                } else {
                    $recommendedAction = if ($Force) { 'Remove' } else { 'RenameToBak' }
                    $reason = 'sppcs.dll exists in Office licensing path; commonly associated with Ohook'
                }
            } elseif ($fileName -ieq 'sppc.dll' -and $isOfficeVfs) {
                if ($metadata.IsReparsePoint -or (($metadata.Length -ne $null) -and [int64]$metadata.Length -lt 65536) -or ($company -and -not $isMicrosoft)) {
                    $isSuspicious = $true
                    $recommendedAction = 'RenameToBak'
                    $reason = 'sppc.dll in Office vfs has reparse point, small size, or non-Microsoft company metadata'
                }
            } elseif ($fileName -ieq 'OSPPC.DLL') {
                if ($metadata.IsReparsePoint -or (($metadata.Length -ne $null) -and [int64]$metadata.Length -lt 65536) -or ($company -and -not $isMicrosoft)) {
                    $isSuspicious = $true
                    $recommendedAction = if ($Force) { 'RenameToBak' } else { 'ReportOnly' }
                    $reason = 'OSPPC.DLL looks unusual; default mode reports only to avoid breaking Office'
                }
            }

            $candidates += [pscustomobject]@{
                Path = $path
                Directory = $dir
                FileName = $fileName
                Metadata = $metadata
                IsSuspicious = $isSuspicious
                RecommendedAction = $recommendedAction
                Reason = $reason
            }
        }
    }
    return @($candidates)
}

function Rename-PathToBackupSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Reason,

        [string]$Category = 'FileArtifact'
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log -Message "File not found for rename: $Path" -Level 'VERBOSE'
        return $null
    }

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) {
        $parent = $item.Parent.FullName
    } else {
        $parent = $item.DirectoryName
    }
    $leaf = $item.Name
    if ([string]::IsNullOrWhiteSpace($parent) -or [string]::IsNullOrWhiteSpace($leaf)) {
        Write-Log -Message "Cannot determine parent/name for backup rename target: $Path" -Level 'WARN'
        return $null
    }

    $newLeaf = '{0}.LegitActivationCleaner.{1}.bak' -f $leaf, $script:RunId
    $destination = Join-Path $parent $newLeaf
    $i = 1
    while (Test-Path -LiteralPath $destination) {
        $newLeaf = '{0}.LegitActivationCleaner.{1}.{2}.bak' -f $leaf, $script:RunId, $i
        $destination = Join-Path $parent $newLeaf
        $i++
    }

    Invoke-SafeAction -Description "Rename $Path to $destination" -Category $Category -Target $Path -Data ([pscustomobject]@{
        Path = $Path
        Destination = $destination
        Reason = $Reason
    }) -Action {
        Rename-Item -LiteralPath $item.FullName -NewName $newLeaf -Force -ErrorAction Stop
    } | Out-Null

    return $destination
}

function Remove-OhookArtifacts {
    [CmdletBinding()]
    param(
        [object[]]$Candidates = $script:DetectedOhookArtifacts
    )

    if (-not $Candidates -or $Candidates.Count -eq 0) {
        Write-Log -Message 'No Ohook target DLLs were found in scoped Office locations.' -Level 'INFO'
        return
    }

    $sawSuspicious = $false
    foreach ($candidate in @($Candidates)) {
        $metadata = $candidate.Metadata
        Write-Log -Message ("DLL observed: {0}; size={1}; sha256={2}; reparse={3}; company={4}; action={5}" -f $metadata.Path, $metadata.Length, $metadata.SHA256, $metadata.IsReparsePoint, $metadata.CompanyName, $candidate.RecommendedAction) -Level 'INFO'
        Add-ReportListItem -ListName 'DetectedArtifacts' -Item ([pscustomobject]@{
            Category = 'OhookDLL'
            Path = $metadata.Path
            Metadata = $metadata
            IsSuspicious = $candidate.IsSuspicious
            RecommendedAction = $candidate.RecommendedAction
            Reason = $candidate.Reason
        })

        if (-not $candidate.IsSuspicious -or $candidate.RecommendedAction -eq 'LogOnly') {
            continue
        }
        $sawSuspicious = $true

        if ($candidate.RecommendedAction -eq 'ReportOnly') {
            Write-Log -Message "Suspicious Office licensing DLL reported only. Use -Force to rename after verifying Office health: $($metadata.Path)" -Level 'WARN'
            Add-ReportListItem -ListName 'Skipped' -Item ([pscustomobject]@{
                Category = 'OhookArtifact'
                Target = $metadata.Path
                Reason = 'Suspicious OSPPC.DLL reported only without -Force'
            })
            continue
        }

        if (-not (Test-IsSafeOhookTarget -Path $metadata.Path)) {
            Write-Log -Message "Unsafe Ohook cleanup target blocked: $($metadata.Path)" -Level 'WARN'
            continue
        }

        if ($candidate.RecommendedAction -eq 'RemoveSymlink' -or $candidate.RecommendedAction -eq 'Remove') {
            Invoke-SafeAction -Description "Remove Ohook artifact $($metadata.Path)" -Category 'OhookArtifact' -Target $metadata.Path -Data $candidate -Action {
                Remove-Item -LiteralPath $metadata.Path -Force -ErrorAction Stop
            } | Out-Null

            Add-ReportListItem -ListName 'FilesRemovedOrRenamed' -Item ([pscustomobject]@{
                Path = $metadata.Path
                Operation = 'Remove'
                ItemType = 'File'
                Reason = $candidate.Reason
                SHA256 = $metadata.SHA256
                Size = $metadata.Length
                Mode = if ($script:DryRunMode) { 'WouldRemove' } else { 'Removed' }
            })
        } elseif ($candidate.RecommendedAction -eq 'RenameToBak') {
            $destination = Rename-PathToBackupSafe -Path $metadata.Path -Reason $candidate.Reason -Category 'OhookArtifact'
            Add-ReportListItem -ListName 'FilesRemovedOrRenamed' -Item ([pscustomobject]@{
                Path = $metadata.Path
                Destination = $destination
                Operation = 'RenameToBak'
                ItemType = 'File'
                Reason = $candidate.Reason
                SHA256 = $metadata.SHA256
                Size = $metadata.Length
                Mode = if ($script:DryRunMode) { 'WouldRename' } else { 'Renamed' }
            })
        }
    }

    if ($sawSuspicious) {
        Write-Log -Message 'If Office reports licensing errors after Ohook cleanup, run Microsoft Office Quick Repair.' -Level 'WARN'
    }
}

function Restart-LicensingServices {
    [CmdletBinding()]
    param()

    if ($NoRestartServices) {
        Write-Log -Message 'Licensing service restart skipped because -NoRestartServices was specified.' -Level 'INFO'
        Add-ReportListItem -ListName 'Skipped' -Item ([pscustomobject]@{
            Category = 'Service'
            Target = 'sppsvc, ClipSVC, osppsvc'
            Reason = '-NoRestartServices'
        })
        return
    }

    $services = @('sppsvc', 'ClipSVC', 'osppsvc')
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
        } catch {
            Write-Log -Message "Service not found: $serviceName" -Level 'VERBOSE'
            continue
        }

        if ($service.Status -eq 'Running') {
            if ($script:DryRunMode) {
                Write-Log -Message "Would do: Restart service $serviceName" -Level 'INFO'
                Add-ReportAction -Category 'Service' -Action "Restart service $serviceName" -Target $serviceName -Status 'WouldDo' -Detail 'Dry-run/WhatIf mode; no service was restarted.' -Data $null
            } else {
                try {
                    Write-Log -Message "Doing: Restart service $serviceName" -Level 'INFO'
                    Restart-Service -Name $serviceName -Force -ErrorAction Stop
                    Write-Log -Message "Done: Restart service $serviceName" -Level 'SUCCESS'
                    Add-ReportAction -Category 'Service' -Action "Restart service $serviceName" -Target $serviceName -Status 'Done' -Detail '' -Data $null
                } catch {
                    Write-Log -Message "Could not restart service $serviceName; continuing. $($_.Exception.Message)" -Level 'WARN'
                    Add-ReportAction -Category 'Service' -Action "Restart service $serviceName" -Target $serviceName -Status 'Warning' -Detail $_.Exception.Message -Data $null
                }
            }
            Add-ReportListItem -ListName 'ServicesRestarted' -Item ([pscustomobject]@{
                Name = $serviceName
                Operation = if ($script:DryRunMode) { 'WouldRestart' } else { 'Restarted' }
            })
        } elseif ($service.StartType -ne 'Disabled') {
            if ($script:DryRunMode) {
                Write-Log -Message "Would do: Start service $serviceName because it is not running" -Level 'INFO'
                Add-ReportAction -Category 'Service' -Action "Start service $serviceName" -Target $serviceName -Status 'WouldDo' -Detail 'Dry-run/WhatIf mode; no service was started.' -Data $null
            } else {
                try {
                    Write-Log -Message "Doing: Start service $serviceName because it is not running" -Level 'INFO'
                    Start-Service -Name $serviceName -ErrorAction Stop
                    Write-Log -Message "Done: Start service $serviceName" -Level 'SUCCESS'
                    Add-ReportAction -Category 'Service' -Action "Start service $serviceName" -Target $serviceName -Status 'Done' -Detail '' -Data $null
                } catch {
                    Write-Log -Message "Could not start service $serviceName; continuing. $($_.Exception.Message)" -Level 'WARN'
                    Add-ReportAction -Category 'Service' -Action "Start service $serviceName" -Target $serviceName -Status 'Warning' -Detail $_.Exception.Message -Data $null
                }
            }
            Add-ReportListItem -ListName 'ServicesRestarted' -Item ([pscustomobject]@{
                Name = $serviceName
                Operation = if ($script:DryRunMode) { 'WouldStart' } else { 'Started' }
            })
        } else {
            Write-Log -Message "Service is disabled, skipped: $serviceName" -Level 'WARN'
            Add-ReportListItem -ListName 'Skipped' -Item ([pscustomobject]@{
                Category = 'Service'
                Target = $serviceName
                Reason = 'Service disabled'
            })
        }
    }
}

function Get-CurrentScriptPathSafe {
    [CmdletBinding()]
    param()

    if ($PSCommandPath) {
        return $PSCommandPath
    }
    if ($MyInvocation.MyCommand.Path) {
        return $MyInvocation.MyCommand.Path
    }
    return $null
}

function Install-PostRebootSweepTask {
    [CmdletBinding()]
    param()

    $scriptPath = Get-CurrentScriptPathSafe
    if ([string]::IsNullOrWhiteSpace($scriptPath) -or -not (Test-Path -LiteralPath $scriptPath)) {
        Write-Log -Message 'Cannot install post-reboot sweep because the current script path could not be resolved.' -Level 'WARN'
        return
    }

    $taskName = 'PostRebootSweep'
    $taskPath = '\LegitActivationCleaner\'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -PostRebootSweep -SkipOffice -SkipOhookCleanup -NoRestartServices -VerboseLog -ExportReport' -f $scriptPath

    if ($script:DryRunMode) {
        Write-Log -Message "Would install one-time post-reboot sweep Scheduled Task: $taskPath$taskName" -Level 'INFO'
        Add-ReportAction -Category 'PostRebootSweep' -Action 'Install post-reboot sweep task' -Target "$taskPath$taskName" -Status 'WouldDo' -Detail $arguments -Data $null
        return
    }

    try {
        $action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
        Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Log -Message "Installed one-time post-reboot sweep task: $taskPath$taskName" -Level 'SUCCESS'
        Add-ReportAction -Category 'PostRebootSweep' -Action 'Install post-reboot sweep task' -Target "$taskPath$taskName" -Status 'Done' -Detail $arguments -Data $null
    } catch {
        Write-Log -Message "ScheduledTasks module path failed for post-reboot sweep; trying schtasks.exe fallback. $($_.Exception.Message)" -Level 'WARN'
        $schtasks = Join-Path $env:SystemRoot 'System32\schtasks.exe'
        $taskRun = '"{0}" {1}' -f $powershell, $arguments
        $result = Invoke-ExternalCommandSafe -FilePath $schtasks -Arguments @('/Create', '/TN', "$taskPath$taskName", '/SC', 'ONSTART', '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/TR', $taskRun, '/F') -Description 'Install post-reboot sweep task with schtasks.exe' -Category 'PostRebootSweep' -Target "$taskPath$taskName" -AllowFailure
        if ($result.ExitCode -eq 0) {
            Write-Log -Message "Installed one-time post-reboot sweep task with schtasks.exe: $taskPath$taskName" -Level 'SUCCESS'
        } else {
            Write-Log -Message 'Could not install post-reboot sweep task; cleanup can still be run manually after reboot.' -Level 'WARN'
        }
    }
}

function Remove-PostRebootSweepTask {
    [CmdletBinding()]
    param()

    $taskName = 'PostRebootSweep'
    $taskPath = '\LegitActivationCleaner\'
    try {
        $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
    } catch {
        $schtasks = Join-Path $env:SystemRoot 'System32\schtasks.exe'
        $query = Invoke-ExternalCommandSafe -FilePath $schtasks -Arguments @('/Query', '/TN', "$taskPath$taskName") -Description 'Query post-reboot sweep task with schtasks.exe' -Category 'PostRebootSweep' -Target "$taskPath$taskName" -ReadOnly -AllowFailure
        if ($query.ExitCode -ne 0) {
            Write-Log -Message "Post-reboot sweep task was not found for self-removal: $taskPath$taskName" -Level 'VERBOSE'
            return
        }
        Invoke-ExternalCommandSafe -FilePath $schtasks -Arguments @('/Delete', '/TN', "$taskPath$taskName", '/F') -Description "Remove one-time post-reboot sweep task $taskPath$taskName" -Category 'PostRebootSweep' -Target "$taskPath$taskName" -AllowFailure | Out-Null
        return
    }

    Invoke-SafeAction -Description "Remove one-time post-reboot sweep task $taskPath$taskName" -Category 'PostRebootSweep' -Target "$taskPath$taskName" -Data $task -Action {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
    } | Out-Null
}

function New-PlainTextReport {
    [CmdletBinding()]
    param()

    $lines = New-Object System.Collections.ArrayList
    $null = $lines.Add('LegitActivationCleaner report')
    $null = $lines.Add(('RunId: {0}' -f $script:Report.RunId))
    $null = $lines.Add(('StartTime: {0}' -f $script:Report.StartTime))
    $null = $lines.Add(('EndTime: {0}' -f $script:Report.EndTime))
    $null = $lines.Add(('DryRun: {0}' -f $script:Report.DryRun))
    $null = $lines.Add(('Force: {0}' -f $script:Report.Force))
    $null = $lines.Add('')
    $null = $lines.Add('OS:')
    foreach ($key in $script:Report.OS.Keys) {
        $null = $lines.Add(('  {0}: {1}' -f $key, $script:Report.OS[$key]))
    }
    $null = $lines.Add('')
    $null = $lines.Add(('Actions: {0}' -f $script:Report.Actions.Count))
    $null = $lines.Add(('Warnings: {0}' -f $script:Report.Warnings.Count))
    $null = $lines.Add(('Errors: {0}' -f $script:Report.Errors.Count))
    $null = $lines.Add('')
    $null = $lines.Add('Next steps:')
    foreach ($step in $script:Report.NextSteps) {
        $null = $lines.Add(('  - {0}' -f $step))
    }
    return ($lines -join [Environment]::NewLine)
}

function Generate-ActivationReport {
    [CmdletBinding()]
    param()

    Ensure-NextSteps
    $script:Report.EndTime = (Get-Date).ToString('o')

    $jsonPath = Join-Path $script:ReportRoot ("LegitActivationCleaner-{0}.json" -f $script:RunId)
    try {
        $script:Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 -Force
        $null = $script:Report.ReportFiles.Add($jsonPath)
        Write-Log -Message "JSON report written: $jsonPath" -Level 'SUCCESS'
    } catch {
        Write-Log -Message "Failed to write JSON report: $($_.Exception.Message)" -Level 'WARN'
    }

    if ($ExportReport) {
        $txtPath = Join-Path $script:ReportRoot ("LegitActivationCleaner-{0}.txt" -f $script:RunId)
        $csvPath = Join-Path $script:ReportRoot ("LegitActivationCleaner-Actions-{0}.csv" -f $script:RunId)

        try {
            New-PlainTextReport | Set-Content -LiteralPath $txtPath -Encoding UTF8 -Force
            $null = $script:Report.ReportFiles.Add($txtPath)
            Write-Log -Message "Text report written: $txtPath" -Level 'SUCCESS'
        } catch {
            Write-Log -Message "Failed to write text report: $($_.Exception.Message)" -Level 'WARN'
        }

        try {
            $script:Report.Actions | Select-Object Time, Category, Action, Target, Status, Detail | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -Force
            $null = $script:Report.ReportFiles.Add($csvPath)
            Write-Log -Message "CSV action report written: $csvPath" -Level 'SUCCESS'
        } catch {
            Write-Log -Message "Failed to write CSV report: $($_.Exception.Message)" -Level 'WARN'
        }
    }
}

function Show-NextSteps {
    [CmdletBinding()]
    param()

    Ensure-NextSteps
    Write-Host ''
    Write-Host 'Next steps' -ForegroundColor Cyan
    foreach ($step in $script:Report.NextSteps) {
        Write-Host " - $step" -ForegroundColor Gray
        Write-Log -Message "Next step: $step" -Level 'INFO'
    }
}

function Ensure-NextSteps {
    [CmdletBinding()]
    param()

    if ($script:Report.NextSteps.Count -gt 0) {
        return
    }

    $steps = @(
        'Restart the computer.',
        'For Windows retail/OEM/volume MAK: run slmgr /ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX, then slmgr /ato, then slmgr /dlv.',
        'For Microsoft 365 / Click-to-Run Office: open an Office app and sign in with a valid Microsoft/M365 account.',
        'For valid Office volume/MSI licensing: use ospp.vbs /inpkey:XXXXX-XXXXX-XXXXX-XXXXX-XXXXX, then follow your organization activation process.',
        'If Office reports licensing errors, run Apps & Features > Microsoft 365 / Office > Modify > Quick Repair.'
    )

    foreach ($step in $steps) {
        $null = $script:Report.NextSteps.Add($step)
    }
}

function Add-DetectedArtifactReportItems {
    [CmdletBinding()]
    param()

    foreach ($task in @($script:DetectedScheduledTasks)) {
        Add-ReportListItem -ListName 'DetectedArtifacts' -Item ([pscustomobject]@{
            Category = 'ScheduledTask'
            Target = ('{0}{1}' -f $task.TaskPath, $task.TaskName)
            Match = $task.Match
            Actions = $task.Actions
        })
    }

    foreach ($file in @($script:DetectedMASFileArtifacts)) {
        Add-ReportListItem -ListName 'DetectedArtifacts' -Item ([pscustomobject]@{
            Category = 'FileArtifact'
            Target = $file.Path
            ItemType = $file.ItemType
            Confidence = $file.Confidence
            Reason = $file.Reason
        })
    }
}

function Invoke-Main {
    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host 'PowerShell 5.1 or later is required.' -ForegroundColor Red
        exit 2
    }

    if (-not (Test-IsAdministrator)) {
        Write-Host 'Administrator rights are required. Start Windows PowerShell as Administrator and run this script again.' -ForegroundColor Red
        exit 1
    }

    Initialize-RunStorage
    Write-Log -Message "Started $script:ToolName $script:Version run $script:RunId" -Level 'INFO'
    Write-Log -Message "Log file: $script:LogPath" -Level 'INFO'
    if ($script:DryRunMode) {
        Write-Log -Message 'Dry-run/WhatIf mode is active. No system changes will be made.' -Level 'INFO'
    }

    Write-Step -Number 1 -Name 'Pre-flight check'
    Show-OfficeCloseWarning
    $script:Report.OS = Get-WindowsOSInfo
    $script:Report.WindowsActivationBefore = @(Get-WindowsActivationState)
    New-SystemRestorePointSafe

    Write-Step -Number 2 -Name 'Detect MAS/KMS artifacts'
    $script:DetectedScheduledTasks = @(Get-MASScheduledTaskCandidates)
    $script:DetectedMASFileArtifacts = @(Get-MASFileCandidates)
    $script:DetectedOhookArtifacts = @(Get-OhookCandidates)
    Add-DetectedArtifactReportItems
    Write-Log -Message ("Detected {0} task(s), {1} file/folder artifact(s), {2} Office DLL observation(s)." -f $script:DetectedScheduledTasks.Count, $script:DetectedMASFileArtifacts.Count, $script:DetectedOhookArtifacts.Count) -Level 'INFO'

    Write-Step -Number 3 -Name 'Remove scheduled tasks and MAS/KMS startup persistence'
    Remove-ScheduledTasksRelatedToMAS
    Remove-RunEntriesRelatedToMAS
    Remove-StartupFolderItemsRelatedToMAS
    Remove-ServicesRelatedToMAS
    Remove-MASFilesAndFolders

    Write-Step -Number 4 -Name 'Clear Windows licensing configuration'
    if ($SkipWindows) {
        Write-Log -Message 'Windows licensing cleanup skipped because -SkipWindows was specified.' -Level 'INFO'
    } else {
        Clear-WindowsKMSConfiguration
        Clear-WindowsProductKey -ActivationStateBefore $script:Report.WindowsActivationBefore
    }

    Write-Step -Number 5 -Name 'Clear Office licensing configuration'
    if ($SkipOffice) {
        Write-Log -Message 'Office licensing cleanup skipped because -SkipOffice was specified.' -Level 'INFO'
    } else {
        Clear-OfficeKMSConfiguration
    }

    Write-Step -Number 6 -Name 'Remove Office product keys'
    if ($SkipOffice) {
        Write-Log -Message 'Office product key cleanup skipped because -SkipOffice was specified.' -Level 'INFO'
    } else {
        Clear-OfficeProductKeys
    }

    Write-Step -Number 7 -Name 'Remove Ohook artifacts'
    if ($SkipOffice -or $SkipOhookCleanup) {
        Write-Log -Message 'Ohook cleanup skipped because -SkipOffice or -SkipOhookCleanup was specified.' -Level 'INFO'
    } else {
        Remove-OhookArtifacts
    }

    Write-Step -Number 8 -Name 'Remove Office license caches'
    if ($SkipOffice) {
        Write-Log -Message 'Office license cache cleanup skipped because -SkipOffice was specified.' -Level 'INFO'
    } else {
        Remove-OfficeLicenseCaches
    }

    Write-Step -Number 9 -Name 'Restart licensing services'
    Restart-LicensingServices

    if ($InstallPostRebootSweep -and -not $PostRebootSweep) {
        Install-PostRebootSweepTask
    }
    if ($PostRebootSweep) {
        Remove-PostRebootSweepTask
    }

    $script:Report.WindowsActivationAfter = @(Get-WindowsActivationState)

    Write-Step -Number 10 -Name 'Generate report'
    Generate-ActivationReport

    Write-Step -Number 11 -Name 'Show next steps'
    Show-NextSteps

    Write-Log -Message "Completed $script:ToolName run." -Level 'SUCCESS'
}

try {
    Invoke-Main
    if ($script:HadWarnings) {
        exit 3
    }
    exit 0
} catch {
    $script:FatalError = $true
    if (-not $script:LogPath) {
        Write-Host "Fatal error: $($_.Exception.Message)" -ForegroundColor Red
    } else {
        Write-Log -Message "Fatal error: $($_.Exception.Message)" -Level 'ERROR'
        try {
            Generate-ActivationReport
        } catch {
            Write-Host "Unable to generate fatal-error report: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    exit 2
}
