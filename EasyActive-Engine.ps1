<# 
.SYNOPSIS
    EasyActive by MyPC - conservative cleanup for MAS/KMS-style activation artifacts.

.DESCRIPTION
    Removes clearly identified non-standard activation persistence/configuration from
    Windows and Microsoft Office so a technician can move a machine back to legitimate
    Windows/Office activation.

    This script does not activate Windows or Office, does not install or contact KMS
    servers, and deliberately does not clear event logs, Defender history, Prefetch,
    Amcache, ShimCache, SRUM, or other forensic artifacts.

.NOTES
    Requires Windows PowerShell 5.1 or later and Administrator rights.
    Default log path: C:\ProgramData\EasyActiveByMyPC\Logs
    Default backup path: C:\ProgramData\EasyActiveByMyPC\Backups
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
    [switch]$PostRebootSweep,
    [switch]$ReadOEMKeyOnly,
    [switch]$ShowFullKeys,
    [switch]$ExportSensitiveKeys,
    [switch]$ReinstallOEMKey,
    [switch]$SkipOEMActivation,
    [switch]$CheckLicenseOnly,
    [switch]$AssessCrack,
    [switch]$LauncherMenu,

    [ValidateSet('vi', 'en')]
    [string]$Language = 'vi'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolName = 'EasyActive by MyPC'
$script:Version = '1.8.8'
$script:Language = $Language.ToLowerInvariant()
$script:RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:ProgramDataRoot = Join-Path $env:ProgramData 'EasyActiveByMyPC'
$script:LogRoot = Join-Path $script:ProgramDataRoot 'Logs'
$script:BackupRoot = Join-Path (Join-Path $script:ProgramDataRoot 'Backups') $script:RunId
$script:ReportRoot = Join-Path $script:ProgramDataRoot 'Reports'
$script:LogPath = $null
$script:LastHtmlReportPath = $null
$script:DryRunMode = [bool]($DryRun -or $WhatIfPreference)
# Convert script-level -WhatIf into the tool's own dry-run mode. This keeps
# logging, backups, and report generation usable while all destructive work is
# still blocked by Invoke-SafeAction / Invoke-ExternalCommandSafe.
$WhatIfPreference = $false
$script:HadWarnings = $false
$script:LoopAgain = $false
# Single source of truth for crack-tool name signatures, shared by name matching,
# persistence-text matching, and scheduled-task detection so they never drift apart.
$script:MASCrackSignatures = @(
    'AutoKMS',
    'KMSAuto',
    'KMS_VL_ALL',
    'KMSpico',
    'KMSTools',
    'KMSCleaner',
    'Ratiborus',
    'HWIDGEN',
    'HWID-Gen',
    'HWID_Activation',
    'Microsoft-Activation-Scripts',
    'MAS_AIO',
    'Re-Loader',
    'ReLoader',
    'Microsoft Toolkit',
    'MicrosoftToolkit',
    'AAct',
    'W10 Digital Activation',
    'W10DigitalActivation',
    'Activation-Renewal',
    'Online_KMS_Activation',
    'Online_KMS_Activation_Script',
    'SppExtComObjHook',
    'R@1n-KMS'
)
# Microsoft activation/licensing domains that cracks sinkhole in the hosts file (shared
# by hosts detection and hosts cleanup).
$script:MASActivationHostDomains = @(
    'sls.microsoft.com',
    'activation.sls',
    'activation-v2.sls',
    'sls.update.microsoft.com',
    'licensing.mp.microsoft.com',
    'licensing.md.mp.microsoft.com',
    'validation.sls',
    'displaycatalog.mp.microsoft.com',
    'activation.microsoft.com'
)
$script:FatalError = $false
$script:DetectedScheduledTasks = @()
$script:DetectedMASFileArtifacts = @()
$script:DetectedOhookArtifacts = @()

function New-ReportObject {
    [CmdletBinding()]
    param()

    return [ordered]@{
    ToolName = $script:ToolName
    Version = $script:Version
    ScriptName = 'EasyActive-Engine.ps1'
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
        ReadOEMKeyOnly = [bool]$ReadOEMKeyOnly
        ShowFullKeys = [bool]$ShowFullKeys
        ExportSensitiveKeys = [bool]$ExportSensitiveKeys
        ReinstallOEMKey = [bool]$ReinstallOEMKey
        SkipOEMActivation = [bool]$SkipOEMActivation
        CheckLicenseOnly = [bool]$CheckLicenseOnly
        AssessCrack = [bool]$AssessCrack
        LauncherMenu = [bool]$LauncherMenu
        Language = $script:Language
    }
    LicenseStatusCheck = [ordered]@{
        Requested = $false
        WindowsEdition = $null
        WindowsExpiry = $null
        WindowsGenuine = $null
        WindowsProductCount = 0
        OfficeProductCount = 0
        Notes = New-Object System.Collections.ArrayList
    }
    CrackAssessment = [ordered]@{
        Requested = $false
        Verdict = 'NotAssessed'
        VerdictText = $null
        Confidence = 'None'
        ConfidenceText = $null
        Reasons = New-Object System.Collections.ArrayList
        Score = 0
        DefiniteArtifact = $false
        Incomplete = $false
        Signals = New-Object System.Collections.ArrayList
    }
    OEMEmbeddedKeyInfo = [ordered]@{
        KeyFound = $false
        MaskedKey = $null
        KeyDescription = $null
        DetectedKeyEdition = 'Unknown'
        CurrentWindowsEdition = $null
        Compatibility = 'Unknown'
        Notes = New-Object System.Collections.ArrayList
    }
    OEMEmbeddedKeyChecked = $false
    OEMKeyReinstall = [ordered]@{
        Requested = $false
        Attempted = $false
        KeyFound = $false
        Compatibility = 'Unknown'
        MaskedKey = $null
        InstallStatus = 'NotAttempted'
        InstallExitCode = $null
        ActivationRequested = $false
        ActivationStatus = 'NotAttempted'
        ActivationExitCode = $null
        Notes = New-Object System.Collections.ArrayList
    }
    OS = [ordered]@{}
    WindowsActivationBefore = @()
    WindowsActivationAfter = @()
    GenuineStatus = $null
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
}

$script:Report = New-ReportObject

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

    $script:LogPath = Join-Path $script:LogRoot ("EasyActiveByMyPC-{0}.log" -f $script:RunId)
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

function Get-UiText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    if ($script:Language -eq 'en') {
        switch ($Key) {
            'AdminRequired' { return 'Administrator rights are required. Start Windows PowerShell as Administrator and run this script again.' }
            'PowerShellRequired' { return 'PowerShell 5.1 or later is required.' }
            'DryRunActive' { return 'Dry-run/WhatIf mode is active. No system changes will be made.' }
            'SensitiveExportWarning' { return 'Sensitive key export is enabled. Keep the report private.' }
            'OfficeCloseWarning' { return 'Close all Microsoft Office apps before cleanup: Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher, Project, Visio, Teams/OneDrive Office file sessions, and any open Office setup/repair window.' }
            'WindowsKeyRemovalWarning' { return 'Warning before Windows key removal: slmgr /upk will uninstall the installed Windows product key from the local licensing store. A valid digital license is not removed, but Windows may require activation refresh or a valid key afterward.' }
            'OEMTitle' { return 'OEM embedded Windows product key' }
            'OEMNoKey' { return 'No OEM embedded product key found in BIOS/UEFI.' }
            'ProductKeyLabel' { return 'Product key' }
            'KeyDescriptionLabel' { return 'Key description' }
            'DetectedKeyEditionLabel' { return 'Detected key edition' }
            'CurrentWindowsEditionLabel' { return 'Current Windows edition' }
            'CompatibilityLabel' { return 'Compatibility' }
            'Unknown' { return 'Unknown' }
            'NextStepsHeading' { return 'Next steps' }
            'ReportTitle' { return 'EasyActive by MyPC report' }
            'ReportOEMHeading' { return 'OEM embedded key info:' }
            'ReportOSHeading' { return 'Operating system' }
            'DryRunBadge' { return 'DRY-RUN' }
            'ReportActions' { return 'Actions' }
            'ReportWarnings' { return 'Warnings' }
            'ReportErrors' { return 'Errors' }
            'ReportNextSteps' { return 'Next steps:' }
            'OEMReadOnlyMode' { return 'Read-only OEM embedded key mode is active. Cleanup, restore point creation, product-key changes, activation commands, and service restarts are skipped.' }
            'CompletedOEMRun' { return "Completed $script:ToolName read-only OEM embedded key run." }
            'CompletedRun' { return "Completed $script:ToolName run." }
            'StepPreflight' { return 'Pre-flight check' }
            'StepReadOEM' { return 'Read OEM embedded key from BIOS/UEFI' }
            'StepGenerateReport' { return 'Generate report' }
            'StepShowNextSteps' { return 'Show next steps' }
            'StepDetectArtifacts' { return 'Detect MAS/KMS artifacts' }
            'StepRemoveScheduled' { return 'Remove scheduled tasks and MAS/KMS startup persistence' }
            'StepClearWindows' { return 'Clear Windows licensing configuration' }
            'StepClearOffice' { return 'Clear Office licensing configuration' }
            'StepRemoveOfficeKeys' { return 'Remove Office product keys' }
            'StepRemoveOhook' { return 'Remove Ohook artifacts' }
            'StepKillOfficeProcesses' { return 'Stop Office processes to release DLL file locks' }
            'StepRemoveOfficeCaches' { return 'Remove Office license caches' }
            'StepRestartServices' { return 'Restart licensing services' }
            'NoChangeOEMNextStep' { return 'No system changes were made by this read-only OEM embedded key check.' }
            'OEMNotCompatibleNextStep' { return 'If compatibility is Not compatible, use a valid key for the current Windows edition or install the edition that matches the OEM key.' }
            'DigitalLicenseNextStep' { return 'Digital License / HWID note: if this machine was activated through MAS HWID/Digital License, this tool can only clean local keys and local configuration. Microsoft server-side hardware entitlement may still reactivate Windows when online. This is not a tool error.' }
            'SensitiveReportNextStep' { return 'Sensitive key export was enabled; keep generated reports private.' }
            'RestartComputerNextStep' { return 'Restart the computer.' }
            'WindowsActivationNextStep' { return 'For Windows retail/OEM/volume MAK: run slmgr /ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX, then slmgr /ato, then slmgr /dlv.' }
            'M365NextStep' { return 'For Microsoft 365 / Click-to-Run Office: open an Office app and sign in with a valid Microsoft/M365 account.' }
            'OfficeVolumeNextStep' { return 'For valid Office volume/MSI licensing: use ospp.vbs /inpkey:XXXXX-XXXXX-XXXXX-XXXXX-XXXXX, then follow your organization activation process.' }
            'OfficeRepairNextStep' { return 'If Office reports licensing errors, run Apps & Features > Microsoft 365 / Office > Modify > Quick Repair.' }
            'StepReinstallOEMKey' { return 'Reinstall the OEM embedded key and activate' }
            'ReinstallOEMTitle' { return 'Reinstall OEM embedded Windows product key' }
            'ReinstallOEMNoKey' { return 'No OEM embedded key was found in BIOS/UEFI, so there is nothing to reinstall.' }
            'ReinstallOEMNotCompatible' { return 'The embedded OEM key targets a different Windows edition than the one installed. Automatic reinstall was skipped to avoid a guaranteed failure. Use -Force to attempt it anyway, or install the matching Windows edition first.' }
            'ReinstallOEMInstalling' { return 'Installing the OEM embedded product key with slmgr /ipk...' }
            'ReinstallOEMInstalled' { return 'The OEM embedded product key was installed successfully.' }
            'ReinstallOEMInstallFailed' { return 'Installing the OEM embedded product key failed. See the log and report for the exit code and details.' }
            'ReinstallOEMActivating' { return 'Activating Windows online with slmgr /ato...' }
            'ReinstallOEMActivated' { return 'Windows activation request completed. Verify the result with slmgr /dlv or Settings > System > Activation.' }
            'ReinstallOEMActivateFailed' { return 'Online activation did not complete (this often means no internet connection). The key is installed; run slmgr /ato again once the machine is online.' }
            'ReinstallOEMSkippedActivation' { return 'Activation was skipped (-SkipOEMActivation). The key is installed; run slmgr /ato to activate when ready.' }
            'ReinstallOEMWouldRun' { return 'Dry-run: the OEM embedded key would be reinstalled and activated. No change was made.' }
            'ReinstallOEMNextStep' { return 'The OEM embedded key was reinstalled automatically from firmware. If Windows is not yet activated, connect to the internet and run slmgr /ato, then verify with slmgr /dlv.' }
            'StepCheckLicense' { return 'Check Windows and Office license / activation status' }
            'LicenseCheckMode' { return 'Read-only license/activation status check is active. No cleanup, restore point, key change, or service restart is performed.' }
            'CompletedLicenseCheck' { return "Completed $script:ToolName read-only license status check." }
            'LicenseWindowsTitle' { return 'Windows license / activation status' }
            'LicenseOfficeTitle' { return 'Office license / activation status' }
            'LicenseNoWindowsProduct' { return 'No Windows license with an installed product key was found.' }
            'LicenseNoOffice' { return 'No Office installation (ospp.vbs) was detected.' }
            'LicenseChannelLabel' { return 'Channel' }
            'LicenseStatusLabel' { return 'Status' }
            'LicenseExpiryLabel' { return 'Expiry' }
            'LicensePartialKeyLabel' { return 'Installed key (last 5)' }
            'LicenseGraceLabel' { return 'Grace remaining (minutes)' }
            'LicenseProductLabel' { return 'Product' }
            'ReportWindowsActivationHeading' { return 'Windows activation status:' }
            'ReportOfficeHeading' { return 'Office license status:' }
            'LicenseCheckNextStep' { return 'This was a read-only status check; nothing was changed. Windows status "Licensed" and Office status "---LICENSED---" mean activated. "Notification"/"Unlicensed" or a grace state means Windows/Office is not fully activated. The channel shows how it is licensed (OEM, Retail, Volume:MAK, or Volume:GVLK for KMS clients).' }
            'ReinstallOEMCheckingNetwork' { return 'Checking internet connectivity before online activation...' }
            'ReinstallOEMOffline' { return 'No internet connection detected, so online activation (slmgr /ato) was skipped. The OEM key is installed; connect to the internet and run slmgr /ato later to finish activation.' }
            'LicenseGenuineLabel' { return 'Genuine check (SLIsGenuineLocal)' }
            'GenuineUnavailable' { return 'Unavailable' }
            'OpenReportPrompt' { return 'Open the report?' }
            'OpenReportHtmlOption' { return '  1 = Open the HTML report' }
            'OpenReportFolderOption' { return '  2 = Open the reports folder' }
            'OpenReportNoOption' { return '  0 = No' }
            'OpenReportInput' { return 'Enter choice' }
            'StepAssessCrack' { return 'Assess Windows crack / license tampering traces' }
            'AssessCrackMode' { return 'Read-only crack/license assessment is active. Nothing is cleaned or changed; the machine is only inspected.' }
            'CompletedAssessment' { return "Completed $script:ToolName read-only crack/license assessment." }
            'AsmTitle' { return 'Crack / license tampering assessment (read-only)' }
            'AsmVerdictHeading' { return 'CONCLUSION' }
            'AsmScoreLabel' { return 'Risk score' }
            'AsmVerdictIncomplete' { return 'Note: some data could not be read, so this assessment may be incomplete.' }
            'AsmVerdictClean' { return 'No crack traces detected. The machine looks genuine/clean based on the checks above.' }
            'AsmVerdictSuspicious' { return 'SUSPICIOUS - only weak signals were found. Not conclusive; review the flagged items.' }
            'AsmVerdictLikely' { return 'LIKELY using a crack - multiple tampering signals were found.' }
            'AsmVerdictCracked' { return 'CRACK DETECTED - clear crack/activation-bypass artifacts are present.' }
            'AsmInstallDate' { return 'Windows install date' }
            'AsmActivationStatus' { return 'Activation status (WMI)' }
            'AsmKmsClientChannel' { return 'KMS client key (GVLK)' }
            'AsmKmsHost' { return 'KMS server config' }
            'AsmKms38' { return 'KMS38 (2038 expiry)' }
            'AsmKms38Signature' { return 'Activation expiry set far in the future' }
            'AsmTsforgeSignature' { return 'TSforge/KMS4k - expiry faked thousands of years ahead' }
            'AsmLicenseBios' { return 'License channel vs OEM/BIOS' }
            'AsmHwid' { return 'HWID / digital license' }
            'AsmToolFolders' { return 'Illegal tool folders/files' }
            'AsmScheduledTasks' { return 'Illegal scheduled tasks' }
            'AsmServices' { return 'Illegal services' }
            'AsmPersistence' { return 'Autorun persistence (Run/Startup)' }
            'AsmServicesDisabled' { return 'Protection services disabled' }
            'AsmRegistryTamper' { return 'Registry tampering (genuine block)' }
            'AsmHostsFile' { return 'Hosts file blocking activation' }
            'AsmOhook' { return 'Office crack (Ohook)' }
            'AsmNoData' { return 'no data / could not read' }
            'AsmNotDetected' { return 'not detected' }
            'AsmKmsLocalEmulator' { return 'localhost/emulator - strong KMS-crack signal' }
            'AsmKmsPrivate' { return 'private IP - could be enterprise KMS' }
            'AsmKmsPublic' { return 'public internet KMS host - almost always a crack' }
            'AsmKmsKnownEmulator' { return 'known public KMS-emulator server - crack' }
            'AsmOemMatches' { return 'OEM/BIOS entitlement matches edition' }
            'AsmOemMismatch' { return 'embedded OEM key targets a different edition' }
            'AsmNoOemKey' { return 'no embedded OEM key in firmware' }
            'AsmHwidInconclusive' { return 'digital license present; HWID spoofing cannot be confirmed offline (informational only)' }
            'AsmHwidNoSignal' { return 'no specific HWID signal' }
            'AsmNextStep' { return 'This was a read-only assessment; nothing was changed. If crack traces were found, use the cleanup options (menu 2/4) to remove them and then re-license the machine properly. A single weak signal (e.g. one registry tweak) is not proof of a crack.' }
            'ReportAssessmentHeading' { return 'Crack / license assessment:' }
            'AsmColCheck' { return 'Check' }
            'AsmColEvidence' { return 'Evidence' }
            'AsmColConfidence' { return 'Confidence' }
            'AsmGenuine' { return 'Genuine authenticity (SLIsGenuineLocal)' }
            'AsmGenuineUnavailable' { return 'genuine check could not run' }
            'AsmGenuineGenuine' { return 'Windows reports GENUINE' }
            'AsmGenuineTampered' { return 'TAMPERED - licensing store was modified (crack signature)' }
            'AsmGenuineForged' { return 'shows Licensed locally but genuine check says INVALID - forged/HWID-style activation' }
            'AsmGenuineNotActivated' { return 'not activated (invalid license, but not a crack)' }
            'AsmGenuineOffline' { return 'could not verify online' }
            'AsmHwidForged' { return 'digital license with no OEM key AND genuine check not clean - possible HWID forgery' }
            'AsmConfidenceLabel' { return 'Confidence' }
            'AsmConfidenceHigh' { return 'High' }
            'AsmConfidenceMedium' { return 'Medium' }
            'AsmConfidenceLow' { return 'Low' }
            'AsmReasonsLabel' { return 'Main reasons' }
            default { return $Key }
        }
    }

    switch ($Key) {
        'AdminRequired' { return 'Cần chạy bằng quyền Administrator. Hãy mở Windows PowerShell bằng Run as administrator rồi chạy lại script.' }
        'PowerShellRequired' { return 'Cần Windows PowerShell 5.1 trở lên.' }
        'DryRunActive' { return 'Đang chạy chế độ kiểm tra thử/Dry-run. Không có thay đổi nào được thực hiện trên hệ thống.' }
        'SensitiveExportWarning' { return 'Đang bật xuất key nhạy cảm. Hãy giữ report ở nơi riêng tư.' }
        'OfficeCloseWarning' { return 'LƯU Ý: Hãy đóng toàn bộ Word, Excel, PowerPoint, Outlook và các ứng dụng Office trước khi tiếp tục. Nếu Office đang mở, một số file license/cache có thể không xử lý được.' }
        'WindowsKeyRemovalWarning' { return 'CẢNH BÁO: slmgr /upk sẽ gỡ product key Windows đang lưu trong licensing store local. Digital License hợp lệ không bị xóa, nhưng Windows có thể cần refresh kích hoạt hoặc nhập key hợp lệ sau khi dọn.' }
        'OEMTitle' { return 'Key Windows OEM nhúng trong BIOS/UEFI' }
        'OEMNoKey' { return 'Không tìm thấy key Windows OEM trong BIOS/UEFI.' }
        'ProductKeyLabel' { return 'Product key' }
        'KeyDescriptionLabel' { return 'Mô tả key' }
        'DetectedKeyEditionLabel' { return 'Phiên bản suy đoán từ key' }
        'CurrentWindowsEditionLabel' { return 'Phiên bản Windows đang cài' }
        'CompatibilityLabel' { return 'Mức tương thích' }
        'Unknown' { return 'Không xác định' }
        'NextStepsHeading' { return 'Bước tiếp theo' }
        'ReportTitle' { return 'Báo cáo EasyActive by MyPC' }
        'ReportOEMHeading' { return 'Thông tin key OEM nhúng:' }
        'ReportOSHeading' { return 'Hệ điều hành' }
        'DryRunBadge' { return 'CHẠY THỬ' }
        'ReportActions' { return 'Thao tác' }
        'ReportWarnings' { return 'Cảnh báo' }
        'ReportErrors' { return 'Lỗi' }
        'ReportNextSteps' { return 'Bước tiếp theo:' }
        'OEMReadOnlyMode' { return 'Đang chạy chế độ chỉ đọc key OEM. Bỏ qua dọn dẹp, tạo restore point, thay đổi product key, lệnh kích hoạt và restart dịch vụ.' }
        'CompletedOEMRun' { return "Hoàn tất lượt đọc key OEM chỉ đọc của $script:ToolName." }
        'CompletedRun' { return "Hoàn tất lượt chạy $script:ToolName." }
        'StepPreflight' { return 'Kiểm tra ban đầu' }
        'StepReadOEM' { return 'Đọc key OEM từ BIOS/UEFI' }
        'StepGenerateReport' { return 'Tạo báo cáo' }
        'StepShowNextSteps' { return 'Hiển thị bước tiếp theo' }
        'StepDetectArtifacts' { return 'Dò dấu vết MAS/KMS' }
        'StepRemoveScheduled' { return 'Xóa lịch tự kích hoạt và cơ chế tự chạy MAS/KMS' }
        'StepClearWindows' { return 'Dọn cấu hình kích hoạt Windows' }
        'StepClearOffice' { return 'Dọn cấu hình kích hoạt Office' }
        'StepRemoveOfficeKeys' { return 'Gỡ product key Office' }
        'StepRemoveOhook' { return 'Gỡ dấu vết Ohook' }
        'StepKillOfficeProcesses' { return 'Dừng tiến trình Office để giải phóng file lock DLL' }
        'StepRemoveOfficeCaches' { return 'Dọn cache license Office' }
        'StepRestartServices' { return 'Restart dịch vụ licensing' }
        'NoChangeOEMNextStep' { return 'Tính năng đọc key OEM chỉ đọc thông tin, không kích hoạt Windows và không thay đổi hệ thống.' }
        'OEMNotCompatibleNextStep' { return 'Nếu kết quả là Not compatible, hãy dùng key hợp lệ cho đúng phiên bản Windows đang cài hoặc cài phiên bản Windows khớp với key OEM.' }
        'DigitalLicenseNextStep' { return 'LƯU Ý VỀ DIGITAL LICENSE / HWID: Nếu máy từng được active bằng MAS dạng HWID/Digital License, công cụ chỉ có thể dọn key và cấu hình local trên máy. Digital license đã gắn với phần cứng trên server Microsoft có thể vẫn khiến Windows tự kích hoạt lại khi online. Đây không phải lỗi của công cụ.' }
        'SensitiveReportNextStep' { return 'Đã bật xuất key nhạy cảm; hãy giữ các report được tạo ở nơi riêng tư.' }
        'RestartComputerNextStep' { return 'Restart máy tính.' }
        'WindowsActivationNextStep' { return 'Với Windows retail/OEM/volume MAK: chạy slmgr /ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX, sau đó slmgr /ato, rồi slmgr /dlv.' }
        'M365NextStep' { return 'Với Microsoft 365 / Office Click-to-Run: mở ứng dụng Office và đăng nhập tài khoản Microsoft/Microsoft 365 hợp lệ.' }
        'OfficeVolumeNextStep' { return 'Với Office volume/MSI hợp lệ: dùng ospp.vbs /inpkey:XXXXX-XXXXX-XXXXX-XXXXX-XXXXX, sau đó kích hoạt theo quy trình của tổ chức.' }
        'OfficeRepairNextStep' { return 'Nếu Office báo lỗi license, vào Apps & Features > Microsoft 365 / Office > Modify > Quick Repair.' }
        'StepReinstallOEMKey' { return 'Cài lại key OEM nhúng và kích hoạt' }
        'ReinstallOEMTitle' { return 'Cài lại key Windows OEM nhúng trong BIOS/UEFI' }
        'ReinstallOEMNoKey' { return 'Không tìm thấy key OEM trong BIOS/UEFI nên không có gì để cài lại.' }
        'ReinstallOEMNotCompatible' { return 'Key OEM nhúng thuộc phiên bản Windows khác với phiên bản đang cài. Đã bỏ qua cài lại tự động để tránh chắc chắn thất bại. Dùng -Force để vẫn thử, hoặc cài đúng phiên bản Windows khớp với key trước.' }
        'ReinstallOEMInstalling' { return 'Đang cài key OEM nhúng bằng slmgr /ipk...' }
        'ReinstallOEMInstalled' { return 'Đã cài key OEM nhúng thành công.' }
        'ReinstallOEMInstallFailed' { return 'Cài key OEM nhúng thất bại. Xem log và báo cáo để biết mã lỗi và chi tiết.' }
        'ReinstallOEMActivating' { return 'Đang kích hoạt Windows online bằng slmgr /ato...' }
        'ReinstallOEMActivated' { return 'Đã gửi yêu cầu kích hoạt Windows. Kiểm tra kết quả bằng slmgr /dlv hoặc Settings > System > Activation.' }
        'ReinstallOEMActivateFailed' { return 'Kích hoạt online chưa hoàn tất (thường do máy chưa có mạng). Key đã được cài; chạy lại slmgr /ato khi máy đã online.' }
        'ReinstallOEMSkippedActivation' { return 'Đã bỏ qua kích hoạt (-SkipOEMActivation). Key đã được cài; chạy slmgr /ato để kích hoạt khi sẵn sàng.' }
        'ReinstallOEMWouldRun' { return 'Chế độ thử: key OEM nhúng sẽ được cài lại và kích hoạt. Không có thay đổi nào được thực hiện.' }
        'ReinstallOEMNextStep' { return 'Key OEM nhúng đã được cài lại tự động từ firmware. Nếu Windows chưa kích hoạt, hãy nối mạng và chạy slmgr /ato, sau đó kiểm tra bằng slmgr /dlv.' }
        'StepCheckLicense' { return 'Kiểm tra trạng thái license / kích hoạt Windows và Office' }
        'LicenseCheckMode' { return 'Đang chạy chế độ chỉ kiểm tra trạng thái license/kích hoạt. Không dọn dẹp, không tạo restore point, không đổi key, không restart dịch vụ.' }
        'CompletedLicenseCheck' { return "Hoàn tất lượt kiểm tra trạng thái license (chỉ đọc) của $script:ToolName." }
        'LicenseWindowsTitle' { return 'Trạng thái license / kích hoạt Windows' }
        'LicenseOfficeTitle' { return 'Trạng thái license / kích hoạt Office' }
        'LicenseNoWindowsProduct' { return 'Không tìm thấy license Windows nào có product key đã cài.' }
        'LicenseNoOffice' { return 'Không phát hiện bản Office (ospp.vbs) nào.' }
        'LicenseChannelLabel' { return 'Kênh key' }
        'LicenseStatusLabel' { return 'Trạng thái' }
        'LicenseExpiryLabel' { return 'Hạn dùng' }
        'LicensePartialKeyLabel' { return 'Key đã cài (5 ký tự cuối)' }
        'LicenseGraceLabel' { return 'Ân hạn còn lại (phút)' }
        'LicenseProductLabel' { return 'Sản phẩm' }
        'ReportWindowsActivationHeading' { return 'Trạng thái kích hoạt Windows:' }
        'ReportOfficeHeading' { return 'Trạng thái license Office:' }
        'LicenseCheckNextStep' { return 'Đây là bước chỉ kiểm tra, không thay đổi gì. Windows ở trạng thái "Licensed" và Office ở "---LICENSED---" nghĩa là đã kích hoạt. Nếu là "Notification"/"Unlicensed" hoặc đang trong thời gian ân hạn thì Windows/Office chưa kích hoạt đầy đủ. Kênh key cho biết dạng license (OEM, Retail, Volume:MAK, hoặc Volume:GVLK cho máy client KMS).' }
        'ReinstallOEMCheckingNetwork' { return 'Đang kiểm tra kết nối mạng trước khi kích hoạt online...' }
        'ReinstallOEMOffline' { return 'Không phát hiện kết nối mạng nên đã bỏ qua kích hoạt online (slmgr /ato). Key OEM đã được cài; hãy nối mạng và chạy slmgr /ato sau để hoàn tất kích hoạt.' }
        'LicenseGenuineLabel' { return 'Kiểm tra Genuine (SLIsGenuineLocal)' }
        'GenuineUnavailable' { return 'Không khả dụng' }
        'OpenReportPrompt' { return 'Mở báo cáo?' }
        'OpenReportHtmlOption' { return '  1 = Mở báo cáo HTML' }
        'OpenReportFolderOption' { return '  2 = Mở thư mục báo cáo' }
        'OpenReportNoOption' { return '  0 = Không' }
        'OpenReportInput' { return 'Nhập lựa chọn' }
        'StepAssessCrack' { return 'Đánh giá dấu vết crack / can thiệp bản quyền Windows' }
        'AssessCrackMode' { return 'Đang chạy chế độ đánh giá crack/bản quyền chỉ đọc. Không dọn, không sửa gì; chỉ soi máy.' }
        'CompletedAssessment' { return "Hoàn tất lượt đánh giá crack/bản quyền (chỉ đọc) của $script:ToolName." }
        'AsmTitle' { return 'Đánh giá dấu vết crack / can thiệp bản quyền (chỉ đọc)' }
        'AsmVerdictHeading' { return 'KẾT LUẬN' }
        'AsmScoreLabel' { return 'Điểm rủi ro' }
        'AsmVerdictIncomplete' { return 'Lưu ý: có dữ liệu không đọc được nên đánh giá này có thể chưa đầy đủ.' }
        'AsmVerdictClean' { return 'Không phát hiện dấu vết crack. Dựa trên các mục kiểm tra ở trên, máy có vẻ chính hãng/sạch.' }
        'AsmVerdictSuspicious' { return 'NGHI NGỜ - chỉ thấy tín hiệu yếu. Chưa đủ kết luận; hãy xem lại các mục bị đánh dấu.' }
        'AsmVerdictLikely' { return 'NHIỀU KHẢ NĂNG đang dùng crack - có nhiều tín hiệu can thiệp.' }
        'AsmVerdictCracked' { return 'PHÁT HIỆN CRACK - có dấu vết crack/bẻ khóa kích hoạt rõ ràng.' }
        'AsmInstallDate' { return 'Ngày cài Windows' }
        'AsmActivationStatus' { return 'Trạng thái kích hoạt (WMI)' }
        'AsmKmsClientChannel' { return 'Key client KMS (GVLK)' }
        'AsmKmsHost' { return 'Cấu hình máy chủ KMS' }
        'AsmKms38' { return 'KMS38 (hạn 2038)' }
        'AsmKms38Signature' { return 'Hạn kích hoạt bị đặt xa bất thường' }
        'AsmTsforgeSignature' { return 'TSforge/KMS4k - hạn bị giả lên hàng nghìn năm' }
        'AsmLicenseBios' { return 'Kênh license đối chiếu OEM/BIOS' }
        'AsmHwid' { return 'HWID / digital license' }
        'AsmToolFolders' { return 'Thư mục/file tool lậu' }
        'AsmScheduledTasks' { return 'Tác vụ lịch lậu' }
        'AsmServices' { return 'Dịch vụ lậu' }
        'AsmPersistence' { return 'Tự khởi động (Run/Startup)' }
        'AsmServicesDisabled' { return 'Dịch vụ bảo vệ bị tắt' }
        'AsmRegistryTamper' { return 'Can thiệp Registry (chặn genuine)' }
        'AsmHostsFile' { return 'File hosts chặn kích hoạt' }
        'AsmOhook' { return 'Crack Office (Ohook)' }
        'AsmNoData' { return 'không có dữ liệu / không đọc được' }
        'AsmNotDetected' { return 'không phát hiện' }
        'AsmKmsLocalEmulator' { return 'localhost/emulator - dấu hiệu crack KMS mạnh' }
        'AsmKmsPrivate' { return 'IP nội bộ - có thể là KMS doanh nghiệp' }
        'AsmKmsPublic' { return 'máy chủ KMS công khai trên internet - gần như luôn là crack' }
        'AsmKmsKnownEmulator' { return 'máy chủ KMS lậu công khai đã biết - crack' }
        'AsmOemMatches' { return 'Entitlement OEM/BIOS khớp phiên bản' }
        'AsmOemMismatch' { return 'key OEM nhúng thuộc phiên bản khác' }
        'AsmNoOemKey' { return 'không có key OEM nhúng trong firmware' }
        'AsmHwidInconclusive' { return 'có digital license; không thể xác nhận HWID giả khi offline (chỉ tham khảo)' }
        'AsmHwidNoSignal' { return 'không có tín hiệu HWID cụ thể' }
        'AsmNextStep' { return 'Đây là bước chỉ đánh giá, không thay đổi gì. Nếu có dấu vết crack, dùng chức năng dọn (menu 2/4) để gỡ rồi cấp phép lại đúng cách cho máy. Một tín hiệu yếu đơn lẻ (ví dụ một khóa registry) chưa phải bằng chứng crack.' }
        'ReportAssessmentHeading' { return 'Đánh giá crack / bản quyền:' }
        'AsmColCheck' { return 'Hạng mục' }
        'AsmColEvidence' { return 'Bằng chứng' }
        'AsmColConfidence' { return 'Độ tin cậy' }
        'AsmGenuine' { return 'Tính chính hãng (SLIsGenuineLocal)' }
        'AsmGenuineUnavailable' { return 'không chạy được kiểm tra genuine' }
        'AsmGenuineGenuine' { return 'Windows báo CHÍNH HÃNG' }
        'AsmGenuineTampered' { return 'BỊ CAN THIỆP - kho license đã bị sửa (chữ ký crack)' }
        'AsmGenuineForged' { return 'máy báo Licensed nhưng genuine nói INVALID - kích hoạt giả kiểu HWID' }
        'AsmGenuineNotActivated' { return 'chưa kích hoạt (license không hợp lệ, nhưng không phải crack)' }
        'AsmGenuineOffline' { return 'không kiểm tra online được' }
        'AsmHwidForged' { return 'digital license, không có key OEM VÀ genuine không sạch - có thể là HWID giả' }
        'AsmConfidenceLabel' { return 'Độ tin cậy' }
        'AsmConfidenceHigh' { return 'Cao' }
        'AsmConfidenceMedium' { return 'Trung bình' }
        'AsmConfidenceLow' { return 'Thấp' }
        'AsmReasonsLabel' { return 'Lý do chính' }
        default { return $Key }
    }
}

function Get-DigitalLicenseNoteLines {
    [CmdletBinding()]
    param()

    if ($script:Language -eq 'en') {
        return @(
            'DIGITAL LICENSE / HWID NOTE:',
            'If this machine was activated through MAS HWID/Digital License, this tool can only clean',
            'local keys and local configuration. Microsoft server-side hardware entitlement may still',
            'reactivate Windows when online.',
            'This is not a tool error.'
        )
    }

    return @(
        'LƯU Ý VỀ DIGITAL LICENSE / HWID:',
        'Nếu máy từng được active bằng MAS dạng HWID/Digital License, công cụ chỉ có thể dọn key',
        'và cấu hình local trên máy. Digital license đã gắn với phần cứng trên server Microsoft',
        'có thể vẫn khiến Windows tự kích hoạt lại khi online.',
        'Đây không phải lỗi của công cụ.'
    )
}

function Get-OEMKeyNoteLines {
    [CmdletBinding()]
    param()

    if ($script:Language -eq 'en') {
        return @(
            'OEM MOTHERBOARD KEY NOTE:',
            'Some machines have a Windows OEM key embedded in BIOS/UEFI.',
            'This key usually matches only the original Windows edition shipped with the device,',
            'for example Home, Pro, or Home Single Language.',
            'OEM key reading is read-only. It does not activate Windows or modify the system.'
        )
    }

    return @(
        'LƯU Ý VỀ KEY OEM THEO MAIN:',
        'Một số máy có key Windows OEM được nhúng trong BIOS/UEFI.',
        'Key này thường chỉ dùng đúng phiên bản Windows gốc theo máy, ví dụ Home, Pro hoặc Home Single Language.',
        'Tính năng đọc key OEM chỉ đọc thông tin, không kích hoạt Windows và không thay đổi hệ thống.'
    )
}

function Write-NoteBlock {
    [CmdletBinding()]
    param(
        [string[]]$Lines
    )

    Write-Host ''
    foreach ($line in @($Lines)) {
        Write-Host $line -ForegroundColor Yellow
        if ($script:LogPath) {
            $logLine = '{0} [INFO] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $line
            try {
                Add-Content -LiteralPath $script:LogPath -Value $logLine -Encoding UTF8
            } catch {
                Write-Host "Failed to write log file: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}

function Read-ChoiceWithTimeout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter(Mandatory = $true)]
        [string[]]$ValidChoices,

        [Parameter(Mandatory = $true)]
        [string]$DefaultChoice,

        [int]$TimeoutSeconds = 10
    )

    Write-Host $Prompt -NoNewline
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                $value = [string]$key.KeyChar
                if ($ValidChoices -contains $value) {
                    Write-Host $value
                    return $value
                }
                if ($key.Key -eq [ConsoleKey]::Enter) {
                    Write-Host ''
                    return $DefaultChoice
                }
            }
        } catch {
            Write-Host ''
            return $DefaultChoice
        }
        Start-Sleep -Milliseconds 150
    }

    Write-Host ''
    return $DefaultChoice
}

function Sync-ReportParameterSnapshot {
    [CmdletBinding()]
    param()

    $script:DryRunMode = [bool]($DryRun -or $WhatIfPreference)
    $script:Report.DryRun = $script:DryRunMode
    $script:Report.Force = [bool]$Force
    $script:Report.Parameters.CreateRestorePoint = [bool]$CreateRestorePoint
    $script:Report.Parameters.SkipOffice = [bool]$SkipOffice
    $script:Report.Parameters.SkipWindows = [bool]$SkipWindows
    $script:Report.Parameters.SkipOhookCleanup = [bool]$SkipOhookCleanup
    $script:Report.Parameters.VerboseLog = [bool]$VerboseLog
    $script:Report.Parameters.ExportReport = [bool]$ExportReport
    $script:Report.Parameters.Force = [bool]$Force
    $script:Report.Parameters.NoRestartServices = [bool]$NoRestartServices
    $script:Report.Parameters.ForceWindowsProductKeyRemoval = [bool]$ForceWindowsProductKeyRemoval
    $script:Report.Parameters.InstallPostRebootSweep = [bool]$InstallPostRebootSweep
    $script:Report.Parameters.PostRebootSweep = [bool]$PostRebootSweep
    $script:Report.Parameters.ReadOEMKeyOnly = [bool]$ReadOEMKeyOnly
    $script:Report.Parameters.ShowFullKeys = [bool]$ShowFullKeys
    $script:Report.Parameters.ExportSensitiveKeys = [bool]$ExportSensitiveKeys
    $script:Report.Parameters.ReinstallOEMKey = [bool]$ReinstallOEMKey
    $script:Report.Parameters.SkipOEMActivation = [bool]$SkipOEMActivation
    $script:Report.Parameters.CheckLicenseOnly = [bool]$CheckLicenseOnly
    $script:Report.Parameters.AssessCrack = [bool]$AssessCrack
    $script:Report.Parameters.LauncherMenu = [bool]$LauncherMenu
    $script:Report.Parameters.Language = $script:Language
}

function Reset-LauncherRunOptions {
    [CmdletBinding()]
    param()

    foreach ($name in @(
        'DryRun',
        'CreateRestorePoint',
        'SkipOffice',
        'SkipWindows',
        'SkipOhookCleanup',
        'VerboseLog',
        'ExportReport',
        'Force',
        'NoRestartServices',
        'ForceWindowsProductKeyRemoval',
        'InstallPostRebootSweep',
        'PostRebootSweep',
        'ReadOEMKeyOnly',
        'ShowFullKeys',
        'ExportSensitiveKeys',
        'ReinstallOEMKey',
        'SkipOEMActivation',
        'CheckLicenseOnly',
        'AssessCrack'
    )) {
        Set-Variable -Name $name -Scope Script -Value $false
    }
}

function Set-LauncherRunOption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [bool]$Value = $true
    )

    Set-Variable -Name $Name -Scope Script -Value $Value
}

function Show-LauncherLanguageSelection {
    [CmdletBinding()]
    param()

    Clear-Host
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ("        {0} v{1}" -f $script:ToolName, $script:Version) -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Chọn ngôn ngữ / Select language:'
    Write-Host ''
    Write-Host '  1. Tiếng Việt'
    Write-Host '  2. English'
    Write-Host ''

    $choice = Read-ChoiceWithTimeout -Prompt 'Nhập lựa chọn [1-2], mặc định 1 sau 10 giây: ' -ValidChoices @('1', '2') -DefaultChoice '1' -TimeoutSeconds 10
    if ($choice -eq '2') {
        $script:Language = 'en'
    } else {
        $script:Language = 'vi'
    }
    Set-Variable -Name Language -Scope Script -Value $script:Language
}

function Show-LauncherMenuVI {
    [CmdletBinding()]
    param()

    Clear-Host
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ("        EasyActive by MyPC v{0}" -f $script:Version) -ForegroundColor Cyan
    Write-Host '  Dọn trạng thái kích hoạt Windows/Office' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Chọn tác vụ:'
    Write-Host ''
    Write-Host '1. Kiểm tra thử, không thay đổi hệ thống'
    Write-Host '2. Dọn cả Windows và Office'
    Write-Host '3. Chỉ dọn Office'
    Write-Host '4. Chỉ dọn Windows'
    Write-Host '5. Đọc key Windows OEM đi theo main / BIOS / UEFI'
    Write-Host '6. Kiểm tra trạng thái license / kích hoạt Windows và Office (chỉ đọc)'
    Write-Host '7. Đánh giá dấu vết crack / bản quyền Windows (chỉ đọc)'
    Write-Host '8. Mở thư mục log và báo cáo'
    Write-Host '0. Thoát'
    Write-Host ''
    Write-Host 'Giải thích nhanh:' -ForegroundColor Yellow
    Write-Host '1 = Chỉ quét và tạo báo cáo, không xóa/sửa gì.'
    Write-Host '2 = Dọn key/cấu hình kích hoạt cũ của cả Windows và Office.'
    Write-Host '3 = Chỉ dọn Office, không ảnh hưởng Windows.'
    Write-Host '4 = Chỉ dọn Windows, không ảnh hưởng Office.'
    Write-Host '5 = Chỉ đọc key OEM, không kích hoạt, không thay đổi máy.'
    Write-Host '6 = Chỉ xem Windows/Office đã kích hoạt hay chưa, dạng license gì. Không thay đổi máy.'
    Write-Host '7 = Soi dấu vết crack (KMS/MAS/KMS38/HWID, hosts, registry, tác vụ...) và cho kết luận. Không thay đổi máy.'
    Write-Host ''
}

function Show-LauncherMenuEN {
    [CmdletBinding()]
    param()

    Clear-Host
    Write-Host '================================================' -ForegroundColor Cyan
    Write-Host ("        EasyActive by MyPC v{0}" -f $script:Version) -ForegroundColor Cyan
    Write-Host '  Windows/Office activation cleanup' -ForegroundColor Cyan
    Write-Host '================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Choose a task:'
    Write-Host ''
    Write-Host '1. Dry-run only, no system changes'
    Write-Host '2. Clean both Windows and Office'
    Write-Host '3. Clean Office only'
    Write-Host '4. Clean Windows only'
    Write-Host '5. Read OEM embedded key from motherboard / BIOS / UEFI'
    Write-Host '6. Check Windows and Office license / activation status (read-only)'
    Write-Host '7. Assess Windows crack / license tampering traces (read-only)'
    Write-Host '8. Open logs and reports folder'
    Write-Host '0. Exit'
    Write-Host ''
}

function Confirm-OfficeAppsClosedFromLauncher {
    [CmdletBinding()]
    param()

    $officeProcessNames = @('WINWORD','EXCEL','POWERPNT','OUTLOOK','ONENOTE','MSACCESS','MSPUB','MSPROJECT','VISIO','GROOVE','LYNC','INFOPATH','OfficeClickToRun','c2rlicensing')
    $running = @($officeProcessNames | ForEach-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue } | Where-Object { $_ })

    Write-Host ''
    if ($running.Count -eq 0) {
        if ($script:Language -eq 'en') {
            Write-Host 'No Office processes detected. Continuing.' -ForegroundColor Green
        } else {
            Write-Host 'Không phát hiện tiến trình Office đang chạy. Tiếp tục.' -ForegroundColor Green
        }
        return $true
    }

    $runningNames = ($running | Select-Object -ExpandProperty Name -Unique) -join ', '
    if ($script:Language -eq 'en') {
        Write-Host 'NOTE:' -ForegroundColor Yellow
        Write-Host "The following Office processes are still running: $runningNames" -ForegroundColor Yellow
        Write-Host 'They must be closed before Ohook DLL cleanup can work.' -ForegroundColor Yellow
        Write-Host ''
        $answer = Read-Host 'Force-close all Office apps now? (Y = yes / N = back to menu)'
    } else {
        Write-Host 'LƯU Ý:' -ForegroundColor Yellow
        Write-Host "Các tiến trình Office đang chạy: $runningNames" -ForegroundColor Yellow
        Write-Host 'Cần đóng trước khi dọn DLL Ohook có thể hoạt động đúng.' -ForegroundColor Yellow
        Write-Host ''
        $answer = Read-Host 'Buộc đóng tất cả ứng dụng Office ngay? (Y = có / N = quay lại menu)'
    }

    if ($answer -notmatch '^(?i)y$') {
        return $false
    }

    foreach ($proc in $running) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        } catch {
            Write-Host "  Could not stop $($proc.Name): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Start-Sleep -Milliseconds 800
    return $true
}

function Confirm-WindowsKeyRemovalFromLauncher {
    [CmdletBinding()]
    param()

    Write-Host ''
    if ($script:Language -eq 'en') {
        Write-Host 'WARNING:' -ForegroundColor Yellow
        Write-Host 'This option may remove the Windows product key currently stored on this machine.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'After cleanup, if the machine does not have a valid Digital License or a new genuine key,' -ForegroundColor Yellow
        Write-Host 'Windows may show as not activated.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Continue only if you understand this action and have a valid key/account for reactivation.' -ForegroundColor Yellow
        Write-Host ''
        $answer = Read-Host 'Continue? (Y = continue / N = back to menu)'
    } else {
        Write-Host 'CẢNH BÁO:' -ForegroundColor Yellow
        Write-Host 'Tùy chọn này có thể gỡ product key Windows đang lưu trên máy.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Sau khi dọn, nếu máy không có Digital License hợp lệ hoặc chưa nhập key bản quyền mới,' -ForegroundColor Yellow
        Write-Host 'Windows có thể hiển thị trạng thái chưa kích hoạt.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Chỉ tiếp tục nếu bạn đã hiểu thao tác này và có key/tài khoản bản quyền hợp lệ để kích hoạt lại.' -ForegroundColor Yellow
        Write-Host ''
        $answer = Read-Host 'Tiếp tục? (Y = tiếp tục / N = quay lại menu)'
    }

    return ($answer -match '^(?i)y$')
}

function Confirm-ReinstallOEMKeyFromLauncher {
    [CmdletBinding()]
    param()

    Write-Host ''
    if ($script:Language -eq 'en') {
        Write-Host 'OEM KEY REINSTALL:' -ForegroundColor Cyan
        Write-Host 'After cleanup, the tool can automatically reinstall the genuine Windows OEM key' -ForegroundColor Gray
        Write-Host 'embedded in this machine BIOS/UEFI and activate it online, so you do not have to' -ForegroundColor Gray
        Write-Host 'read the log and type the key by hand.' -ForegroundColor Gray
        Write-Host ''
        Write-Host 'This only runs if the machine actually has an embedded OEM key that matches the' -ForegroundColor Gray
        Write-Host 'installed Windows edition. It is skipped otherwise.' -ForegroundColor Gray
        Write-Host ''
        $answer = Read-Host 'Auto-reinstall and activate the OEM key after cleanup? (Y/N)'
    } else {
        Write-Host 'CÀI LẠI KEY OEM:' -ForegroundColor Cyan
        Write-Host 'Sau khi dọn, công cụ có thể tự động cài lại key Windows OEM chính hãng nhúng trong' -ForegroundColor Gray
        Write-Host 'BIOS/UEFI của máy và kích hoạt online, để bạn không phải đọc log rồi nhập key thủ công.' -ForegroundColor Gray
        Write-Host ''
        Write-Host 'Chỉ chạy nếu máy thực sự có key OEM nhúng khớp với phiên bản Windows đang cài.' -ForegroundColor Gray
        Write-Host 'Nếu không có thì bước này được bỏ qua.' -ForegroundColor Gray
        Write-Host ''
        $answer = Read-Host 'Tự động cài lại và kích hoạt key OEM sau khi dọn? (Y/N)'
    }

    return ($answer -match '^(?i)y$')
}

function Open-LogFolderFromLauncher {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $script:ProgramDataRoot)) {
        New-Item -Path $script:ProgramDataRoot -ItemType Directory -Force | Out-Null
    }
    Start-Process -FilePath 'explorer.exe' -ArgumentList $script:ProgramDataRoot
}

function Invoke-LauncherMenu {
    [CmdletBinding()]
    param()

    Show-LauncherLanguageSelection

    while ($true) {
        if ($script:Language -eq 'en') {
            Show-LauncherMenuEN
            $choice = Read-Host 'Enter choice [0-8]'
        } else {
            Show-LauncherMenuVI
            $choice = Read-Host 'Nhập lựa chọn [0-8]'
        }

        Reset-LauncherRunOptions
        Set-LauncherRunOption -Name 'VerboseLog' -Value $true
        Set-LauncherRunOption -Name 'ExportReport' -Value $true

        switch ($choice) {
            '1' {
                Set-LauncherRunOption -Name 'DryRun'
                Set-LauncherRunOption -Name 'CreateRestorePoint'
                Sync-ReportParameterSnapshot
                return $true
            }
            '2' {
                if (-not (Confirm-OfficeAppsClosedFromLauncher)) { continue }
                if (-not (Confirm-WindowsKeyRemovalFromLauncher)) { continue }
                Set-LauncherRunOption -Name 'CreateRestorePoint'
                Set-LauncherRunOption -Name 'ForceWindowsProductKeyRemoval'
                if (Confirm-ReinstallOEMKeyFromLauncher) {
                    Set-LauncherRunOption -Name 'ReinstallOEMKey'
                }
                Sync-ReportParameterSnapshot
                return $true
            }
            '3' {
                if (-not (Confirm-OfficeAppsClosedFromLauncher)) { continue }
                Set-LauncherRunOption -Name 'CreateRestorePoint'
                Set-LauncherRunOption -Name 'SkipWindows'
                Sync-ReportParameterSnapshot
                return $true
            }
            '4' {
                if (-not (Confirm-WindowsKeyRemovalFromLauncher)) { continue }
                Set-LauncherRunOption -Name 'CreateRestorePoint'
                Set-LauncherRunOption -Name 'SkipOffice'
                Set-LauncherRunOption -Name 'ForceWindowsProductKeyRemoval'
                if (Confirm-ReinstallOEMKeyFromLauncher) {
                    Set-LauncherRunOption -Name 'ReinstallOEMKey'
                }
                Sync-ReportParameterSnapshot
                return $true
            }
            '5' {
                Set-LauncherRunOption -Name 'ReadOEMKeyOnly'
                Sync-ReportParameterSnapshot
                return $true
            }
            '6' {
                Set-LauncherRunOption -Name 'CheckLicenseOnly'
                Sync-ReportParameterSnapshot
                return $true
            }
            '7' {
                Set-LauncherRunOption -Name 'AssessCrack'
                Sync-ReportParameterSnapshot
                return $true
            }
            '8' {
                Open-LogFolderFromLauncher
                continue
            }
            '0' {
                return $false
            }
            default {
                if ($script:Language -eq 'en') {
                    Write-Host 'Invalid choice.' -ForegroundColor Yellow
                } else {
                    Write-Host 'Lựa chọn không hợp lệ.' -ForegroundColor Yellow
                }
                Start-Sleep -Seconds 1
            }
        }
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

    $message = Get-UiText -Key 'OfficeCloseWarning'
    Write-Host ''
    Write-Host $message -ForegroundColor Yellow
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
        [switch]$AllowFailure,

        # Values listed here (for example a raw product key) are replaced with a
        # masked form in everything that is logged, reported, or returned, while
        # the real value is still passed to the external process.
        [string[]]$RedactArguments = @()
    )

    $redactMap = @{}
    foreach ($secret in @($RedactArguments)) {
        if (-not [string]::IsNullOrWhiteSpace($secret) -and -not $redactMap.ContainsKey($secret)) {
            $masked = Mask-ProductKey -ProductKey $secret
            if ([string]::IsNullOrWhiteSpace($masked)) { $masked = '***REDACTED***' }
            $redactMap[$secret] = $masked
        }
    }

    $quotedArgs = @($Arguments | ForEach-Object {
        $display = $_
        if ($redactMap.ContainsKey($display)) { $display = $redactMap[$display] }
        if ($display -match '\s') { '"{0}"' -f $display } else { $display }
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
        $lines = @($output | ForEach-Object {
            $text = $_.ToString()
            foreach ($secret in $redactMap.Keys) {
                $text = $text.Replace($secret, $redactMap[$secret])
            }
            $text
        })
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
        Checkpoint-Computer -Description ("EasyActiveByMyPC {0}" -f $script:RunId) -RestorePointType 'MODIFY_SETTINGS'
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
        if ($Force) {
            Write-Log -Message "Registry backup failed but -Force specified; continuing without backup: $KeyPath" -Level 'WARN'
        } else {
            Write-Log -Message "Skipping registry value cleanup because backup failed: $KeyPath" -Level 'WARN'
            return
        }
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
        if ($Force) {
            Write-Log -Message "Registry backup failed but -Force specified; continuing without backup: $KeyPath" -Level 'WARN'
        } else {
            Write-Log -Message "Skipping registry key removal because backup failed: $KeyPath" -Level 'WARN'
            return
        }
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

function Get-WindowsLicenseExpiry {
    [CmdletBinding()]
    param()

    $slmgr = Join-Path $env:SystemRoot 'System32\slmgr.vbs'
    $cscript = Join-Path $env:SystemRoot 'System32\cscript.exe'
    if (-not (Test-Path -LiteralPath $slmgr)) {
        return $null
    }

    $result = Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $slmgr, '/xpr') -Description 'Read Windows activation expiry with slmgr /xpr' -Category 'WindowsLicensing' -Target 'slmgr /xpr' -ReadOnly -AllowFailure
    $lines = @($result.Output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
    if ($lines.Count -eq 0) {
        return $null
    }
    return ($lines -join ' ')
}

function Test-InternetConnectivity {
    [CmdletBinding()]
    param(
        [string[]]$TargetHosts = @('www.microsoft.com', 'login.live.com'),
        [int]$Port = 443,
        [int]$TimeoutMs = 3000
    )

    foreach ($targetHost in $TargetHosts) {
        $client = $null
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect($targetHost, $Port, $null, $null)
            $waited = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            if ($waited -and $client.Connected) {
                $client.EndConnect($async)
                return $true
            }
        } catch {
            # Try the next host.
        } finally {
            if ($client) {
                try { $client.Close() } catch { }
            }
        }
    }
    return $false
}

function Get-WindowsGenuineStatus {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        Available = $false
        State = $null
        StateText = 'Unknown'
        Hresult = $null
    }

    $stateMap = @{
        0 = 'Genuine'
        1 = 'Invalid license'
        2 = 'Tampered'
        3 = 'Offline (could not verify)'
    }

    try {
        if (-not ([System.Management.Automation.PSTypeName]'EasyActiveByMyPC.GenuineCheck').Type) {
            $code = @'
using System;
using System.Runtime.InteropServices;
namespace EasyActiveByMyPC {
    public static class GenuineCheck {
        [DllImport("slc.dll", CharSet = CharSet.Unicode)]
        private static extern int SLIsGenuineLocal(ref Guid pAppId, ref int pGenuineState, IntPtr pUIOptions);
        public static int Check(out int state) {
            Guid appId = new Guid("55c92734-d682-4d71-983e-d6ec3f16059f");
            state = -1;
            return SLIsGenuineLocal(ref appId, ref state, IntPtr.Zero);
        }
    }
}
'@
            Add-Type -TypeDefinition $code -ErrorAction Stop
        }

        $state = -1
        $hr = [EasyActiveByMyPC.GenuineCheck]::Check([ref]$state)
        $result.Available = $true
        $result.Hresult = ('0x{0:X8}' -f $hr)
        $result.State = $state
        if ($hr -eq 0) {
            $result.StateText = if ($stateMap.ContainsKey([int]$state)) { $stateMap[[int]$state] } else { 'Unknown' }
        } else {
            $result.StateText = ('Check failed (HRESULT 0x{0:X8})' -f $hr)
        }
    } catch {
        Write-Log -Message "SLIsGenuineLocal genuine check unavailable: $($_.Exception.Message)" -Level 'INFO'
        $result.Available = $false
        $reason = [string]$_.Exception.Message
        if ($reason.Length -gt 80) { $reason = $reason.Substring(0, 80) + '...' }
        $result.StateText = if ([string]::IsNullOrWhiteSpace($reason)) { (Get-UiText -Key 'GenuineUnavailable') } else { ('{0}: {1}' -f (Get-UiText -Key 'GenuineUnavailable'), $reason) }
    }

    return [pscustomobject]$result
}

function Mask-ProductKey {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$ProductKey
    )

    if ([string]::IsNullOrWhiteSpace($ProductKey)) {
        return $null
    }

    $clean = (($ProductKey.Trim()) -replace '[^A-Za-z0-9]', '').ToUpperInvariant()
    if ($clean.Length -lt 5) {
        return 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'
    }

    $lastFive = $clean.Substring($clean.Length - 5, 5)
    return ('XXXXX-XXXXX-XXXXX-XXXXX-{0}' -f $lastFive)
}

function Convert-KeyDescriptionToEdition {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$KeyDescription
    )

    if ([string]::IsNullOrWhiteSpace($KeyDescription)) {
        return 'Unknown'
    }

    $text = $KeyDescription.Trim()

    if ($text -match '(?i)\bServer\b') {
        return 'Windows Server'
    }
    if ($text -match '(?i)CoreSingleLanguage') {
        return 'Windows Home Single Language'
    }
    if ($text -match '(?i)CoreCountrySpecific') {
        return 'Windows Home China'
    }
    if ($text -match '(?i)\bEducation\b') {
        return 'Windows Education'
    }
    if ($text -match '(?i)\bEnterprise\b|EnterpriseS') {
        return 'Windows Enterprise'
    }
    if ($text -match '(?i)\bProfessional(?:N)?\b') {
        return 'Windows Pro'
    }
    if ($text -match '(?i)\bCore(?:N)?\b') {
        return 'Windows Home'
    }

    return 'Unknown'
}

function Get-CurrentWindowsEdition {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        FriendlyName = 'Unknown'
        DismEditionID = $null
        ProductName = $null
        EditionID = $null
        DisplayVersion = $null
        CurrentBuild = $null
        Source = $null
        Notes = New-Object System.Collections.ArrayList
    }

    $dism = Join-Path $env:SystemRoot 'System32\dism.exe'
    if (Test-Path -LiteralPath $dism) {
        $dismResult = Invoke-ExternalCommandSafe -FilePath $dism -Arguments @('/Online', '/Get-CurrentEdition', '/English') -Description 'Read current Windows edition with DISM' -Category 'WindowsEdition' -Target 'DISM /Online /Get-CurrentEdition' -ReadOnly -AllowFailure
        if ($dismResult.ExitCode -eq 0) {
            foreach ($line in @($dismResult.Output)) {
                if ($line -match '^\s*Current Edition\s*:\s*(.+?)\s*$') {
                    $result.DismEditionID = $Matches[1].Trim()
                    $result.Source = 'DISM'
                    break
                }
            }
        } else {
            $null = $result.Notes.Add('DISM current edition query failed; registry fallback used if available.')
        }
    } else {
        $null = $result.Notes.Add('DISM was not found; registry fallback used if available.')
    }

    try {
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.PSObject.Properties.Name -contains 'ProductName') {
            $result.ProductName = $cv.ProductName
        }
        if ($cv.PSObject.Properties.Name -contains 'EditionID') {
            $result.EditionID = $cv.EditionID
        }
        if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') {
            $result.DisplayVersion = $cv.DisplayVersion
        } elseif ($cv.PSObject.Properties.Name -contains 'ReleaseId') {
            $result.DisplayVersion = $cv.ReleaseId
        }
        if ($cv.PSObject.Properties.Name -contains 'CurrentBuild') {
            $result.CurrentBuild = $cv.CurrentBuild
        }
        if (-not $result.Source) {
            $result.Source = 'Registry'
        }
    } catch {
        $null = $result.Notes.Add("Unable to read Windows CurrentVersion registry: $($_.Exception.Message)")
        Write-Log -Message "Unable to read current Windows edition from registry: $($_.Exception.Message)" -Level 'WARN'
    }

    if (-not [string]::IsNullOrWhiteSpace($result.ProductName)) {
        $result.FriendlyName = $result.ProductName
    } elseif (-not [string]::IsNullOrWhiteSpace($result.DismEditionID)) {
        $result.FriendlyName = $result.DismEditionID
    } elseif (-not [string]::IsNullOrWhiteSpace($result.EditionID)) {
        $result.FriendlyName = $result.EditionID
    }

    $details = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($result.EditionID)) {
        $null = $details.Add("EditionID: $($result.EditionID)")
    }
    if (-not [string]::IsNullOrWhiteSpace($result.DismEditionID)) {
        $null = $details.Add("DISM: $($result.DismEditionID)")
    }
    if (-not [string]::IsNullOrWhiteSpace($result.DisplayVersion)) {
        $null = $details.Add("Version: $($result.DisplayVersion)")
    }
    if (-not [string]::IsNullOrWhiteSpace($result.CurrentBuild)) {
        $null = $details.Add("Build: $($result.CurrentBuild)")
    }
    if ($details.Count -gt 0) {
        $result.FriendlyName = ('{0} ({1})' -f $result.FriendlyName, ($details -join ', '))
    }

    return [pscustomobject]$result
}

function Convert-EditionTextToCompatibilityGroup {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$EditionText
    )

    if ([string]::IsNullOrWhiteSpace($EditionText)) {
        return 'Unknown'
    }

    $text = $EditionText.Trim()

    if ($text -match '(?i)\bServer\b') { return 'Server' }
    if ($text -match '(?i)Single\s*Language|CoreSingleLanguage') { return 'HomeSingleLanguage' }
    if ($text -match '(?i)CoreCountrySpecific|China') { return 'HomeChina' }
    if ($text -match '(?i)\bEducation\b') { return 'Education' }
    if ($text -match '(?i)\bEnterprise\b|EnterpriseS') { return 'Enterprise' }
    if ($text -match '(?i)Workstation') { return 'ProWorkstation' }
    if ($text -match '(?i)\bProfessional(?:N)?\b|\bPro(?:N)?\b') { return 'Pro' }
    if ($text -match '(?i)\bCore(?:N)?\b|\bHome(?:N)?\b') { return 'Home' }

    return 'Unknown'
}

function Test-OEMKeyEditionCompatibility {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$DetectedKeyEdition,

        [AllowNull()]
        [object]$CurrentWindowsEdition
    )

    $currentText = $null
    if ($CurrentWindowsEdition -is [string]) {
        $currentText = $CurrentWindowsEdition
    } elseif ($null -ne $CurrentWindowsEdition) {
        $parts = New-Object System.Collections.ArrayList
        foreach ($name in @('FriendlyName', 'ProductName', 'EditionID', 'DismEditionID')) {
            if ($CurrentWindowsEdition.PSObject.Properties.Name -contains $name) {
                $value = $CurrentWindowsEdition.$name
                if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                    $null = $parts.Add([string]$value)
                }
            }
        }
        $currentText = ($parts -join ' ')
    }

    $keyGroup = Convert-EditionTextToCompatibilityGroup -EditionText $DetectedKeyEdition
    $currentGroup = Convert-EditionTextToCompatibilityGroup -EditionText $currentText

    if ($keyGroup -eq 'Unknown' -or $currentGroup -eq 'Unknown') {
        return 'Unknown'
    }

    if ($keyGroup -eq $currentGroup) {
        return 'Compatible'
    }

    return 'Not compatible'
}

function Get-OEMEmbeddedProductKey {
    [CmdletBinding()]
    param()

    $service = $null
    $source = $null
    $notes = New-Object System.Collections.ArrayList

    try {
        $service = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
        $source = 'CIM'
    } catch {
        $message = "Get-CimInstance SoftwareLicensingService failed; trying WMI fallback. $($_.Exception.Message)"
        Write-Log -Message $message -Level 'VERBOSE'
        $null = $notes.Add('CIM query failed; WMI fallback was attempted.')
    }

    if (-not $service) {
        try {
            $service = Get-WmiObject -Class SoftwareLicensingService -ErrorAction Stop
            $source = 'WMI'
        } catch {
            $message = "Unable to read SoftwareLicensingService through CIM or WMI: $($_.Exception.Message)"
            Write-Log -Message $message -Level 'WARN'
            $null = $notes.Add($message)
        }
    }

    $key = $null
    $description = $null
    if ($service) {
        if ($service.PSObject.Properties.Name -contains 'OA3xOriginalProductKey') {
            $key = [string]$service.OA3xOriginalProductKey
        }
        if ($service.PSObject.Properties.Name -contains 'OA3xOriginalProductKeyDescription') {
            $description = [string]$service.OA3xOriginalProductKeyDescription
        }
    }

    $currentEdition = Get-CurrentWindowsEdition
    $detectedEdition = Convert-KeyDescriptionToEdition -KeyDescription $description
    $compatibility = Test-OEMKeyEditionCompatibility -DetectedKeyEdition $detectedEdition -CurrentWindowsEdition $currentEdition
    $keyFound = -not [string]::IsNullOrWhiteSpace($key)
    $maskedKey = Mask-ProductKey -ProductKey $key

    if (-not $keyFound) {
        $maskedKey = $null
        $detectedEdition = 'Unknown'
        $compatibility = 'Unknown'
        $null = $notes.Add((Get-UiText -Key 'OEMNoKey'))
    }

    if ([string]::IsNullOrWhiteSpace($description)) {
        $null = $notes.Add('OA3xOriginalProductKeyDescription was empty or unavailable.')
    }
    if ($compatibility -eq 'Unknown') {
        $null = $notes.Add('Edition compatibility could not be determined confidently.')
    } elseif ($compatibility -eq 'Not compatible') {
        $null = $notes.Add('The embedded OEM key appears to target a different Windows edition. Automatic edition switching was not attempted.')
    }
    if ($source) {
        $null = $notes.Add("SoftwareLicensingService source: $source.")
    }

    $info = [ordered]@{
        KeyFound = [bool]$keyFound
        MaskedKey = $maskedKey
        KeyDescription = $description
        DetectedKeyEdition = $detectedEdition
        CurrentWindowsEdition = $currentEdition.FriendlyName
        Compatibility = $compatibility
        Notes = $notes
    }

    if ($ExportSensitiveKeys -and $keyFound) {
        $info['FullKey'] = $key
    }

    $script:Report.OEMEmbeddedKeyInfo = $info
    $script:Report.OEMEmbeddedKeyChecked = $true

    Write-NoteBlock -Lines (Get-OEMKeyNoteLines)
    Write-Host ''
    Write-Host (Get-UiText -Key 'OEMTitle') -ForegroundColor Cyan
    if (-not $keyFound) {
        Write-Host (Get-UiText -Key 'OEMNoKey') -ForegroundColor Yellow
        Write-Log -Message (Get-UiText -Key 'OEMNoKey') -Level 'INFO'
    } else {
        if ($ExportSensitiveKeys) {
            Write-Host (Get-UiText -Key 'SensitiveExportWarning') -ForegroundColor Yellow
            Write-Log -Message (Get-UiText -Key 'SensitiveExportWarning') -Level 'INFO'
        }

        if ($ShowFullKeys) {
            Write-Host ("{0}: {1}" -f (Get-UiText -Key 'ProductKeyLabel'), $key) -ForegroundColor Yellow
            Write-Log -Message ("OEM embedded product key found: {0}. Full key was shown on console only." -f $maskedKey) -Level 'INFO'
        } else {
            Write-Host ("{0}: {1}" -f (Get-UiText -Key 'ProductKeyLabel'), $maskedKey) -ForegroundColor Gray
            Write-Log -Message ("OEM embedded product key found: {0}" -f $maskedKey) -Level 'INFO'
        }
    }

    Write-Host ("{0}: {1}" -f (Get-UiText -Key 'KeyDescriptionLabel'), $(if ([string]::IsNullOrWhiteSpace($description)) { Get-UiText -Key 'Unknown' } else { $description })) -ForegroundColor Gray
    Write-Host ("{0}: {1}" -f (Get-UiText -Key 'DetectedKeyEditionLabel'), $detectedEdition) -ForegroundColor Gray
    Write-Host ("{0}: {1}" -f (Get-UiText -Key 'CurrentWindowsEditionLabel'), $currentEdition.FriendlyName) -ForegroundColor Gray
    Write-Host ("{0}: {1}" -f (Get-UiText -Key 'CompatibilityLabel'), $compatibility) -ForegroundColor Gray

    foreach ($note in @($notes)) {
        Write-Log -Message ("OEM key note: {0}" -f $note) -Level 'INFO'
    }

    Add-ReportAction -Category 'OEMEmbeddedKey' -Action 'Read OEM embedded Windows product key' -Target 'SoftwareLicensingService.OA3xOriginalProductKey' -Status 'Done' -Detail ('KeyFound={0}; Compatibility={1}' -f $keyFound, $compatibility) -Data ([pscustomobject]@{
        KeyFound = $keyFound
        MaskedKey = $maskedKey
        KeyDescription = $description
        DetectedKeyEdition = $detectedEdition
        CurrentWindowsEdition = $currentEdition.FriendlyName
        Compatibility = $compatibility
    })

    # The returned object always carries the raw key so a caller (for example the
    # OEM reinstall step) can use it in memory. This object is never serialized to
    # disk; only $script:Report.OEMEmbeddedKeyInfo above is persisted, and that
    # keeps the full key out unless -ExportSensitiveKeys was requested.
    return [pscustomobject]@{
        KeyFound = [bool]$keyFound
        FullKey = $key
        MaskedKey = $maskedKey
        KeyDescription = $description
        DetectedKeyEdition = $detectedEdition
        CurrentWindowsEdition = $currentEdition.FriendlyName
        Compatibility = $compatibility
        Notes = $notes
    }
}

function Install-OEMEmbeddedProductKey {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$OEMInfo
    )

    $reinstall = $script:Report.OEMKeyReinstall
    $reinstall.Requested = $true

    Write-Host ''
    Write-Host (Get-UiText -Key 'ReinstallOEMTitle') -ForegroundColor Cyan
    Write-Log -Message (Get-UiText -Key 'ReinstallOEMTitle') -Level 'INFO'

    # Read the OEM key now if the caller did not already provide it.
    if ($null -eq $OEMInfo) {
        $OEMInfo = Get-OEMEmbeddedProductKey
    }

    $keyFound = $false
    $fullKey = $null
    $compatibility = 'Unknown'
    $maskedKey = $null
    if ($null -ne $OEMInfo) {
        if ($OEMInfo.PSObject.Properties.Name -contains 'KeyFound') { $keyFound = [bool]$OEMInfo.KeyFound }
        if ($OEMInfo.PSObject.Properties.Name -contains 'FullKey') { $fullKey = [string]$OEMInfo.FullKey }
        if ($OEMInfo.PSObject.Properties.Name -contains 'Compatibility') { $compatibility = [string]$OEMInfo.Compatibility }
        if ($OEMInfo.PSObject.Properties.Name -contains 'MaskedKey') { $maskedKey = [string]$OEMInfo.MaskedKey }
    }

    $reinstall.KeyFound = $keyFound
    $reinstall.Compatibility = $compatibility
    $reinstall.MaskedKey = $maskedKey

    if (-not $keyFound -or [string]::IsNullOrWhiteSpace($fullKey)) {
        $msg = Get-UiText -Key 'ReinstallOEMNoKey'
        Write-Host $msg -ForegroundColor Yellow
        Write-Log -Message $msg -Level 'INFO'
        $reinstall.InstallStatus = 'NoKey'
        $null = $reinstall.Notes.Add($msg)
        Add-ReportAction -Category 'OEMKeyReinstall' -Action 'Reinstall OEM embedded key' -Target 'slmgr /ipk' -Status 'Skipped' -Detail 'No OEM embedded key was available.' -Data $null
        return
    }

    # An embedded OEM key that targets a different Windows edition will always be
    # rejected by slmgr /ipk, so skip it by default and only try under -Force.
    if ($compatibility -eq 'Not compatible' -and -not $Force) {
        $msg = Get-UiText -Key 'ReinstallOEMNotCompatible'
        Write-Host $msg -ForegroundColor Yellow
        Write-Log -Message $msg -Level 'WARN'
        $reinstall.InstallStatus = 'SkippedNotCompatible'
        $null = $reinstall.Notes.Add($msg)
        Add-ReportAction -Category 'OEMKeyReinstall' -Action 'Reinstall OEM embedded key' -Target 'slmgr /ipk' -Status 'Skipped' -Detail 'Embedded OEM key targets a different Windows edition; use -Force to override.' -Data ([pscustomobject]@{ Compatibility = $compatibility })
        return
    }

    $slmgr = Join-Path $env:SystemRoot 'System32\slmgr.vbs'
    $cscript = Join-Path $env:SystemRoot 'System32\cscript.exe'
    if (-not (Test-Path -LiteralPath $slmgr)) {
        Write-Log -Message "slmgr.vbs not found: $slmgr" -Level 'WARN'
        $reinstall.InstallStatus = 'ToolMissing'
        $null = $reinstall.Notes.Add('slmgr.vbs was not found.')
        return
    }

    $reinstall.Attempted = $true
    Write-Host (Get-UiText -Key 'ReinstallOEMInstalling') -ForegroundColor Gray
    Write-Log -Message (Get-UiText -Key 'ReinstallOEMInstalling') -Level 'INFO'

    # The raw key is passed to slmgr but redacted from the log, report, and output.
    $ipk = Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $slmgr, '/ipk', $fullKey) -Description 'Install OEM embedded Windows product key with slmgr /ipk' -Category 'WindowsLicensing' -Target 'slmgr /ipk (OEM embedded key)' -AllowFailure -RedactArguments @($fullKey)

    if ($ipk.SkippedDryRun) {
        $msg = Get-UiText -Key 'ReinstallOEMWouldRun'
        Write-Host $msg -ForegroundColor Yellow
        Write-Log -Message $msg -Level 'INFO'
        $reinstall.InstallStatus = 'WouldInstall'
        $reinstall.ActivationStatus = 'WouldActivate'
        $null = $reinstall.Notes.Add($msg)
        return
    }

    $reinstall.InstallExitCode = $ipk.ExitCode
    $ipkLooksError = ((@($ipk.Output) -join ' ') -match '0x[0-9A-Fa-f]{8}')
    $installOk = ($ipk.ExitCode -eq 0) -and -not $ipkLooksError

    if (-not $installOk) {
        $msg = Get-UiText -Key 'ReinstallOEMInstallFailed'
        Write-Host $msg -ForegroundColor Yellow
        Write-Log -Message $msg -Level 'WARN'
        $reinstall.InstallStatus = 'Failed'
        $null = $reinstall.Notes.Add($msg)
        return
    }

    $msg = Get-UiText -Key 'ReinstallOEMInstalled'
    Write-Host $msg -ForegroundColor Green
    Write-Log -Message $msg -Level 'SUCCESS'
    $reinstall.InstallStatus = 'Installed'
    $null = $reinstall.Notes.Add($msg)

    if ($SkipOEMActivation) {
        $msg = Get-UiText -Key 'ReinstallOEMSkippedActivation'
        Write-Host $msg -ForegroundColor Yellow
        Write-Log -Message $msg -Level 'INFO'
        $reinstall.ActivationStatus = 'Skipped'
        $null = $reinstall.Notes.Add($msg)
        return
    }

    Write-Host (Get-UiText -Key 'ReinstallOEMCheckingNetwork') -ForegroundColor Gray
    Write-Log -Message (Get-UiText -Key 'ReinstallOEMCheckingNetwork') -Level 'INFO'
    if (-not (Test-InternetConnectivity)) {
        $msg = Get-UiText -Key 'ReinstallOEMOffline'
        Write-Host $msg -ForegroundColor Yellow
        Write-Log -Message $msg -Level 'WARN'
        $reinstall.ActivationStatus = 'SkippedOffline'
        $null = $reinstall.Notes.Add($msg)
    } else {
        $reinstall.ActivationRequested = $true
        Write-Host (Get-UiText -Key 'ReinstallOEMActivating') -ForegroundColor Gray
        Write-Log -Message (Get-UiText -Key 'ReinstallOEMActivating') -Level 'INFO'

        $ato = Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $slmgr, '/ato') -Description 'Activate Windows online with slmgr /ato' -Category 'WindowsLicensing' -Target 'slmgr /ato' -AllowFailure
        $reinstall.ActivationExitCode = $ato.ExitCode
        $atoLooksError = ((@($ato.Output) -join ' ') -match '0x[0-9A-Fa-f]{8}')
        $activateOk = ($ato.ExitCode -eq 0) -and -not $atoLooksError

        if ($activateOk) {
            $msg = Get-UiText -Key 'ReinstallOEMActivated'
            Write-Host $msg -ForegroundColor Green
            Write-Log -Message $msg -Level 'SUCCESS'
            $reinstall.ActivationStatus = 'Activated'
            $null = $reinstall.Notes.Add($msg)
        } else {
            $msg = Get-UiText -Key 'ReinstallOEMActivateFailed'
            Write-Host $msg -ForegroundColor Yellow
            Write-Log -Message $msg -Level 'WARN'
            $reinstall.ActivationStatus = 'ActivationFailed'
            $null = $reinstall.Notes.Add($msg)
        }
    }

    # Read-only verification of the resulting license state.
    Invoke-ExternalCommandSafe -FilePath $cscript -Arguments @('//NoLogo', $slmgr, '/dlv') -Description 'Show Windows license status with slmgr /dlv' -Category 'WindowsLicensing' -Target 'slmgr /dlv' -ReadOnly -AllowFailure | Out-Null
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
    $keywords = $script:MASCrackSignatures

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
            if ($item.Name.IndexOf('.EasyActiveByMyPC.', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
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

    $highConfidence = $script:MASCrackSignatures

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

    $keywords = $script:MASCrackSignatures

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
    if ($item.Name.IndexOf('.EasyActiveByMyPC.', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Write-Log -Message "Skipping prior EasyActiveByMyPC backup artifact: $Path" -Level 'VERBOSE'
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

function Remove-GenuineBlockingRegistry {
    [CmdletBinding()]
    param()

    Write-Log -Message 'Checking for genuine-blocking registry tweaks (NoGenTicket / NoAcquireGT).' -Level 'INFO'
    # These policy values suppress Windows genuine-ticket generation; crack tools add them.
    # Removing them restores the machine ability to validate genuinely. Exact key varies by
    # build, so all plausible locations are checked; Remove-RegistryValuesSafe skips absent ones.
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
    )
    foreach ($p in $paths) {
        Remove-RegistryValuesSafe -KeyPath $p -ValueNames @('NoGenTicket', 'NoAcquireGT') -Category 'GenuineBlockRegistry'
    }
}

function Restore-DisabledLicensingServices {
    [CmdletBinding()]
    param()

    Write-Log -Message 'Checking protection services for a disabled (crack-tampered) start type.' -Level 'INFO'
    # Default start types: sppsvc = Manual(3), ClipSVC = Manual(3), osppsvc = Manual(3).
    # Only services that are currently Disabled (Start=4) are restored; healthy machines are untouched.
    $services = @(
        [pscustomobject]@{ Name = 'sppsvc'; Default = 3 },
        [pscustomobject]@{ Name = 'ClipSVC'; Default = 3 },
        [pscustomobject]@{ Name = 'osppsvc'; Default = 3 }
    )

    foreach ($svc in $services) {
        $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        if (-not (Test-Path -LiteralPath $keyPath)) {
            Write-Log -Message "Service not present, skipped: $($svc.Name)" -Level 'VERBOSE'
            continue
        }

        $start = $null
        try {
            $start = (Get-ItemProperty -LiteralPath $keyPath -Name 'Start' -ErrorAction Stop).'Start'
        } catch {
            Write-Log -Message "Could not read Start type for $($svc.Name): $($_.Exception.Message)" -Level 'WARN'
            continue
        }
        if ($null -eq $start -or [int]$start -ne 4) {
            Write-Log -Message "Service $($svc.Name) is not disabled; no change needed." -Level 'VERBOSE'
            continue
        }

        $backup = Export-RegistryKeySafe -RegistryPath $keyPath -Reason "Backup before re-enabling $($svc.Name)"
        if (-not $script:DryRunMode -and -not $backup) {
            if ($Force) {
                Write-Log -Message "Registry backup failed but -Force specified; continuing: $($svc.Name)" -Level 'WARN'
            } else {
                Write-Log -Message "Skipping service restore because backup failed: $($svc.Name)" -Level 'WARN'
                continue
            }
        }

        $svcName = [string]$svc.Name
        $defaultStart = [int]$svc.Default
        $localKeyPath = $keyPath
        $data = [pscustomobject]@{ Service = $svcName; FromStart = 4; ToStart = $defaultStart; Backup = $backup }
        Invoke-SafeAction -Description "Re-enable protection service $svcName (Start 4 -> $defaultStart)" -Category 'ServiceRestore' -Target $svcName -Data $data -Action {
            Set-ItemProperty -LiteralPath $localKeyPath -Name 'Start' -Value $defaultStart -Type DWord -ErrorAction Stop
        } | Out-Null

        Add-ReportListItem -ListName 'ServicesReEnabled' -Item $data
    }
}

function Remove-HostsActivationBlocks {
    [CmdletBinding()]
    param()

    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hostsPath)) {
        Write-Log -Message 'Hosts file not found; nothing to clean.' -Level 'VERBOSE'
        return
    }

    $activationDomains = $script:MASActivationHostDomains

    $lines = $null
    try {
        $lines = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)
    } catch {
        Write-Log -Message "Could not read hosts file: $($_.Exception.Message)" -Level 'WARN'
        return
    }

    $removed = New-Object System.Collections.ArrayList
    $kept = New-Object System.Collections.ArrayList
    foreach ($raw in $lines) {
        $line = [string]$raw
        $trimmed = $line.Trim()
        $isBlock = $false
        if (-not [string]::IsNullOrWhiteSpace($trimmed) -and -not $trimmed.StartsWith('#')) {
            $parts = $trimmed -split '\s+'
            if ($parts.Count -ge 2 -and ($parts[0] -match '^(0\.0\.0\.0|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::)')) {
                for ($i = 1; $i -lt $parts.Count; $i++) {
                    $hostName = $parts[$i]
                    if ($hostName.StartsWith('#')) { break }
                    foreach ($domain in $activationDomains) {
                        if ($hostName.IndexOf($domain, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $isBlock = $true
                            break
                        }
                    }
                    if ($isBlock) { break }
                }
            }
        }
        if ($isBlock) { $null = $removed.Add($line) } else { $null = $kept.Add($line) }
    }

    if ($removed.Count -eq 0) {
        Write-Log -Message 'No Microsoft-activation-blocking entries found in hosts file.' -Level 'INFO'
        return
    }

    $backupPath = Join-Path $script:BackupRoot ('hosts-{0}.bak' -f $script:RunId)
    if ($script:DryRunMode) {
        foreach ($r in $removed) {
            Write-Log -Message "Would remove hosts entry: $r" -Level 'INFO'
            Add-ReportAction -Category 'HostsCleanup' -Action 'Remove hosts activation block' -Target ([string]$r).Trim() -Status 'WouldDo' -Detail "Backup would be written to $backupPath" -Data $null
        }
        return
    }

    $backupOk = $false
    try {
        Copy-Item -LiteralPath $hostsPath -Destination $backupPath -Force -ErrorAction Stop
        $backupOk = $true
        Write-Log -Message "Hosts file backed up: $backupPath" -Level 'SUCCESS'
    } catch {
        Write-Log -Message "Hosts backup failed: $($_.Exception.Message)" -Level 'WARN'
    }
    if (-not $backupOk -and -not $Force) {
        Write-Log -Message 'Skipping hosts cleanup because backup failed. Use -Force to override.' -Level 'WARN'
        return
    }

    $localHostsPath = $hostsPath
    $keptLines = @($kept)
    $data = [pscustomobject]@{ HostsPath = $hostsPath; Backup = $backupPath; RemovedCount = $removed.Count }
    Invoke-SafeAction -Description ("Remove {0} Microsoft-activation-blocking entry(ies) from hosts file" -f $removed.Count) -Category 'HostsCleanup' -Target $hostsPath -Data $data -Action {
        Set-Content -LiteralPath $localHostsPath -Value $keptLines -Encoding ASCII -ErrorAction Stop
    } | Out-Null

    foreach ($r in $removed) {
        Add-ReportListItem -ListName 'HostsEntriesRemoved' -Item ([pscustomobject]@{ Entry = ([string]$r).Trim(); Backup = $backupPath })
    }
}

function Clear-WindowsKMSConfiguration {
    [CmdletBinding()]
    param()

    $rootKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
    $valueNames = @(
        'KeyManagementServiceName',
        'KeyManagementServicePort',
        'KeyManagementServiceLookupDomain',
        'DiscoveredKeyManagementServiceMachineName',
        'DiscoveredKeyManagementServiceMachinePort',
        'DisableDnsPublishing',
        'DisableKeyManagementServiceHostCaching'
    )

    $rootKeyPaths = @(
        $rootKeyPath,
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
    )
    $keyPaths = @()
    foreach ($root in $rootKeyPaths) {
        $keyPaths += $root
        if (Test-Path -LiteralPath $root) {
            try {
                $keyPaths += @(Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
                    Join-Path $root $_.PSChildName
                })
            } catch {
                Write-Log -Message "Unable to enumerate SoftwareProtectionPlatform subkeys: $($_.Exception.Message)" -Level 'WARN'
            }
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
        'KeyManagementServiceLookupDomain',
        'DiscoveredKeyManagementServiceMachineName',
        'DiscoveredKeyManagementServiceMachinePort',
        'DisableDnsPublishing',
        'DisableKeyManagementServiceHostCaching'
    )

    # Standard MSI / SPP platform paths
    $keyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OfficeSoftwareProtectionPlatform'
    )

    # C2R ClickToRun Configuration paths (Fix N.N 2: these were missing)
    $c2rPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration',
        'HKLM:\SOFTWARE\Microsoft\Office\15.0\ClickToRun\Configuration'
    )

    # Group Policy / Policies paths that can override Office KMS settings
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    foreach ($ver in @('16.0', '15.0', '14.0')) {
        $keyPaths += "HKLM:\SOFTWARE\Policies\Microsoft\Office\$ver\Common\OfficePolicies"
        $keyPaths += "HKLM:\SOFTWARE\Policies\Microsoft\Office\$ver\Common\Licensing"
    }

    foreach ($keyPath in ($keyPaths | Select-Object -Unique)) {
        Remove-RegistryValuesSafe -KeyPath $keyPath -ValueNames $valueNames -Category 'OfficeKMSRegistry'
    }

    # C2R paths: same value names plus SharedComputerLicensing
    $c2rValueNames = $valueNames + @('OSPPREARM', 'SharedComputerLicensing')
    foreach ($keyPath in ($c2rPaths | Select-Object -Unique)) {
        Remove-RegistryValuesSafe -KeyPath $keyPath -ValueNames $c2rValueNames -Category 'OfficeKMSRegistry'
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
            Write-Log -Message (Get-UiText -Key 'WindowsKeyRemovalWarning') -Level 'WARN'
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

function Invoke-LicenseStatusCheck {
    [CmdletBinding()]
    param()

    $summary = $script:Report.LicenseStatusCheck
    $summary.Requested = $true

    # ---- Windows ----
    Write-Host ''
    Write-Host (Get-UiText -Key 'LicenseWindowsTitle') -ForegroundColor Cyan
    Write-Log -Message (Get-UiText -Key 'LicenseWindowsTitle') -Level 'INFO'

    $edition = Get-CurrentWindowsEdition
    $summary.WindowsEdition = $edition.FriendlyName
    Write-Host ("{0}: {1}" -f (Get-UiText -Key 'CurrentWindowsEditionLabel'), $edition.FriendlyName) -ForegroundColor Gray

    $winState = @(Get-WindowsActivationState)
    $script:Report.WindowsActivationBefore = $winState
    $summary.WindowsProductCount = $winState.Count

    if ($winState.Count -eq 0) {
        Write-Host (Get-UiText -Key 'LicenseNoWindowsProduct') -ForegroundColor Yellow
        Write-Log -Message (Get-UiText -Key 'LicenseNoWindowsProduct') -Level 'INFO'
    } else {
        foreach ($product in $winState) {
            $name = if ([string]::IsNullOrWhiteSpace([string]$product.Name)) { $product.Description } else { $product.Name }
            Write-Host ''
            Write-Host ("  {0}: {1}" -f (Get-UiText -Key 'LicenseProductLabel'), $name) -ForegroundColor Gray
            Write-Host ("  {0}: {1}" -f (Get-UiText -Key 'LicenseChannelLabel'), $(if ([string]::IsNullOrWhiteSpace([string]$product.ProductKeyChannel)) { Get-UiText -Key 'Unknown' } else { $product.ProductKeyChannel })) -ForegroundColor Gray
            $statusColor = if ([int]$product.LicenseStatus -eq 1) { 'Green' } else { 'Yellow' }
            Write-Host ("  {0}: {1}" -f (Get-UiText -Key 'LicenseStatusLabel'), $product.LicenseStatusText) -ForegroundColor $statusColor
            if (-not [string]::IsNullOrWhiteSpace([string]$product.PartialProductKey)) {
                Write-Host ("  {0}: XXXXX-XXXXX-XXXXX-XXXXX-{1}" -f (Get-UiText -Key 'LicensePartialKeyLabel'), $product.PartialProductKey) -ForegroundColor Gray
            }
            $grace = 0
            if ($product.PSObject.Properties.Name -contains 'GracePeriodRemaining' -and $product.GracePeriodRemaining) {
                $grace = [int]$product.GracePeriodRemaining
            }
            if ($grace -gt 0) {
                Write-Host ("  {0}: {1}" -f (Get-UiText -Key 'LicenseGraceLabel'), $grace) -ForegroundColor Yellow
            }
        }
    }

    $expiry = Get-WindowsLicenseExpiry
    $summary.WindowsExpiry = $expiry
    if (-not [string]::IsNullOrWhiteSpace($expiry)) {
        Write-Host ''
        Write-Host ("{0}: {1}" -f (Get-UiText -Key 'LicenseExpiryLabel'), $expiry) -ForegroundColor Gray
        Write-Log -Message ("Windows expiry: {0}" -f $expiry) -Level 'INFO'
    }

    $genuine = Get-WindowsGenuineStatus
    $summary.WindowsGenuine = $genuine.StateText
    $genuineColor = if ($genuine.Available -and [int]([string]$genuine.State) -eq 0) { 'Green' } else { 'Yellow' }
    Write-Host ("{0}: {1}" -f (Get-UiText -Key 'LicenseGenuineLabel'), $genuine.StateText) -ForegroundColor $genuineColor
    Write-Log -Message ("Windows genuine check: {0} (HRESULT {1})" -f $genuine.StateText, $genuine.Hresult) -Level 'INFO'

    # ---- OEM embedded key (read-only) ----
    $oemInfo = Get-OEMEmbeddedProductKey

    # ---- Office (read-only) ----
    Write-Host ''
    Write-Host (Get-UiText -Key 'LicenseOfficeTitle') -ForegroundColor Cyan
    Write-Log -Message (Get-UiText -Key 'LicenseOfficeTitle') -Level 'INFO'

    $officeCount = 0
    if ($SkipOffice) {
        Write-Log -Message 'Office license status check skipped because -SkipOffice was specified.' -Level 'INFO'
    } else {
        $osppPaths = @(Find-OfficeOSPP)
        if ($osppPaths.Count -eq 0) {
            Write-Host (Get-UiText -Key 'LicenseNoOffice') -ForegroundColor Yellow
            Write-Log -Message (Get-UiText -Key 'LicenseNoOffice') -Level 'INFO'
        } else {
            foreach ($ospp in $osppPaths) {
                $officeProducts = @(Get-OfficeInstalledKeys -OSPPPath $ospp)
                foreach ($product in $officeProducts) {
                    $officeCount++
                    $name = if ([string]::IsNullOrWhiteSpace([string]$product.LicenseName)) { $product.LicenseDescription } else { $product.LicenseName }
                    Write-Host ''
                    Write-Host ("  {0}: {1}" -f (Get-UiText -Key 'LicenseProductLabel'), $name) -ForegroundColor Gray
                    $isLicensed = ([string]$product.LicenseStatus -match '(?i)LICENSED')
                    $statusColor = if ($isLicensed) { 'Green' } else { 'Yellow' }
                    Write-Host ("  {0}: {1}" -f (Get-UiText -Key 'LicenseStatusLabel'), $(if ([string]::IsNullOrWhiteSpace([string]$product.LicenseStatus)) { Get-UiText -Key 'Unknown' } else { $product.LicenseStatus })) -ForegroundColor $statusColor
                    if (-not [string]::IsNullOrWhiteSpace([string]$product.LastFive)) {
                        Write-Host ("  {0}: XXXXX-XXXXX-XXXXX-XXXXX-{1}" -f (Get-UiText -Key 'LicensePartialKeyLabel'), $product.LastFive) -ForegroundColor Gray
                    }
                }
            }
            if ($officeCount -eq 0) {
                Write-Host (Get-UiText -Key 'LicenseNoOffice') -ForegroundColor Yellow
            }
        }
    }
    $summary.OfficeProductCount = $officeCount

    Add-ReportAction -Category 'LicenseStatusCheck' -Action 'Check Windows and Office license/activation status' -Target 'SoftwareLicensingProduct + ospp.vbs /dstatusall' -Status 'Done' -Detail ('WindowsProducts={0}; OfficeProducts={1}' -f $winState.Count, $officeCount) -Data ([pscustomobject]@{
        WindowsEdition = $edition.FriendlyName
        WindowsExpiry = $expiry
        WindowsProductCount = $winState.Count
        OfficeProductCount = $officeCount
    })
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
        # C2R VFS paths (x64)
        (Join-Path $env:ProgramFiles 'Microsoft Office\root\vfs\System'),
        (Join-Path $env:ProgramFiles 'Microsoft Office\root\vfs\SystemX86'),
        (Join-Path $env:ProgramFiles 'Common Files\Microsoft Shared\OfficeSoftwareProtectionPlatform'),
        # MSI paths Office 14/15/16/19 (x64) - Fix N.N 3: were missing
        (Join-Path $env:ProgramFiles 'Microsoft Office\Office16'),
        (Join-Path $env:ProgramFiles 'Microsoft Office\Office15'),
        (Join-Path $env:ProgramFiles 'Microsoft Office\Office14'),
        (Join-Path $env:ProgramFiles 'Microsoft Office\Office19')
    )
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $dirs += @(
            # C2R VFS paths (x86)
            (Join-Path $programFilesX86 'Microsoft Office\root\vfs\System'),
            (Join-Path $programFilesX86 'Microsoft Office\root\vfs\SystemX86'),
            (Join-Path $programFilesX86 'Common Files\Microsoft Shared\OfficeSoftwareProtectionPlatform'),
            # MSI paths Office 14/15/16/19 (x86) - Fix N.N 3: were missing
            (Join-Path $programFilesX86 'Microsoft Office\Office16'),
            (Join-Path $programFilesX86 'Microsoft Office\Office15'),
            (Join-Path $programFilesX86 'Microsoft Office\Office14'),
            (Join-Path $programFilesX86 'Microsoft Office\Office19')
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

    $newLeaf = '{0}.EasyActiveByMyPC.{1}.bak' -f $leaf, $script:RunId
    $destination = Join-Path $parent $newLeaf
    $i = 1
    while (Test-Path -LiteralPath $destination) {
        $newLeaf = '{0}.EasyActiveByMyPC.{1}.{2}.bak' -f $leaf, $script:RunId, $i
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

function Stop-OfficeProcessesSafe {
    [CmdletBinding()]
    param()

    # Fix N.N 3: Force-kill all Office processes so DLL files are not locked
    # when Ohook removal runs. Without this, Rename-Item / Remove-Item fails
    # silently and sppc.dll / OSPPC.DLL are never actually cleaned.
    $officeProcessNames = @(
        'WINWORD', 'EXCEL', 'POWERPNT', 'OUTLOOK', 'ONENOTE',
        'MSACCESS', 'MSPUB', 'MSPROJECT', 'VISIO', 'INFOPATH',
        'GROOVE', 'LYNC', 'MSOASB', 'MSOHTMED',
        'OfficeClickToRun', 'c2rlicensing'
    )

    $killed = @()
    foreach ($name in $officeProcessNames) {
        $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
        foreach ($proc in $procs) {
            Invoke-SafeAction -Description "Stop Office process $name (PID $($proc.Id)) to release DLL file locks" -Category 'OfficeProcess' -Target $name -Action {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            } | Out-Null
            $killed += $name
        }
    }

    # Also stop ClickToRun service which holds file locks on C2R DLLs
    foreach ($svcName in @('ClickToRunSvc', 'OfficeSvcMgr')) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Invoke-SafeAction -Description "Stop service $svcName to release C2R DLL file locks" -Category 'OfficeProcess' -Target $svcName -Action {
                Stop-Service -Name $svcName -Force -ErrorAction Stop
            } | Out-Null
            $killed += $svcName
        }
    }

    if ($killed.Count -gt 0) {
        Write-Log -Message ("Stopped $($killed.Count) Office process(es)/service(s) to release DLL locks: " + ($killed -join ', ')) -Level 'INFO'
        Start-Sleep -Milliseconds 800
    } else {
        Write-Log -Message 'No Office processes or services were running; DLL file locks already clear.' -Level 'VERBOSE'
    }
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

    $services = @('sppsvc', 'ClipSVC', 'osppsvc', 'ClickToRunSvc', 'OfficeSvcMgr')
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
    $taskPath = '\EasyActiveByMyPC\'
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
    $taskPath = '\EasyActiveByMyPC\'
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
    $null = $lines.Add((Get-UiText -Key 'ReportTitle'))
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
    if ($script:Report.OEMEmbeddedKeyChecked) {
        $null = $lines.Add('')
        $null = $lines.Add((Get-UiText -Key 'ReportOEMHeading'))
        foreach ($key in $script:Report.OEMEmbeddedKeyInfo.Keys) {
            $value = $script:Report.OEMEmbeddedKeyInfo[$key]
            if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $value = @($value) -join '; '
            }
            $null = $lines.Add(('  {0}: {1}' -f $key, $value))
        }
        if ($script:Report.OEMKeyReinstall.Requested) {
            $null = $lines.Add('')
            $null = $lines.Add((Get-UiText -Key 'ReinstallOEMTitle'))
            foreach ($key in $script:Report.OEMKeyReinstall.Keys) {
                $value = $script:Report.OEMKeyReinstall[$key]
                if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                    $value = @($value) -join '; '
                }
                $null = $lines.Add(('  {0}: {1}' -f $key, $value))
            }
        }
    }

    $winList = @($script:Report.WindowsActivationAfter)
    if ($winList.Count -eq 0) {
        $winList = @($script:Report.WindowsActivationBefore)
    }
    if ($winList.Count -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add((Get-UiText -Key 'ReportWindowsActivationHeading'))
        foreach ($product in $winList) {
            $name = if ([string]::IsNullOrWhiteSpace([string]$product.Name)) { [string]$product.Description } else { [string]$product.Name }
            $channel = if ([string]::IsNullOrWhiteSpace([string]$product.ProductKeyChannel)) { 'Unknown' } else { [string]$product.ProductKeyChannel }
            $last5 = if ([string]::IsNullOrWhiteSpace([string]$product.PartialProductKey)) { '-----' } else { [string]$product.PartialProductKey }
            $null = $lines.Add(('  - {0} | {1}: {2} | {3}: {4} | ...{5}' -f $name, (Get-UiText -Key 'LicenseStatusLabel'), $product.LicenseStatusText, (Get-UiText -Key 'LicenseChannelLabel'), $channel, $last5))
        }
    }

    $officeList = @($script:Report.OfficeProducts)
    if ($officeList.Count -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add((Get-UiText -Key 'ReportOfficeHeading'))
        foreach ($product in $officeList) {
            $name = if ([string]::IsNullOrWhiteSpace([string]$product.LicenseName)) { [string]$product.LicenseDescription } else { [string]$product.LicenseName }
            $status = if ([string]::IsNullOrWhiteSpace([string]$product.LicenseStatus)) { 'Unknown' } else { [string]$product.LicenseStatus }
            $last5 = if ([string]::IsNullOrWhiteSpace([string]$product.LastFive)) { '-----' } else { [string]$product.LastFive }
            $null = $lines.Add(('  - {0} | {1}: {2} | ...{3}' -f $name, (Get-UiText -Key 'LicenseStatusLabel'), $status, $last5))
        }
    }

    if ($script:Report.CrackAssessment.Requested) {
        $ca = $script:Report.CrackAssessment
        $null = $lines.Add('')
        $null = $lines.Add((Get-UiText -Key 'ReportAssessmentHeading'))
        foreach ($sig in @($ca.Signals)) {
            $prefix = switch ([string]$sig.Severity) { 'Pass' { '[+]' } 'Info' { '[i]' } 'Warn' { '[?]' } 'Fail' { '[!]' } default { '[ ]' } }
            $null = $lines.Add(('  {0} {1}: {2}' -f $prefix, $sig.Category, $sig.Evidence))
        }
        $null = $lines.Add('')
        $null = $lines.Add(('  {0}: {1}' -f (Get-UiText -Key 'AsmVerdictHeading'), $ca.VerdictText))
        $null = $lines.Add(('  {0}: {1} | {2}: {3}' -f (Get-UiText -Key 'AsmScoreLabel'), $ca.Score, (Get-UiText -Key 'AsmConfidenceLabel'), [string]$ca.ConfidenceText))
        if (@($ca.Reasons).Count -gt 0) {
            $null = $lines.Add(('  {0}:' -f (Get-UiText -Key 'AsmReasonsLabel')))
            foreach ($reason in @($ca.Reasons)) { $null = $lines.Add(('    - {0}' -f $reason)) }
        }
        if ($ca.Incomplete) {
            $null = $lines.Add(('  {0}' -f (Get-UiText -Key 'AsmVerdictIncomplete')))
        }
    }

    $null = $lines.Add('')
    foreach ($line in (Get-DigitalLicenseNoteLines)) {
        $null = $lines.Add($line)
    }
    $null = $lines.Add('')
    $null = $lines.Add(('{0}: {1}' -f (Get-UiText -Key 'ReportActions'), $script:Report.Actions.Count))
    $null = $lines.Add(('{0}: {1}' -f (Get-UiText -Key 'ReportWarnings'), $script:Report.Warnings.Count))
    $null = $lines.Add(('{0}: {1}' -f (Get-UiText -Key 'ReportErrors'), $script:Report.Errors.Count))
    $null = $lines.Add('')
    $null = $lines.Add((Get-UiText -Key 'ReportNextSteps'))
    foreach ($step in $script:Report.NextSteps) {
        $null = $lines.Add(('  - {0}' -f $step))
    }
    return ($lines -join [Environment]::NewLine)
}

function New-AssessmentSignal {
    [CmdletBinding()]
    param(
        [string]$Id,
        [string]$Category,
        [ValidateSet('Pass', 'Info', 'Warn', 'Fail')]
        [string]$Severity,
        [ValidateSet('High', 'Medium', 'Low', 'None')]
        [string]$Confidence = 'None',
        [int]$Weight = 0,
        [string]$Evidence = ''
    )

    $signal = [pscustomobject]@{
        Id = $Id
        Category = $Category
        Severity = $Severity
        Confidence = $Confidence
        Weight = $Weight
        Evidence = $Evidence
    }
    $null = $script:Report.CrackAssessment.Signals.Add($signal)

    $prefix = switch ($Severity) { 'Pass' { '[+]' } 'Info' { '[i]' } 'Warn' { '[?]' } 'Fail' { '[!]' } default { '[ ]' } }
    $color = switch ($Severity) { 'Pass' { 'Green' } 'Info' { 'Gray' } 'Warn' { 'Yellow' } 'Fail' { 'Red' } default { 'Gray' } }
    Write-Host ("  {0} {1}: {2}" -f $prefix, $Category, $Evidence) -ForegroundColor $color
    Write-Log -Message ("Assessment [{0}] {1} ({2}/{3}): {4}" -f $Id, $Category, $Severity, $Confidence, $Evidence) -Level 'INFO'
    return $signal
}

function Get-WindowsInstallDate {
    [CmdletBinding()]
    param()

    try {
        $os = @(Get-CimOrWmiObjectSafe -ClassName Win32_OperatingSystem) | Select-Object -First 1
        if ($os -and $os.InstallDate) {
            $value = $os.InstallDate
            if ($value -is [datetime]) { return $value }
            try { return [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$value) } catch { return $null }
        }
    } catch {
        Write-Log -Message "Unable to read Windows install date: $($_.Exception.Message)" -Level 'WARN'
    }
    return $null
}

function Test-KnownKmsEmulatorDomain {
    [CmdletBinding()]
    param([string]$HostValue)

    if ([string]::IsNullOrWhiteSpace($HostValue)) { return $false }
    $h = $HostValue.Trim().Trim('[', ']')
    if (($h.Split(':').Count -eq 2) -and ($h -match '^(.+):\d+$')) { $h = $Matches[1] }
    $h = $h.Trim().ToLowerInvariant()

    # Curated list of well-known public KMS-emulator servers (crack). Not exhaustive; a public
    # internet KMS host is itself already suspicious, but a match here is treated as definite.
    $known = @(
        'kms.loli.beer', 'kms.digiboy.ir', 'kms8.msguides.com', 'kms.msguides.com',
        'kms.03k.org', 'kms.chinancce.com', 'kms.shuax.com', 'kms.cangshui.net',
        'kms.lotro.cc', 'kms.moeclub.org', 'kms.library.hk', 'kms.lolico.moe',
        'win.kms.moe', 'kms.wxlost.com', 'kms.ddns.net', 'kms.v0v.bid', 'zh.us.to'
    )
    foreach ($d in $known) {
        if ($h -eq $d -or $h.EndsWith('.' + $d)) { return $true }
    }
    return $false
}

function Get-KmsHostClassification {
    [CmdletBinding()]
    param([string]$HostValue)

    if ([string]::IsNullOrWhiteSpace($HostValue)) { return 'None' }
    if (Test-KnownKmsEmulatorDomain -HostValue $HostValue) { return 'KnownEmulatorDomain' }
    $h = $HostValue.Trim().Trim('[', ']')
    if (($h.Split(':').Count -eq 2) -and ($h -match '^(.+):\d+$')) { $h = $Matches[1] }
    $h = $h.Trim()
    if ($h -match '(?i)^(localhost|::1)$') { return 'LocalEmulator' }
    if ($h -match '^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)$') { return 'LocalEmulator' }
    if ($h -match '^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { return 'PrivateKms' }
    if ($h -match '^192\.168\.\d{1,3}\.\d{1,3}$') { return 'PrivateKms' }
    if ($h -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$') { return 'PrivateKms' }
    return 'PublicKms'
}

function Get-KmsHostFinding {
    [CmdletBinding()]
    param()

    $rootKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
    $result = [pscustomobject]@{ Name = $null; Port = $null; Source = $null; Classification = 'None' }
    $rootKeyPaths = @(
        $rootKeyPath,
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
    )
    $paths = @()
    foreach ($root in $rootKeyPaths) {
        $paths += $root
        try {
            if (Test-Path -LiteralPath $root) {
                $paths += @(Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object { Join-Path $root $_.PSChildName })
            }
        } catch { }
    }

    # A KMS host can linger in the configured name, the DNS-discovered name, or a lookup domain.
    # Tools like WinCheck read the discovered value too, so all of them must be checked.
    $hostValueNames = @('KeyManagementServiceName', 'DiscoveredKeyManagementServiceMachineName', 'KeyManagementServiceLookupDomain')

    foreach ($p in ($paths | Select-Object -Unique)) {
        foreach ($valueName in $hostValueNames) {
            try {
                $name = (Get-ItemProperty -LiteralPath $p -Name $valueName -ErrorAction SilentlyContinue).$valueName
                if (-not [string]::IsNullOrWhiteSpace([string]$name)) {
                    $result.Name = [string]$name
                    $result.Source = $valueName
                    $result.Port = (Get-ItemProperty -LiteralPath $p -Name 'KeyManagementServicePort' -ErrorAction SilentlyContinue).'KeyManagementServicePort'
                    break
                }
            } catch { }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$result.Name)) { break }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$result.Name)) {
        $result.Classification = Get-KmsHostClassification -HostValue $result.Name
    }
    return $result
}

function Get-Kms38Finding {
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{ IsKms38 = $false; ExpiryText = $null; Year = $null; HasData = $false }
    $xpr = Get-WindowsLicenseExpiry
    if ([string]::IsNullOrWhiteSpace($xpr)) { return $result }
    $result.HasData = $true
    $result.ExpiryText = $xpr
    foreach ($match in [regex]::Matches($xpr, '\b([2-9]\d{3})\b')) {
        $year = [int]$match.Groups[1].Value
        if ($year -ge 2037) {
            $result.IsKms38 = $true
            $result.Year = $year
            break
        }
    }
    return $result
}

function Get-GenuineBlockingFindings {
    [CmdletBinding()]
    param()

    $findings = New-Object System.Collections.ArrayList

    $regChecks = @(
        @{ Value = 'NoGenTicket'; Paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform',
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
        ) },
        @{ Value = 'NoAcquireGT'; Paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform',
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
        ) }
    )
    foreach ($check in $regChecks) {
        foreach ($p in $check.Paths) {
            try {
                $value = (Get-ItemProperty -LiteralPath $p -Name $check.Value -ErrorAction SilentlyContinue).$($check.Value)
                if ($null -ne $value) {
                    $null = $findings.Add([pscustomobject]@{ Type = 'Registry'; Name = $check.Value; Location = $p; Value = $value })
                    break
                }
            } catch { }
        }
    }

    foreach ($svc in @('sppsvc', 'ClipSVC', 'osppsvc')) {
        $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        try {
            $start = (Get-ItemProperty -LiteralPath $p -Name 'Start' -ErrorAction SilentlyContinue).'Start'
            if ($null -ne $start -and [int]$start -eq 4) {
                $null = $findings.Add([pscustomobject]@{ Type = 'Service'; Name = $svc; Location = $p; Value = 'Start=4 (Disabled)' })
            }
        } catch { }
    }
    return @($findings)
}

function Get-HostsFileActivationBlocks {
    [CmdletBinding()]
    param()

    $blocks = New-Object System.Collections.ArrayList
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hostsPath)) { return @($blocks) }

    $activationDomains = $script:MASActivationHostDomains

    $lines = $null
    try { $lines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop } catch { return @($blocks) }

    foreach ($raw in @($lines)) {
        $line = ([string]$raw).Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        $parts = $line -split '\s+'
        if ($parts.Count -lt 2) { continue }
        $ip = $parts[0]
        if (-not ($ip -match '^(0\.0\.0\.0|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::)')) { continue }
        for ($i = 1; $i -lt $parts.Count; $i++) {
            $hostName = $parts[$i]
            if ($hostName.StartsWith('#')) { break }
            foreach ($domain in $activationDomains) {
                if ($hostName.IndexOf($domain, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $null = $blocks.Add(('{0} -> {1}' -f $hostName, $ip))
                    break
                }
            }
        }
    }
    return @($blocks)
}

function Get-MASServiceCandidates {
    [CmdletBinding()]
    param()

    $candidates = New-Object System.Collections.ArrayList
    try {
        foreach ($service in @(Get-CimOrWmiObjectSafe -ClassName Win32_Service)) {
            $name = [string]$service.Name
            $display = [string]$service.DisplayName
            $pathName = [string]$service.PathName
            if ((Test-MASArtifactName -Name $name).IsMatch -or (Test-MASArtifactName -Name $display).IsMatch -or (Test-MASPersistenceText -Text $pathName).IsMatch) {
                $null = $candidates.Add(('{0} ({1})' -f $name, $display))
            }
        }
    } catch {
        Write-Log -Message "Unable to scan services for activation artifacts: $($_.Exception.Message)" -Level 'WARN'
    }
    return @($candidates)
}

function Get-MASPersistenceCandidates {
    [CmdletBinding()]
    param()

    $candidates = New-Object System.Collections.ArrayList

    # Machine-level autorun registry keys (64-bit + 32-bit view). These mirror the locations
    # that Remove-RunEntriesRelatedToMAS cleans, so detection and removal stay in sync.
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $props = $null
        try { $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop } catch { continue }
        foreach ($prop in $props.PSObject.Properties) {
            $valueName = [string]$prop.Name
            if ($valueName -like 'PS*') { continue }
            $valueData = [string]$prop.Value
            if ((Test-MASArtifactName -Name $valueName).IsMatch -or (Test-MASPersistenceText -Text $valueData).IsMatch) {
                $null = $candidates.Add(('Run: {0}' -f $valueName))
            }
        }
    }

    # Machine-level Startup folder (per-user startup is handled by the cleanup path).
    $startupFolder = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
    if (Test-Path -LiteralPath $startupFolder) {
        try {
            foreach ($item in @(Get-ChildItem -LiteralPath $startupFolder -File -ErrorAction Stop)) {
                if ((Test-MASArtifactName -Name $item.Name).IsMatch) {
                    $null = $candidates.Add(('Startup: {0}' -f $item.Name))
                }
            }
        } catch { }
    }

    return @($candidates)
}

function Get-CrackAssessmentVerdict {
    [CmdletBinding()]
    param([bool]$Incomplete = $false)

    $signals = @($script:Report.CrackAssessment.Signals)
    $definite = @($signals | Where-Object { $_.Severity -eq 'Fail' -and $_.Confidence -eq 'High' }).Count -gt 0
    $scoreObj = $signals | Where-Object { $_.Severity -eq 'Warn' -or $_.Severity -eq 'Fail' } | Measure-Object -Property Weight -Sum
    $score = if ($scoreObj -and $null -ne $scoreObj.Sum) { [int]$scoreObj.Sum } else { 0 }

    $verdict = 'Clean'
    if ($definite) {
        $verdict = 'Cracked'
    } elseif ($score -ge 50) {
        $verdict = 'LikelyCracked'
    } elseif ($score -ge 10) {
        $verdict = 'Suspicious'
    }

    # Overall confidence in the verdict
    $confidence = 'Medium'
    if ($definite) {
        $confidence = 'High'
    } elseif ($verdict -eq 'LikelyCracked') {
        $confidence = 'Medium'
    } elseif ($verdict -eq 'Suspicious') {
        $confidence = 'Low'
    } else {
        # Clean: high only if we actually gathered the key data and genuine check passed
        $genuineOk = @($signals | Where-Object { $_.Id -eq 'genuine_check' -and $_.Severity -eq 'Pass' }).Count -gt 0
        $confidence = if ($Incomplete) { 'Low' } elseif ($genuineOk) { 'High' } else { 'Medium' }
    }

    # Top contributing signals (evidence behind the verdict)
    $reasons = @($signals |
        Where-Object { $_.Severity -eq 'Warn' -or $_.Severity -eq 'Fail' } |
        Sort-Object -Property @{ Expression = { [int]$_.Weight } } -Descending |
        Select-Object -First 5 |
        ForEach-Object { ('{0} - {1}' -f $_.Category, $_.Evidence) })

    return [pscustomobject]@{
        Verdict = $verdict
        Score = $score
        Definite = $definite
        Confidence = $confidence
        Reasons = $reasons
    }
}

function Invoke-CrackAssessment {
    [CmdletBinding()]
    param()

    $ca = $script:Report.CrackAssessment
    $ca.Requested = $true
    $incomplete = $false

    Write-Host ''
    Write-Host (Get-UiText -Key 'AsmTitle') -ForegroundColor Cyan
    Write-Log -Message (Get-UiText -Key 'AsmTitle') -Level 'INFO'
    Write-Host ''

    # 0. Install date (context only)
    $installDate = Get-WindowsInstallDate
    $installText = if ($installDate) { $installDate.ToString('yyyy-MM-dd HH:mm:ss') } else { Get-UiText -Key 'AsmNoData' }
    $null = New-AssessmentSignal -Id 'install_date' -Category (Get-UiText -Key 'AsmInstallDate') -Severity 'Info' -Evidence $installText

    # 1. Activation status (WMI)
    $winState = @(Get-WindowsActivationState)
    $script:Report.WindowsActivationBefore = $winState
    $channels = ''
    $licensed = $false
    if ($winState.Count -eq 0) {
        $incomplete = $true
        $null = New-AssessmentSignal -Id 'activation' -Category (Get-UiText -Key 'AsmActivationStatus') -Severity 'Info' -Evidence (Get-UiText -Key 'AsmNoData')
    } else {
        $licensed = @($winState | Where-Object { [int]$_.LicenseStatus -eq 1 }).Count -gt 0
        $channels = (@($winState | ForEach-Object { [string]$_.ProductKeyChannel }) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique) -join ', '
        $sev = if ($licensed) { 'Pass' } else { 'Warn' }
        $w = if ($licensed) { 0 } else { 5 }
        $statusWord = if ($licensed) { 'Licensed' } else { 'Not licensed' }
        $null = New-AssessmentSignal -Id 'activation' -Category (Get-UiText -Key 'AsmActivationStatus') -Severity $sev -Weight $w -Evidence ('{0} | {1}' -f $statusWord, $channels)

        # KMS client channel (GVLK)
        if ($channels -match '(?i)GVLK') {
            $null = New-AssessmentSignal -Id 'kms_channel' -Category (Get-UiText -Key 'AsmKmsClientChannel') -Severity 'Warn' -Confidence 'Medium' -Weight 40 -Evidence 'Volume:GVLK (KMS client key)'
        } else {
            $null = New-AssessmentSignal -Id 'kms_channel' -Category (Get-UiText -Key 'AsmKmsClientChannel') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
        }
    }

    # 1b. Genuine authenticity (SLIsGenuineLocal) — catches forged/HWID licenses that pass local licensing
    $genuine = Get-WindowsGenuineStatus
    $script:Report.GenuineStatus = $genuine
    if (-not $genuine.Available) {
        $null = New-AssessmentSignal -Id 'genuine_check' -Category (Get-UiText -Key 'AsmGenuine') -Severity 'Info' -Evidence (Get-UiText -Key 'AsmGenuineUnavailable')
    } elseif ([int]$genuine.State -eq 0) {
        $null = New-AssessmentSignal -Id 'genuine_check' -Category (Get-UiText -Key 'AsmGenuine') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmGenuineGenuine')
    } elseif ([int]$genuine.State -eq 2) {
        $null = New-AssessmentSignal -Id 'genuine_check' -Category (Get-UiText -Key 'AsmGenuine') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence (Get-UiText -Key 'AsmGenuineTampered')
    } elseif ([int]$genuine.State -eq 1) {
        if ($licensed) {
            $null = New-AssessmentSignal -Id 'genuine_check' -Category (Get-UiText -Key 'AsmGenuine') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence (Get-UiText -Key 'AsmGenuineForged')
        } else {
            $null = New-AssessmentSignal -Id 'genuine_check' -Category (Get-UiText -Key 'AsmGenuine') -Severity 'Info' -Evidence (Get-UiText -Key 'AsmGenuineNotActivated')
        }
    } else {
        $null = New-AssessmentSignal -Id 'genuine_check' -Category (Get-UiText -Key 'AsmGenuine') -Severity 'Info' -Evidence (Get-UiText -Key 'AsmGenuineOffline')
    }

    # 2. KMS host configuration
    $kmsHost = Get-KmsHostFinding
    $kmsSource = if ([string]::IsNullOrWhiteSpace([string]$kmsHost.Source)) { 'KeyManagementServiceName' } else { [string]$kmsHost.Source }
    switch ($kmsHost.Classification) {
        'KnownEmulatorDomain' {
            $null = New-AssessmentSignal -Id 'kms_host' -Category (Get-UiText -Key 'AsmKmsHost') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence ('{0} = {1} ({2})' -f $kmsSource, $kmsHost.Name, (Get-UiText -Key 'AsmKmsKnownEmulator'))
        }
        'LocalEmulator' {
            $null = New-AssessmentSignal -Id 'kms_host' -Category (Get-UiText -Key 'AsmKmsHost') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence ('{0} = {1} ({2})' -f $kmsSource, $kmsHost.Name, (Get-UiText -Key 'AsmKmsLocalEmulator'))
        }
        'PublicKms' {
            $null = New-AssessmentSignal -Id 'kms_host' -Category (Get-UiText -Key 'AsmKmsHost') -Severity 'Warn' -Confidence 'Medium' -Weight 40 -Evidence ('{0} = {1} ({2})' -f $kmsSource, $kmsHost.Name, (Get-UiText -Key 'AsmKmsPublic'))
        }
        'PrivateKms' {
            $null = New-AssessmentSignal -Id 'kms_host' -Category (Get-UiText -Key 'AsmKmsHost') -Severity 'Warn' -Confidence 'Low' -Weight 25 -Evidence ('{0} = {1} ({2})' -f $kmsSource, $kmsHost.Name, (Get-UiText -Key 'AsmKmsPrivate'))
        }
        default {
            $null = New-AssessmentSignal -Id 'kms_host' -Category (Get-UiText -Key 'AsmKmsHost') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
        }
    }

    # 3. KMS38 (far-future expiry)
    $kms38 = Get-Kms38Finding
    if (-not $kms38.HasData) {
        $null = New-AssessmentSignal -Id 'kms38' -Category (Get-UiText -Key 'AsmKms38') -Severity 'Info' -Evidence (Get-UiText -Key 'AsmNoData')
    } elseif ($kms38.IsKms38) {
        $expiryNote = if ([int]$kms38.Year -ge 3000) { Get-UiText -Key 'AsmTsforgeSignature' } else { Get-UiText -Key 'AsmKms38Signature' }
        $null = New-AssessmentSignal -Id 'kms38' -Category (Get-UiText -Key 'AsmKms38') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence ('{0} ~{1} (slmgr /xpr)' -f $expiryNote, $kms38.Year)
    } else {
        $null = New-AssessmentSignal -Id 'kms38' -Category (Get-UiText -Key 'AsmKms38') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }

    # 4. License channel vs OEM/BIOS
    $oemInfo = Get-OEMEmbeddedProductKey
    if ($oemInfo.KeyFound -and [string]$oemInfo.Compatibility -eq 'Compatible') {
        $null = New-AssessmentSignal -Id 'license_bios' -Category (Get-UiText -Key 'AsmLicenseBios') -Severity 'Pass' -Evidence ('{0}: {1}' -f (Get-UiText -Key 'AsmOemMatches'), $oemInfo.DetectedKeyEdition)
    } elseif ($oemInfo.KeyFound) {
        $null = New-AssessmentSignal -Id 'license_bios' -Category (Get-UiText -Key 'AsmLicenseBios') -Severity 'Warn' -Confidence 'Low' -Weight 10 -Evidence ('{0} (OEM={1}, Windows={2})' -f (Get-UiText -Key 'AsmOemMismatch'), $oemInfo.DetectedKeyEdition, $oemInfo.CurrentWindowsEdition)
    } else {
        $null = New-AssessmentSignal -Id 'license_bios' -Category (Get-UiText -Key 'AsmLicenseBios') -Severity 'Info' -Evidence (Get-UiText -Key 'AsmNoOemKey')
    }

    # 5. HWID / digital license — only meaningful when corroborated by a failed genuine check
    $winStateHasData = ($winState.Count -gt 0)
    $digitalNoOem = ($winStateHasData -and ($channels -match '(?i)Retail') -and -not $oemInfo.KeyFound)
    $genuineNotClean = ($genuine.Available -and [int]$genuine.State -ne 0 -and [int]$genuine.State -ne 3)
    if ($digitalNoOem -and $genuineNotClean) {
        $null = New-AssessmentSignal -Id 'hwid' -Category (Get-UiText -Key 'AsmHwid') -Severity 'Warn' -Confidence 'Medium' -Weight 40 -Evidence (Get-UiText -Key 'AsmHwidForged')
    } elseif ($digitalNoOem) {
        $null = New-AssessmentSignal -Id 'hwid' -Category (Get-UiText -Key 'AsmHwid') -Severity 'Info' -Confidence 'Low' -Weight 0 -Evidence (Get-UiText -Key 'AsmHwidInconclusive')
    } else {
        $null = New-AssessmentSignal -Id 'hwid' -Category (Get-UiText -Key 'AsmHwid') -Severity 'Info' -Evidence (Get-UiText -Key 'AsmHwidNoSignal')
    }

    # 6. Illegal tool folders/files
    $fileCandidates = @(Get-MASFileCandidates)
    if ($fileCandidates.Count -gt 0) {
        $highFiles = @($fileCandidates | Where-Object { [string]$_.Confidence -eq 'High' })
        $names = (@($fileCandidates | ForEach-Object { Split-Path -Leaf ([string]$_.Path) }) | Select-Object -First 6) -join ', '
        if ($highFiles.Count -gt 0) {
            $null = New-AssessmentSignal -Id 'tool_folders' -Category (Get-UiText -Key 'AsmToolFolders') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence $names
        } else {
            $null = New-AssessmentSignal -Id 'tool_folders' -Category (Get-UiText -Key 'AsmToolFolders') -Severity 'Warn' -Confidence 'Medium' -Weight 40 -Evidence $names
        }
    } else {
        $null = New-AssessmentSignal -Id 'tool_folders' -Category (Get-UiText -Key 'AsmToolFolders') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }

    # 7. Illegal scheduled tasks
    $taskCandidates = @(Get-MASScheduledTaskCandidates)
    if ($taskCandidates.Count -gt 0) {
        $names = (@($taskCandidates | ForEach-Object { [string]$_.TaskName }) | Where-Object { $_ } | Select-Object -First 6) -join ', '
        if ([string]::IsNullOrWhiteSpace($names)) { $names = ('{0} task(s)' -f $taskCandidates.Count) }
        $null = New-AssessmentSignal -Id 'scheduled_tasks' -Category (Get-UiText -Key 'AsmScheduledTasks') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence $names
    } else {
        $null = New-AssessmentSignal -Id 'scheduled_tasks' -Category (Get-UiText -Key 'AsmScheduledTasks') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }

    # 8. Illegal services
    $svcCandidates = @(Get-MASServiceCandidates)
    if ($svcCandidates.Count -gt 0) {
        $null = New-AssessmentSignal -Id 'services' -Category (Get-UiText -Key 'AsmServices') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence ((@($svcCandidates) | Select-Object -First 6) -join ', ')
    } else {
        $null = New-AssessmentSignal -Id 'services' -Category (Get-UiText -Key 'AsmServices') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }

    # 8b. Autorun persistence (Run keys / Startup folder) — mirrors what cleanup removes
    $persistence = @(Get-MASPersistenceCandidates)
    if ($persistence.Count -gt 0) {
        $null = New-AssessmentSignal -Id 'persistence' -Category (Get-UiText -Key 'AsmPersistence') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence ((@($persistence) | Select-Object -First 5) -join ' ; ')
    } else {
        $null = New-AssessmentSignal -Id 'persistence' -Category (Get-UiText -Key 'AsmPersistence') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }

    # 9. Office Ohook
    $ohookCandidates = @(Get-OhookCandidates)
    if ($ohookCandidates.Count -gt 0) {
        $names = (@($ohookCandidates | ForEach-Object { Split-Path -Leaf ([string]$_.Path) }) | Where-Object { $_ } | Select-Object -First 4) -join ', '
        if ([string]::IsNullOrWhiteSpace($names)) { $names = ('{0} item(s)' -f $ohookCandidates.Count) }
        $null = New-AssessmentSignal -Id 'ohook' -Category (Get-UiText -Key 'AsmOhook') -Severity 'Fail' -Confidence 'High' -Weight 100 -Evidence $names
    } else {
        $null = New-AssessmentSignal -Id 'ohook' -Category (Get-UiText -Key 'AsmOhook') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }

    # 10. Genuine-blocking registry + disabled services
    $blockingFindings = @(Get-GenuineBlockingFindings)
    $regFindings = @($blockingFindings | Where-Object { $_.Type -eq 'Registry' })
    $svcDisabled = @($blockingFindings | Where-Object { $_.Type -eq 'Service' })
    if ($regFindings.Count -gt 0) {
        $desc = (@($regFindings | ForEach-Object { '{0} @ {1}' -f $_.Name, $_.Location }) | Select-Object -First 4) -join ' ; '
        $null = New-AssessmentSignal -Id 'registry_tamper' -Category (Get-UiText -Key 'AsmRegistryTamper') -Severity 'Warn' -Confidence 'Low' -Weight (15 * $regFindings.Count) -Evidence $desc
    } else {
        $null = New-AssessmentSignal -Id 'registry_tamper' -Category (Get-UiText -Key 'AsmRegistryTamper') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }
    if ($svcDisabled.Count -gt 0) {
        $null = New-AssessmentSignal -Id 'services_disabled' -Category (Get-UiText -Key 'AsmServicesDisabled') -Severity 'Warn' -Confidence 'Medium' -Weight (35 * $svcDisabled.Count) -Evidence ((@($svcDisabled | ForEach-Object { $_.Name })) -join ', ')
    } else {
        $null = New-AssessmentSignal -Id 'services_disabled' -Category (Get-UiText -Key 'AsmServicesDisabled') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }

    # 11. Hosts file blocking Microsoft activation
    $hostsBlocks = @(Get-HostsFileActivationBlocks)
    if ($hostsBlocks.Count -gt 0) {
        $null = New-AssessmentSignal -Id 'hosts_file' -Category (Get-UiText -Key 'AsmHostsFile') -Severity 'Warn' -Confidence 'Medium' -Weight 30 -Evidence ((@($hostsBlocks) | Select-Object -First 4) -join ' ; ')
    } else {
        $null = New-AssessmentSignal -Id 'hosts_file' -Category (Get-UiText -Key 'AsmHostsFile') -Severity 'Pass' -Evidence (Get-UiText -Key 'AsmNotDetected')
    }

    # Verdict
    $verdict = Get-CrackAssessmentVerdict -Incomplete $incomplete
    $ca.Verdict = $verdict.Verdict
    $ca.Score = $verdict.Score
    $ca.DefiniteArtifact = $verdict.Definite
    $ca.Confidence = $verdict.Confidence
    $ca.Incomplete = $incomplete
    $ca.Reasons.Clear()
    foreach ($reason in @($verdict.Reasons)) { $null = $ca.Reasons.Add($reason) }

    $verdictKey = switch ($verdict.Verdict) {
        'Clean' { 'AsmVerdictClean' }
        'Suspicious' { 'AsmVerdictSuspicious' }
        'LikelyCracked' { 'AsmVerdictLikely' }
        'Cracked' { 'AsmVerdictCracked' }
        default { 'AsmVerdictClean' }
    }
    $ca.VerdictText = Get-UiText -Key $verdictKey
    $confidenceKey = switch ($verdict.Confidence) {
        'High' { 'AsmConfidenceHigh' }
        'Medium' { 'AsmConfidenceMedium' }
        'Low' { 'AsmConfidenceLow' }
        default { 'AsmConfidenceMedium' }
    }
    $ca.ConfidenceText = Get-UiText -Key $confidenceKey
    $verdictColor = switch ($verdict.Verdict) { 'Clean' { 'Green' } 'Suspicious' { 'Yellow' } default { 'Red' } }

    Write-Host ''
    Write-Host (Get-UiText -Key 'AsmVerdictHeading') -ForegroundColor Cyan
    Write-Host ('  {0}' -f $ca.VerdictText) -ForegroundColor $verdictColor
    Write-Host ('  {0}: {1} | {2}: {3}' -f (Get-UiText -Key 'AsmScoreLabel'), $verdict.Score, (Get-UiText -Key 'AsmConfidenceLabel'), $ca.ConfidenceText) -ForegroundColor Gray
    if (@($ca.Reasons).Count -gt 0) {
        Write-Host ('  {0}:' -f (Get-UiText -Key 'AsmReasonsLabel')) -ForegroundColor Gray
        foreach ($reason in @($ca.Reasons)) { Write-Host ('    - {0}' -f $reason) -ForegroundColor Gray }
    }
    if ($incomplete) {
        Write-Host ('  {0}' -f (Get-UiText -Key 'AsmVerdictIncomplete')) -ForegroundColor Yellow
    }
    Write-Log -Message ("Crack assessment verdict: {0} (score={1}, confidence={2}, definite={3}, incomplete={4})" -f $verdict.Verdict, $verdict.Score, $verdict.Confidence, $verdict.Definite, $incomplete) -Level 'INFO'

    Add-ReportAction -Category 'CrackAssessment' -Action 'Assess crack/license tampering traces' -Target 'read-only diagnostic' -Status 'Done' -Detail ('Verdict={0}; Score={1}; Confidence={2}; Definite={3}' -f $verdict.Verdict, $verdict.Score, $verdict.Confidence, $verdict.Definite) -Data ([pscustomobject]@{
        Verdict = $verdict.Verdict
        Score = $verdict.Score
        Confidence = $verdict.Confidence
        Definite = $verdict.Definite
        Incomplete = $incomplete
        SignalCount = @($ca.Signals).Count
    })
}

function New-HtmlReport {
    [CmdletBinding()]
    param()

    $esc = { param($v) if ($null -eq $v) { '' } else { [System.Security.SecurityElement]::Escape([string]$v) } }

    $orderedRows = {
        param($dict)
        $rows = ''
        foreach ($key in $dict.Keys) {
            $value = $dict[$key]
            if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $value = @($value) -join '; '
            }
            $rows += ('<tr><th>{0}</th><td>{1}</td></tr>' -f (& $esc $key), (& $esc $value))
        }
        return $rows
    }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<!DOCTYPE html><html lang="')
    $null = $sb.Append((& $esc $script:Language))
    $null = $sb.Append('"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>')
    $null = $sb.Append((& $esc (Get-UiText -Key 'ReportTitle')))
    $null = $sb.Append('</title><style>')
    $null = $sb.Append('body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f5f7;color:#1b1f23;}')
    $null = $sb.Append('.wrap{max-width:960px;margin:0 auto;padding:24px;}')
    $null = $sb.Append('h1{font-size:22px;margin:0;}')
    $null = $sb.Append('.head{background:#0b5cad;color:#fff;padding:20px 24px;border-radius:10px 10px 0 0;}')
    $null = $sb.Append('.head .sub{opacity:.85;font-size:13px;margin-top:4px;}')
    $null = $sb.Append('.card{background:#fff;border:1px solid #e3e6ea;border-top:none;padding:18px 24px;}')
    $null = $sb.Append('.card:last-child{border-radius:0 0 10px 10px;}')
    $null = $sb.Append('h2{font-size:15px;text-transform:uppercase;letter-spacing:.04em;color:#0b5cad;border-bottom:2px solid #eef1f4;padding-bottom:6px;}')
    $null = $sb.Append('table{width:100%;border-collapse:collapse;font-size:14px;}')
    $null = $sb.Append('th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #eef1f4;vertical-align:top;}')
    $null = $sb.Append('th{color:#586069;font-weight:600;width:230px;}')
    $null = $sb.Append('.tbl th{width:auto;color:#1b1f23;background:#f6f8fa;}')
    $null = $sb.Append('.ok{color:#137333;font-weight:600;}.warn{color:#b06000;font-weight:600;}')
    $null = $sb.Append('.pill{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;}')
    $null = $sb.Append('.pill.ok{background:#e6f4ea;}.pill.warn{background:#fef7e0;}.pill.bad{background:#fce8e6;color:#b3261e;}')
    $null = $sb.Append('.muted{color:#6a737d;font-size:12px;}ul{margin:6px 0 0 18px;}')
    $null = $sb.Append('</style></head><body><div class="wrap">')

    $dryLabel = if ($script:DryRunMode) { ' (' + (& $esc (Get-UiText -Key 'DryRunBadge')) + ')' } else { '' }
    $null = $sb.Append('<div class="head"><h1>')
    $null = $sb.Append((& $esc (Get-UiText -Key 'ReportTitle')))
    $null = $sb.Append($dryLabel)
    $null = $sb.Append('</h1><div class="sub">')
    $null = $sb.Append((& $esc ('{0} v{1} · Run {2} · {3} → {4}' -f $script:ToolName, $script:Version, $script:RunId, $script:Report.StartTime, $script:Report.EndTime)))
    $null = $sb.Append('</div></div>')

    # OS
    if ($script:Report.OS -and @($script:Report.OS.Keys).Count -gt 0) {
        $null = $sb.Append('<div class="card"><h2>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'ReportOSHeading')))
        $null = $sb.Append('</h2><table>')
        $null = $sb.Append((& $orderedRows $script:Report.OS))
        $null = $sb.Append('</table></div>')
    }

    # Windows activation
    $winList = @($script:Report.WindowsActivationAfter)
    if ($winList.Count -eq 0) { $winList = @($script:Report.WindowsActivationBefore) }
    if ($winList.Count -gt 0) {
        $null = $sb.Append('<div class="card"><h2>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'ReportWindowsActivationHeading')))
        $null = $sb.Append('</h2>')
        if ($script:Report.LicenseStatusCheck.Requested -and $script:Report.LicenseStatusCheck.WindowsGenuine) {
            $null = $sb.Append('<p class="muted">')
            $null = $sb.Append((& $esc ((Get-UiText -Key 'LicenseGenuineLabel') + ': ' + $script:Report.LicenseStatusCheck.WindowsGenuine)))
            $null = $sb.Append('</p>')
        }
        $null = $sb.Append('<table class="tbl"><tr><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'LicenseProductLabel')))
        $null = $sb.Append('</th><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'LicenseStatusLabel')))
        $null = $sb.Append('</th><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'LicenseChannelLabel')))
        $null = $sb.Append('</th><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'LicensePartialKeyLabel')))
        $null = $sb.Append('</th></tr>')
        foreach ($product in $winList) {
            $name = if ([string]::IsNullOrWhiteSpace([string]$product.Name)) { [string]$product.Description } else { [string]$product.Name }
            $channel = if ([string]::IsNullOrWhiteSpace([string]$product.ProductKeyChannel)) { 'Unknown' } else { [string]$product.ProductKeyChannel }
            $last5 = if ([string]::IsNullOrWhiteSpace([string]$product.PartialProductKey)) { '-----' } else { [string]$product.PartialProductKey }
            $cls = if ([int]$product.LicenseStatus -eq 1) { 'ok' } else { 'warn' }
            $null = $sb.Append(('<tr><td>{0}</td><td><span class="pill {1}">{2}</span></td><td>{3}</td><td>...{4}</td></tr>' -f (& $esc $name), $cls, (& $esc $product.LicenseStatusText), (& $esc $channel), (& $esc $last5)))
        }
        $null = $sb.Append('</table></div>')
    }

    # Office
    $officeList = @($script:Report.OfficeProducts)
    if ($officeList.Count -gt 0) {
        $null = $sb.Append('<div class="card"><h2>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'ReportOfficeHeading')))
        $null = $sb.Append('</h2>')
        $null = $sb.Append('<table class="tbl"><tr><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'LicenseProductLabel')))
        $null = $sb.Append('</th><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'LicenseStatusLabel')))
        $null = $sb.Append('</th><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'LicensePartialKeyLabel')))
        $null = $sb.Append('</th></tr>')
        foreach ($product in $officeList) {
            $name = if ([string]::IsNullOrWhiteSpace([string]$product.LicenseName)) { [string]$product.LicenseDescription } else { [string]$product.LicenseName }
            $status = if ([string]::IsNullOrWhiteSpace([string]$product.LicenseStatus)) { 'Unknown' } else { [string]$product.LicenseStatus }
            $last5 = if ([string]::IsNullOrWhiteSpace([string]$product.LastFive)) { '-----' } else { [string]$product.LastFive }
            $cls = if ($status -match '(?i)LICENSED') { 'ok' } else { 'warn' }
            $null = $sb.Append(('<tr><td>{0}</td><td><span class="pill {1}">{2}</span></td><td>...{3}</td></tr>' -f (& $esc $name), $cls, (& $esc $status), (& $esc $last5)))
        }
        $null = $sb.Append('</table></div>')
    }

    # OEM embedded key
    if ($script:Report.OEMEmbeddedKeyChecked) {
        $null = $sb.Append('<div class="card"><h2>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'ReportOEMHeading')))
        $null = $sb.Append('</h2><table>')
        $null = $sb.Append((& $orderedRows $script:Report.OEMEmbeddedKeyInfo))
        $null = $sb.Append('</table>')
        if ($script:Report.OEMKeyReinstall.Requested) {
            $null = $sb.Append('<h2 style="margin-top:16px;">')
            $null = $sb.Append((& $esc (Get-UiText -Key 'ReinstallOEMTitle')))
            $null = $sb.Append('</h2><table>')
            $null = $sb.Append((& $orderedRows $script:Report.OEMKeyReinstall))
            $null = $sb.Append('</table>')
        }
        $null = $sb.Append('</div>')
    }

    # Crack / license assessment
    if ($script:Report.CrackAssessment.Requested) {
        $ca = $script:Report.CrackAssessment
        $bannerColor = switch ([string]$ca.Verdict) { 'Clean' { '#137333' } 'Suspicious' { '#b06000' } default { '#b3261e' } }
        $null = $sb.Append('<div class="card"><h2>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'ReportAssessmentHeading')))
        $null = $sb.Append('</h2>')
        $null = $sb.Append(('<p style="font-size:15px;font-weight:700;color:{0};">{1}</p>' -f $bannerColor, (& $esc $ca.VerdictText)))
        $null = $sb.Append(('<p class="muted">{0}: {1} &nbsp;|&nbsp; {2}: {3}</p>' -f (& $esc (Get-UiText -Key 'AsmScoreLabel')), $ca.Score, (& $esc (Get-UiText -Key 'AsmConfidenceLabel')), (& $esc [string]$ca.ConfidenceText)))
        if (@($ca.Reasons).Count -gt 0) {
            $null = $sb.Append(('<p style="margin-bottom:4px;"><strong>{0}:</strong></p><ul>' -f (& $esc (Get-UiText -Key 'AsmReasonsLabel'))))
            foreach ($reason in @($ca.Reasons)) {
                $null = $sb.Append(('<li>{0}</li>' -f (& $esc [string]$reason)))
            }
            $null = $sb.Append('</ul>')
        }
        if ($ca.Incomplete) {
            $null = $sb.Append(('<p class="muted">{0}</p>' -f (& $esc (Get-UiText -Key 'AsmVerdictIncomplete'))))
        }
        $null = $sb.Append('<table class="tbl"><tr><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'AsmColCheck')))
        $null = $sb.Append('</th><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'LicenseStatusLabel')))
        $null = $sb.Append('</th><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'AsmColConfidence')))
        $null = $sb.Append('</th><th>')
        $null = $sb.Append((& $esc (Get-UiText -Key 'AsmColEvidence')))
        $null = $sb.Append('</th></tr>')
        foreach ($sig in @($ca.Signals)) {
            $cls = switch ([string]$sig.Severity) { 'Pass' { 'ok' } 'Fail' { 'bad' } 'Warn' { 'warn' } default { '' } }
            $conf = if ([string]$sig.Confidence -eq 'None') { '-' } else { [string]$sig.Confidence }
            $null = $sb.Append(('<tr><td>{0}</td><td><span class="pill {1}">{2}</span></td><td>{3}</td><td>{4}</td></tr>' -f (& $esc $sig.Category), $cls, (& $esc $sig.Severity), (& $esc $conf), (& $esc $sig.Evidence)))
        }
        $null = $sb.Append('</table></div>')
    }

    # Summary + next steps
    $null = $sb.Append('<div class="card"><h2>')
    $null = $sb.Append((& $esc (Get-UiText -Key 'ReportNextSteps')))
    $null = $sb.Append('</h2><p>')
    $null = $sb.Append((& $esc ('{0}: {1} · {2}: {3} · {4}: {5}' -f (Get-UiText -Key 'ReportActions'), $script:Report.Actions.Count, (Get-UiText -Key 'ReportWarnings'), $script:Report.Warnings.Count, (Get-UiText -Key 'ReportErrors'), $script:Report.Errors.Count)))
    $null = $sb.Append('</p><ul>')
    foreach ($step in $script:Report.NextSteps) {
        $null = $sb.Append('<li>')
        $null = $sb.Append((& $esc $step))
        $null = $sb.Append('</li>')
    }
    $null = $sb.Append('</ul></div>')

    $null = $sb.Append('</div></body></html>')
    return $sb.ToString()
}

function Invoke-ReportRetention {
    [CmdletBinding()]
    param(
        [int]$Keep = 30
    )

    if ($script:DryRunMode) {
        return
    }

    $specs = @(
        @{ Dir = $script:ReportRoot; Pattern = 'EasyActiveByMyPC-*.json' },
        @{ Dir = $script:ReportRoot; Pattern = 'EasyActiveByMyPC-*.txt' },
        @{ Dir = $script:ReportRoot; Pattern = 'EasyActiveByMyPC-*.html' },
        @{ Dir = $script:ReportRoot; Pattern = 'EasyActiveByMyPC-Actions-*.csv' },
        @{ Dir = $script:LogRoot; Pattern = 'EasyActiveByMyPC-*.log' }
    )

    foreach ($spec in $specs) {
        try {
            if ([string]::IsNullOrWhiteSpace([string]$spec.Dir) -or -not (Test-Path -LiteralPath $spec.Dir)) {
                continue
            }
            $files = @(Get-ChildItem -LiteralPath $spec.Dir -Filter $spec.Pattern -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending)
            if ($files.Count -le $Keep) {
                continue
            }
            $old = @($files | Select-Object -Skip $Keep)
            foreach ($file in $old) {
                try {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    Write-Log -Message "Retention removed old report/log: $($file.FullName)" -Level 'VERBOSE'
                } catch {
                    Write-Log -Message "Retention could not remove $($file.FullName): $($_.Exception.Message)" -Level 'WARN'
                }
            }
        } catch {
            Write-Log -Message "Retention scan failed for $($spec.Dir): $($_.Exception.Message)" -Level 'WARN'
        }
    }
}

function Invoke-ReportOpenPrompt {
    [CmdletBinding()]
    param()

    if (-not $LauncherMenu) {
        return
    }

    $htmlPath = $script:LastHtmlReportPath
    $hasHtml = (-not [string]::IsNullOrWhiteSpace([string]$htmlPath)) -and (Test-Path -LiteralPath $htmlPath)

    Write-Host ''
    Write-Host (Get-UiText -Key 'OpenReportPrompt') -ForegroundColor Cyan
    if ($hasHtml) {
        Write-Host (Get-UiText -Key 'OpenReportHtmlOption') -ForegroundColor Gray
    }
    Write-Host (Get-UiText -Key 'OpenReportFolderOption') -ForegroundColor Gray
    Write-Host (Get-UiText -Key 'OpenReportNoOption') -ForegroundColor Gray

    $valid = if ($hasHtml) { @('0', '1', '2') } else { @('0', '2') }
    $choice = Read-Host (Get-UiText -Key 'OpenReportInput')
    if ($choice -notin $valid) {
        return
    }

    try {
        if ($choice -eq '1' -and $hasHtml) {
            Start-Process -FilePath $htmlPath | Out-Null
        } elseif ($choice -eq '2') {
            if (-not [string]::IsNullOrWhiteSpace([string]$script:ReportRoot)) {
                if (-not (Test-Path -LiteralPath $script:ReportRoot)) {
                    New-Item -Path $script:ReportRoot -ItemType Directory -Force | Out-Null
                }
                Start-Process -FilePath 'explorer.exe' -ArgumentList $script:ReportRoot | Out-Null
            }
        }
    } catch {
        Write-Log -Message "Could not open report location: $($_.Exception.Message)" -Level 'WARN'
    }
}

function Generate-ActivationReport {
    [CmdletBinding()]
    param()

    Ensure-NextSteps
    $script:Report.EndTime = (Get-Date).ToString('o')

    $jsonPath = Join-Path $script:ReportRoot ("EasyActiveByMyPC-{0}.json" -f $script:RunId)
    try {
        $script:Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 -Force
        $null = $script:Report.ReportFiles.Add($jsonPath)
        Write-Log -Message "JSON report written: $jsonPath" -Level 'SUCCESS'
    } catch {
        Write-Log -Message "Failed to write JSON report: $($_.Exception.Message)" -Level 'WARN'
    }

    if ($ExportReport) {
        $txtPath = Join-Path $script:ReportRoot ("EasyActiveByMyPC-{0}.txt" -f $script:RunId)
        $csvPath = Join-Path $script:ReportRoot ("EasyActiveByMyPC-Actions-{0}.csv" -f $script:RunId)
        $htmlPath = Join-Path $script:ReportRoot ("EasyActiveByMyPC-{0}.html" -f $script:RunId)

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

        try {
            New-HtmlReport | Set-Content -LiteralPath $htmlPath -Encoding UTF8 -Force
            $null = $script:Report.ReportFiles.Add($htmlPath)
            $script:LastHtmlReportPath = $htmlPath
            Write-Log -Message "HTML report written: $htmlPath" -Level 'SUCCESS'
        } catch {
            Write-Log -Message "Failed to write HTML report: $($_.Exception.Message)" -Level 'WARN'
        }
    }

    Invoke-ReportRetention
}

function Show-NextSteps {
    [CmdletBinding()]
    param()

    Ensure-NextSteps
    Write-Host ''
    Write-Host (Get-UiText -Key 'NextStepsHeading') -ForegroundColor Cyan
    Write-NoteBlock -Lines (Get-DigitalLicenseNoteLines)
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

    $steps = New-Object System.Collections.ArrayList
    $reinstallStatus = [string]$script:Report.OEMKeyReinstall.InstallStatus
    if ($reinstallStatus -eq 'Installed' -or $reinstallStatus -eq 'WouldInstall') {
        $null = $steps.Add((Get-UiText -Key 'ReinstallOEMNextStep'))
    }
    $null = $steps.Add((Get-UiText -Key 'RestartComputerNextStep'))
    $null = $steps.Add((Get-UiText -Key 'WindowsActivationNextStep'))
    $null = $steps.Add((Get-UiText -Key 'M365NextStep'))
    $null = $steps.Add((Get-UiText -Key 'OfficeVolumeNextStep'))
    $null = $steps.Add((Get-UiText -Key 'OfficeRepairNextStep'))

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

function Reset-RunContext {
    [CmdletBinding()]
    param()

    # Fresh identity + report for the next task so each task keeps its own RunId / log / report / backups.
    $script:RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:BackupRoot = Join-Path (Join-Path $script:ProgramDataRoot 'Backups') $script:RunId
    $script:LogPath = $null
    $script:LastHtmlReportPath = $null
    $script:HadWarnings = $false
    $script:Report = New-ReportObject
}

function Confirm-ReturnToLauncherMenu {
    [CmdletBinding()]
    param()

    Write-Host ''
    if ($script:Language -eq 'en') {
        Write-Host 'Task finished.' -ForegroundColor Cyan
        Write-Host 'Tip: if you just cleaned Windows/Office licensing, restart the PC before the next action.' -ForegroundColor Gray
        $answer = Read-Host 'Press Enter to return to the main menu, or type N/0 to exit'
    } else {
        Write-Host 'Đã xong tác vụ.' -ForegroundColor Cyan
        Write-Host 'Lưu ý: nếu vừa dọn bản quyền Windows/Office, nên khởi động lại máy trước khi làm thao tác tiếp theo.' -ForegroundColor Gray
        $answer = Read-Host 'Nhấn Enter để quay lại menu chính, hoặc gõ N/0 để thoát'
    }
    # Default (empty) returns to menu; only an explicit no/exit leaves.
    return (-not ($answer -match '^(?i)\s*(n|no|0|q|exit|thoat|thoát)\s*$'))
}

function Invoke-Main {
    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host (Get-UiText -Key 'PowerShellRequired') -ForegroundColor Red
        exit 2
    }

    if (-not (Test-IsAdministrator)) {
        Write-Host (Get-UiText -Key 'AdminRequired') -ForegroundColor Red
        exit 1
    }

    if ($LauncherMenu) {
        $shouldRun = Invoke-LauncherMenu
        if (-not $shouldRun) {
            $script:LoopAgain = $false
            return
        }
    } else {
        Sync-ReportParameterSnapshot
    }

    Initialize-RunStorage
    Write-Log -Message "Started $script:ToolName $script:Version run $script:RunId" -Level 'INFO'
    Write-Log -Message "Log file: $script:LogPath" -Level 'INFO'
    if ($script:DryRunMode) {
        Write-Log -Message (Get-UiText -Key 'DryRunActive') -Level 'INFO'
    }
    if ($ExportSensitiveKeys) {
        Write-Host (Get-UiText -Key 'SensitiveExportWarning') -ForegroundColor Yellow
        Write-Log -Message (Get-UiText -Key 'SensitiveExportWarning') -Level 'INFO'
    }

    if ($ReadOEMKeyOnly) {
        Write-Step -Number 1 -Name (Get-UiText -Key 'StepPreflight')
        $script:Report.OS = Get-WindowsOSInfo
        Write-Log -Message (Get-UiText -Key 'OEMReadOnlyMode') -Level 'INFO'

        Write-Step -Number 2 -Name (Get-UiText -Key 'StepReadOEM')
        Get-OEMEmbeddedProductKey | Out-Null

        $script:Report.NextSteps.Clear()
        $null = $script:Report.NextSteps.Add((Get-UiText -Key 'NoChangeOEMNextStep'))
        $null = $script:Report.NextSteps.Add((Get-UiText -Key 'OEMNotCompatibleNextStep'))
        if ($ExportSensitiveKeys) {
            $null = $script:Report.NextSteps.Add((Get-UiText -Key 'SensitiveReportNextStep'))
        }

        Write-Step -Number 3 -Name (Get-UiText -Key 'StepGenerateReport')
        Generate-ActivationReport

        Write-Step -Number 4 -Name (Get-UiText -Key 'StepShowNextSteps')
        Show-NextSteps

        Invoke-ReportOpenPrompt
        Write-Log -Message (Get-UiText -Key 'CompletedOEMRun') -Level 'SUCCESS'
    }
    elseif ($CheckLicenseOnly) {
        Write-Step -Number 1 -Name (Get-UiText -Key 'StepPreflight')
        $script:Report.OS = Get-WindowsOSInfo
        Write-Log -Message (Get-UiText -Key 'LicenseCheckMode') -Level 'INFO'

        Write-Step -Number 2 -Name (Get-UiText -Key 'StepCheckLicense')
        Invoke-LicenseStatusCheck

        $script:Report.NextSteps.Clear()
        $null = $script:Report.NextSteps.Add((Get-UiText -Key 'LicenseCheckNextStep'))

        Write-Step -Number 3 -Name (Get-UiText -Key 'StepGenerateReport')
        Generate-ActivationReport

        Write-Step -Number 4 -Name (Get-UiText -Key 'StepShowNextSteps')
        Show-NextSteps

        Invoke-ReportOpenPrompt
        Write-Log -Message (Get-UiText -Key 'CompletedLicenseCheck') -Level 'SUCCESS'
    }
    elseif ($AssessCrack) {
        Write-Step -Number 1 -Name (Get-UiText -Key 'StepPreflight')
        $script:Report.OS = Get-WindowsOSInfo
        Write-Log -Message (Get-UiText -Key 'AssessCrackMode') -Level 'INFO'

        Write-Step -Number 2 -Name (Get-UiText -Key 'StepAssessCrack')
        Invoke-CrackAssessment

        $script:Report.NextSteps.Clear()
        $null = $script:Report.NextSteps.Add((Get-UiText -Key 'AsmNextStep'))

        Write-Step -Number 3 -Name (Get-UiText -Key 'StepGenerateReport')
        Generate-ActivationReport

        Write-Step -Number 4 -Name (Get-UiText -Key 'StepShowNextSteps')
        Show-NextSteps

        Invoke-ReportOpenPrompt
        Write-Log -Message (Get-UiText -Key 'CompletedAssessment') -Level 'SUCCESS'
    }
    else {
        Write-Step -Number 1 -Name (Get-UiText -Key 'StepPreflight')
    Show-OfficeCloseWarning
    $script:Report.OS = Get-WindowsOSInfo
    $script:Report.WindowsActivationBefore = @(Get-WindowsActivationState)
    New-SystemRestorePointSafe

    Write-Step -Number 2 -Name (Get-UiText -Key 'StepDetectArtifacts')
    $script:DetectedScheduledTasks = @(Get-MASScheduledTaskCandidates)
    $script:DetectedMASFileArtifacts = @(Get-MASFileCandidates)
    $script:DetectedOhookArtifacts = @(Get-OhookCandidates)
    Add-DetectedArtifactReportItems
    Write-Log -Message ("Detected {0} task(s), {1} file/folder artifact(s), {2} Office DLL observation(s)." -f $script:DetectedScheduledTasks.Count, $script:DetectedMASFileArtifacts.Count, $script:DetectedOhookArtifacts.Count) -Level 'INFO'

    Write-Step -Number 3 -Name (Get-UiText -Key 'StepRemoveScheduled')
    Remove-ScheduledTasksRelatedToMAS
    Remove-RunEntriesRelatedToMAS
    Remove-StartupFolderItemsRelatedToMAS
    Remove-ServicesRelatedToMAS
    Remove-MASFilesAndFolders

    Write-Step -Number 4 -Name (Get-UiText -Key 'StepClearWindows')
    if ($SkipWindows) {
        Write-Log -Message 'Windows licensing cleanup skipped because -SkipWindows was specified.' -Level 'INFO'
    } else {
        Clear-WindowsKMSConfiguration
        Clear-WindowsProductKey -ActivationStateBefore $script:Report.WindowsActivationBefore
        Remove-GenuineBlockingRegistry
        Restore-DisabledLicensingServices
        Remove-HostsActivationBlocks

        if ($ReinstallOEMKey) {
            $oemInfo = Get-OEMEmbeddedProductKey
            Install-OEMEmbeddedProductKey -OEMInfo $oemInfo
        }
    }

    Write-Step -Number 5 -Name (Get-UiText -Key 'StepClearOffice')
    if ($SkipOffice) {
        Write-Log -Message 'Office licensing cleanup skipped because -SkipOffice was specified.' -Level 'INFO'
    } else {
        Clear-OfficeKMSConfiguration
    }

    Write-Step -Number 6 -Name (Get-UiText -Key 'StepRemoveOfficeKeys')
    if ($SkipOffice) {
        Write-Log -Message 'Office product key cleanup skipped because -SkipOffice was specified.' -Level 'INFO'
    } else {
        Clear-OfficeProductKeys
    }

    Write-Step -Number 7 -Name (Get-UiText -Key 'StepRemoveOhook')
    if ($SkipOffice -or $SkipOhookCleanup) {
        Write-Log -Message 'Ohook cleanup skipped because -SkipOffice or -SkipOhookCleanup was specified.' -Level 'INFO'
    } else {
        # Fix N.N 3: kill Office processes first so sppc.dll / OSPPC.DLL are not file-locked
        Stop-OfficeProcessesSafe
        Remove-OhookArtifacts
    }

    Write-Step -Number 8 -Name (Get-UiText -Key 'StepRemoveOfficeCaches')
    if ($SkipOffice) {
        Write-Log -Message 'Office license cache cleanup skipped because -SkipOffice was specified.' -Level 'INFO'
    } else {
        Remove-OfficeLicenseCaches
    }

    Write-Step -Number 9 -Name (Get-UiText -Key 'StepRestartServices')
    Restart-LicensingServices

    if ($InstallPostRebootSweep -and -not $PostRebootSweep) {
        Install-PostRebootSweepTask
    }
    if ($PostRebootSweep) {
        Remove-PostRebootSweepTask
    }

    $script:Report.WindowsActivationAfter = @(Get-WindowsActivationState)

    Write-Step -Number 10 -Name (Get-UiText -Key 'StepGenerateReport')
    Generate-ActivationReport

    Write-Step -Number 11 -Name (Get-UiText -Key 'StepShowNextSteps')
    Show-NextSteps

    Invoke-ReportOpenPrompt
    Write-Log -Message (Get-UiText -Key 'CompletedRun') -Level 'SUCCESS'
    }

    if (-not $LauncherMenu) {
        $script:LoopAgain = $false
        return
    }
    $script:LoopAgain = Confirm-ReturnToLauncherMenu
}

try {
    $script:SessionExitCode = 0
    do {
        $script:LoopAgain = $false
        Invoke-Main
        if ($script:HadWarnings) {
            $script:SessionExitCode = 3
        }
        if ($script:LoopAgain) {
            Reset-RunContext
        }
    } while ($script:LoopAgain)
    exit $script:SessionExitCode
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
