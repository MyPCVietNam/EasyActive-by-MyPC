# DeActive by MyPC

Version: `1.4.0`

## Changes in v1.4.0

- **Fix root cause 1:** Registry backup failure no longer silently blocks cleanup when running with full options (2/3/4). Previously, a full or unwritable disk could cause all KMS registry values to be skipped without any visible error.
- **Fix root cause 2:** Added missing Click-to-Run registry paths (`ClickToRun\Configuration`, `Policies\...\OfficePolicies`) to `Clear-OfficeKMSConfiguration`. This was the primary cause of Office re-activating via KMS after cleanup, because C2R stores its own KMS host separately.
- **Fix root cause 2:** `Restart-LicensingServices` now includes `ClickToRunSvc` and `OfficeSvcMgr` so the C2R renewal service is properly reset.
- **Fix root cause 3:** New `Stop-OfficeProcessesSafe` function runs automatically before Ohook cleanup. It force-kills all Office processes and stops `ClickToRunSvc` to release file locks on `sppc.dll` / `OSPPC.DLL`.
- **Fix root cause 3:** `Get-OhookDirectories` now includes MSI Office paths (`Office16`, `Office15`, `Office14`, `Office19`) to detect Ohook in MSI installations as well as C2R.
- **Fix root cause 3:** Launcher now auto-detects running Office processes and offers to force-close them instead of only asking the user.

`DeActive by MyPC` is a conservative Windows/Office activation cleanup tool for IT technicians who need to remove old non-standard MAS/KMS-style activation configuration so a machine can be activated again with a legitimate Windows digital license, product key, Microsoft account, or Microsoft 365 account.

The tool does not perform illegal activation, does not bypass licensing, does not install KMS emulators, does not contact unofficial activation servers, and does not delete Windows Event Logs or forensic traces.

## Main Features

- Dry-run mode with no system changes
- Optional System Restore Point before cleanup
- Remove old Windows/Office product keys
- Clear leftover KMS/MAS configuration
- Remove scheduled activation persistence
- Clean Office licensing caches
- Help handle Ohook artifacts
- Read the Windows OEM key embedded in motherboard BIOS/UEFI
- Clear logs, registry backups, and reports

## Quick Start

1. Extract the tool.
2. Right-click `DeActive-by-MyPC.bat`.
3. Choose Run as administrator.
4. Select a language. If no language is selected after the timeout, Vietnamese is used by default.
5. Choose a task:
   - 1 = Dry-run only, no system changes
   - 2 = Clean both Windows and Office
   - 3 = Clean Office only
   - 4 = Clean Windows only
   - 5 = Read OEM embedded key from motherboard / BIOS / UEFI
   - 6 = Open logs and reports folder
6. Restart the computer after Windows/Office cleanup.
7. Enter a genuine product key or sign in with a valid Microsoft/Microsoft 365 account.

## Read OEM Embedded Key

The tool can read the Windows product key embedded in BIOS/UEFI firmware by querying `SoftwareLicensingService.OA3xOriginalProductKey`.

Not all machines have an embedded OEM key. The OEM key is usually tied to the original Windows edition shipped with the device. If the current installed Windows edition does not match the OEM key edition, activation may fail.

This function is read-only. It does not activate Windows and does not modify the system.

Product keys are sensitive. By default, the console and reports show a masked key like `XXXXX-XXXXX-XXXXX-XXXXX-ABCDE`. Advanced PowerShell parameters are available: `-ReadOEMKeyOnly`, `-ShowFullKeys`, and `-ExportSensitiveKeys`. Use `-ExportSensitiveKeys` only when the generated report will be kept private.

## Digital License / HWID Note

If this machine was activated through MAS HWID/Digital License, this tool can only clean local keys and local configuration. Microsoft server-side hardware entitlement may still reactivate Windows when online.

This is not a tool error.

## Logs, Backups, Reports

After running, data is stored under:

```text
C:\ProgramData\LegitActivationCleaner
```

Included folders:

- Logs
- Backups
- Reports

## Safety Commitment

DeActive by MyPC:

- Does not perform illegal activation
- Does not bypass licensing
- Does not install KMS
- Does not contact unofficial activation servers
- Does not delete Windows Event Logs
- Does not delete Defender history, Prefetch, Amcache, ShimCache, or SRUM
- Does not send data to the internet

## Project Files

- `DeActive-by-MyPC.bat` - public branded launcher.
- `Clean-MAS-Activation.cmd` - bilingual menu launcher.
- `Clean-MAS-Activation.ps1` - main PowerShell implementation.
- `README.md` - Vietnamese documentation.
- `CHECKSUMS.sha256` - SHA256 list for release files.

## SHA256

The full checksum list is in `CHECKSUMS.sha256`.
