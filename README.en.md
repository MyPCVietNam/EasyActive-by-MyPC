# DeActive by MyPC

Version: `1.6.0`

## Changes in v1.6.0

- **New feature — License / activation status check (read-only):** Added menu option 6 and the `-CheckLicenseOnly` switch. This mode only reads and displays whether Windows and Office are activated and how they are licensed, without changing anything.
  - Windows: read from `SoftwareLicensingProduct` (WMI) — edition, key channel (OEM / Retail / Volume:MAK / Volume:GVLK for KMS clients), status (Licensed / Notification / Grace / Unlicensed), last 5 characters of the installed key, and expiry via `slmgr /xpr`.
  - Office: read from `ospp.vbs /dstatusall` — license name, status (`---LICENSED---`, etc.), last 5 characters.
- The text report now lists Windows and Office activation status clearly (previously only in the JSON report). This applies to **every** run, not just the check mode.
- Menu: "Open logs folder" moved from 6 to 7.

Note: the tool reads the *real activation status* that Windows/Office report (activated/genuine or not, and the license type). It cannot — and should not — "validate an arbitrary key string offline"; only Microsoft's servers can confirm a key.

## Changes in v1.5.0

- **New feature — Automatic OEM key reinstall:** After removing the old Windows key, the tool can automatically reinstall the genuine Windows OEM key embedded in the machine's BIOS/UEFI (`slmgr /ipk`), activate it online (`slmgr /ato`), and verify the result (`slmgr /dlv`). Previously you had to read the log to get the key and type it in by hand; now the tool does the whole thing.
- When run from the menu, options 2 (clean both) and 4 (clean Windows only) now add a Y/N prompt asking whether to auto-reinstall and activate the OEM key after cleanup. It is opt-in, never silent.
- The reinstall step runs only if the machine actually has an embedded OEM key that **matches** the installed Windows edition. If the OEM key targets a different edition, the step is skipped to avoid a guaranteed failure (override with `-Force`).
- The product key is always masked in logs, reports, and command output; the full key is never written to a file, even during reinstall.
- New PowerShell parameters: `-ReinstallOEMKey` (enable OEM key reinstall) and `-SkipOEMActivation` (install the key only, skip online activation).

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
- Optionally reinstall and activate the detected OEM key automatically instead of typing it by hand
- Check Windows and Office license / activation status (read-only)
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
   - 6 = Check Windows and Office license / activation status (read-only)
   - 7 = Open logs and reports folder
6. Restart the computer after Windows/Office cleanup.
7. Enter a genuine product key or sign in with a valid Microsoft/Microsoft 365 account.

## Read OEM Embedded Key

The tool can read the Windows product key embedded in BIOS/UEFI firmware by querying `SoftwareLicensingService.OA3xOriginalProductKey`.

Not all machines have an embedded OEM key. The OEM key is usually tied to the original Windows edition shipped with the device. If the current installed Windows edition does not match the OEM key edition, activation may fail.

Reading the key (menu option 5) is read-only: it does not activate Windows and does not modify the system.

### Reinstalling the OEM key (menu option 2 or 4)

Separately from the read-only option, the tool can reinstall the OEM key after cleanup. It runs `slmgr /ipk` with the machine's own embedded genuine key, then `slmgr /ato` to activate against Microsoft's official servers, then `slmgr /dlv` to verify. This is legitimate activation using the license tied to that hardware — it is not a bypass and does not use KMS. It runs only when you accept the Y/N prompt and only when the OEM key matches the installed Windows edition (or you pass `-Force`). If no compatible embedded key exists, the step is skipped.

Product keys are sensitive. By default, the console and reports show a masked key like `XXXXX-XXXXX-XXXXX-XXXXX-ABCDE`. Advanced PowerShell parameters are available: `-ReadOEMKeyOnly`, `-ShowFullKeys`, `-ExportSensitiveKeys`, `-ReinstallOEMKey`, and `-SkipOEMActivation`. Use `-ExportSensitiveKeys` only when the generated report will be kept private. The full key is never written to logs, even during reinstall.

Example — clean Windows only, then reinstall and activate the OEM key:

```text
Clean-MAS-Activation.ps1 -SkipOffice -ForceWindowsProductKeyRemoval -ReinstallOEMKey
```

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
