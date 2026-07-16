# EasyActive by MyPC

Version: `1.8.4`

## Changes in v1.8.4 (rebrand)

- **Renamed the tool: `DeActive by MyPC` → `EasyActive by MyPC`.** The new name better reflects the purpose — *easy, legitimate activation* — instead of being mistaken for "deactivation".
- Renamed files: `EasyActive-Engine.ps1`, `EasyActive-Menu.cmd`, `EasyActive-by-MyPC.bat`.
- **Data folder changed:** logs/reports/backups now live under `C:\ProgramData\EasyActiveByMyPC\` (previously `...\DeActiveByMyPC\`). *Note:* old data stays in the old folder and is not migrated automatically — delete it manually if not needed.
- Functionality is unchanged from v1.8.3.

## Changes in v1.8.3 (return to menu + clearer cancel option)

- **Return to the main menu after a task:** previously the tool exited after finishing one task; now after each task it asks *"Press Enter to return to the main menu, or N/0 to exit"*. This lets you run a full chain in one session, e.g. Assess (menu 7) → Clean (menu 2) → Assess again (menu 7) to confirm it is clean.
- **Each task gets its own RunId/log/report:** returning to the menu starts a fresh RunId and report, so results from different tasks are never mixed.
- **Restart reminder:** if you just cleaned licensing, the tool reminds you to restart before the next action.
- **Clearer confirmation prompts:** the warning prompts (clean Windows / close Office) now say **"N = back to menu"** instead of just "N/Cancel", so it is not mistaken for exiting.

*No "Back" item was added to the root menu* because the root is already the top level (it has "0 = Exit" and re-displays itself).

## Changes in v1.8.2 (more thorough crack cleanup)

Added 3 cleanup steps (run in the Windows cleanup phase, respecting `-SkipWindows`) that remove the remaining *genuine-validation-suppression* tampering that was previously only detected, not removed — so that after a legitimate key is installed the machine is genuinely clean with no crack residue:

- **Remove genuine-blocking registry values:** deletes `NoGenTicket` / `NoAcquireGT` (checks all plausible locations, removes only where actually present). Restores Windows' ability to generate a genuine ticket.
- **Re-enable disabled protection services:** if `sppsvc` / `ClipSVC` / `osppsvc` were set to Disabled (Start=4) by a crack, restores them to Manual (Start=3). Healthy machines are left untouched.
- **Clean hosts-file activation blocks:** removes exactly the lines that sinkhole Microsoft activation domains to `0.0.0.0/127.x`, leaving the rest of the file intact.

All follow the existing safety model: **`-DryRun` only lists, never changes**, **backup before modifying** (registry export + hosts file copy into the per-run Backups folder), with logging and report entries. If a backup fails the step is skipped (unless `-Force`).

*Note:* KMS38 needs no dedicated step — once the key is removed, config cleared, a legitimate key installed and re-activated, the activation expiry is overwritten and self-cleans through the re-license flow.

## Changes in v1.8.1 (assessment completion - Phase 2)

- **Genuine authenticity now feeds the verdict:** The assessment mode (menu 7) now uses `SLIsGenuineLocal` to catch **forged HWID/KMS-style licenses** — the case where a machine reports "activated" at the WMI level but the genuine check says *Invalid/Tampered*. This is a much stronger and more accurate signal than reading `LicenseStatus` alone. A machine that is simply not activated (invalid but not a crack) is not accused.
- **Smarter HWID detection:** HWID used to be informational only. It is now promoted to a scored signal **only when corroborated** (digital license + no OEM key + genuine check not clean). If the genuine check reports genuine, a digital license is treated as legitimate — avoiding false positives on real digital licenses.
- **Verdict now includes confidence + reasons:** Each assessment now reports an overall **Confidence** (High/Medium/Low) and lists the **Main reasons** (the highest-weighted signals behind the verdict), so you can see *why* the conclusion was reached instead of a bare one-liner.
- **HTML/TXT report additions:** added a "Confidence" column to the checklist table, an overall confidence line, and a "Main reasons" section.

## Changes in v1.8.0

- **New "Crack / license tampering assessment" mode (menu 7, read-only):** Runs a full sweep for activation-bypass traces and produces a **CONCLUSION** with evidence — similar to the license-checking tool shown by authorities, but **more conservative to avoid false accusations**. Nothing is cleaned or changed; the machine is only inspected and reported on.
- **Checks performed:** Windows install date; activation status (WMI); KMS client key (GVLK); **KMS server config** (red flag when it points to `127.0.0.1/127.0.0.2/0.0.0.0/localhost` = KMS_VL_ALL/MAS signature); **KMS38** (activation expiry pushed to ~2038 via `slmgr /xpr`); license channel vs **OEM/BIOS** key; HWID/digital license (informational only, no accusation); **illegal tool folders/files**; **illegal scheduled tasks**; **illegal services**; Office crack (**Ohook**); **registry tampering** (`NoGenTicket`, `NoAcquireGT`); **disabled protection services** (`sppsvc`/`ClipSVC`/`osppsvc` Start=4); and **hosts file blocking Microsoft activation servers**.
- **Weighted verdict:** signals are aggregated into 4 levels — *No crack detected / Suspicious / Likely cracked / Crack detected*. A single weak signal (e.g. only `NoGenTicket`) is rated "Suspicious" rather than immediately declared a crack.
- **Broader crack-tool signature library:** added KMSpico, KMSTools, Ratiborus, HWIDGEN, Microsoft-Activation-Scripts/MAS_AIO, Re-Loader, Microsoft Toolkit, AAct, W10 Digital Activation, SppExtComObjHook, and more — used by both the scan/clean and the assessment paths.
- **Assessment results in both HTML and TXT reports:** added a per-category checklist table plus a colored verdict banner (green/amber/red).
- New command-line switch: `-AssessCrack` (runs the read-only assessment mode).

## Changes in v1.7.1

- **Bug fix:** In license-check mode (menu 6), the report showed the "OEM embedded key info" section as empty (KeyFound=False) even when the machine has an OEM key, because that mode never read the OEM key. The license-check mode now also reads the OEM key, so the report shows the full details (MaskedKey, KeyDescription, DetectedKeyEdition, Compatibility, etc.).
- **Cleaner reports:** Each report section (Windows / Office / OEM key) is now shown only when that mode actually gathered its data. For example, the "Read OEM key" mode (menu 5) no longer shows misleading empty Windows/Office sections.
- **Easier genuine diagnostics:** When `SLIsGenuineLocal` cannot run, the report now shows the reason ("Unavailable: ...") instead of just "Unavailable", making the cause easier to find.

## Changes in v1.7.0

- **Rebranding for a less sensitive name:** `Clean-MAS-Activation.ps1` → `EasyActive-Engine.ps1`, `Clean-MAS-Activation.cmd` → `EasyActive-Menu.cmd`. The data folder `C:\ProgramData\LegitActivationCleaner` → `C:\ProgramData\EasyActiveByMyPC` (logs, reports, backups, and report filenames all follow the new name). `EasyActive-by-MyPC.bat` remains the main entry point.
- **Connectivity check before activation:** Before running `slmgr /ato` (the activation step after reinstalling the OEM key), the tool tests internet connectivity. If the machine is offline it warns and skips activation (the key is still installed) instead of letting the command fail.
- **Deeper genuine check:** The license-check mode (option 6) now calls the `SLIsGenuineLocal` API (via P/Invoke) to read the real Windows genuine state (Genuine / Invalid license / Tampered / Offline), which is more accurate than reading `LicenseStatus` alone.
- **HTML report + log rotation:** In addition to JSON/TXT/CSV, the tool now writes a readable `.html` report. After a run (when launched from the menu), you can choose to open the HTML file or open the reports folder. The tool also keeps the 30 most recent reports/logs and prunes older ones (it never touches the backups folder).

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

`EasyActive by MyPC` is a conservative Windows/Office activation cleanup tool for IT technicians who need to remove old non-standard MAS/KMS-style activation configuration so a machine can be activated again with a legitimate Windows digital license, product key, Microsoft account, or Microsoft 365 account.

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
2. Right-click `EasyActive-by-MyPC.bat`.
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
EasyActive-Engine.ps1 -SkipOffice -ForceWindowsProductKeyRemoval -ReinstallOEMKey
```

## Digital License / HWID Note

If this machine was activated through MAS HWID/Digital License, this tool can only clean local keys and local configuration. Microsoft server-side hardware entitlement may still reactivate Windows when online.

This is not a tool error.

## Logs, Backups, Reports

After running, data is stored under:

```text
C:\ProgramData\EasyActiveByMyPC
```

Included folders:

- Logs
- Backups
- Reports

## Safety Commitment

EasyActive by MyPC:

- Does not perform illegal activation
- Does not bypass licensing
- Does not install KMS
- Does not contact unofficial activation servers
- Does not delete Windows Event Logs
- Does not delete Defender history, Prefetch, Amcache, ShimCache, or SRUM
- Does not send data to the internet

## Project Files

- `EasyActive-by-MyPC.bat` - public branded launcher.
- `EasyActive-Menu.cmd` - bilingual menu launcher.
- `EasyActive-Engine.ps1` - main PowerShell implementation.
- `README.md` - Vietnamese documentation.
- `CHECKSUMS.sha256` - SHA256 list for release files.

## SHA256

The full checksum list is in `CHECKSUMS.sha256`.
