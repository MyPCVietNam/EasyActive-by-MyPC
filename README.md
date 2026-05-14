# DeActive by MyPC

Version: `1.2.0`

`DeActive by MyPC` is a conservative Windows/Office activation cleanup tool for IT technicians who need to remove non-standard MAS/KMS-style activation configuration so the machine can be activated again with a legitimate Windows digital license, product key, Microsoft account, or Microsoft 365 account.

## Files

- `DeActive-by-MyPC.bat` - public branded launcher; calls the `.cmd` file.
- `Clean-MAS-Activation.cmd` - backend launcher with a simple menu.
- `Clean-MAS-Activation.ps1` - main PowerShell 5.1+ implementation.

## Menu

Run `DeActive-by-MyPC.bat` as Administrator, then choose:

```text
1. Dry-run only (simulate cleanup, no changes)
2. Clean Office and Windows activation keys/configuration
3. Clean Office activation keys/configuration only
4. Clean Windows activation keys/configuration only
5. Read OEM embedded key from motherboard / BIOS / UEFI
```

Real cleanup menu options use `-CreateRestorePoint` by default. If System Restore is disabled, the tool logs a warning and continues.

Menu option 5 is read-only. It does not create a restore point, remove keys, install keys, activate Windows, restart licensing services, or call `slmgr /ipk` / `slmgr /ato`.

## Read OEM Embedded Key

The tool can read the Windows product key embedded in motherboard BIOS/UEFI firmware by querying `SoftwareLicensingService.OA3xOriginalProductKey`.

Notes:

- Not all machines have an embedded OEM key.
- The OEM key is usually tied to the original Windows edition shipped with the device.
- If the current installed Windows edition does not match the OEM key edition, activation may fail.
- With MAS HWID/Digital License activation, this tool cannot remove Microsoft server-side digital entitlement for the device hardware.
- This function is read-only and does not activate Windows.
- Product keys are sensitive. By default, the console and reports show a masked key like `XXXXX-XXXXX-XXXXX-XXXXX-ABCDE`.
- Advanced PowerShell parameters are available: `-ReadOEMKeyOnly`, `-ShowFullKeys`, and `-ExportSensitiveKeys`. Use `-ExportSensitiveKeys` only when the generated report will be kept private.

## Safety Notes

- Close all Office apps before Office cleanup.
- Windows key cleanup warns before running `slmgr /upk`.
- A Windows Digital License / HWID entitlement is stored by Microsoft's activation service for the device hardware. This tool can remove local product keys and KMS/MAS configuration, but it does not remove a legitimate Microsoft digital license; after cleanup Windows may reactivate automatically when online.
- Registry keys are exported before registry modification.
- File/folder cleanup prefers rename-to-`.bak` unless a force mode is used manually.
- The default menu does not install `PostRebootSweep`; that feature remains available only through explicit PowerShell parameters.
- The tool does not clear Event Logs, Defender history, Prefetch, Amcache, ShimCache, SRUM, or other forensic artifacts.
- The tool does not activate Windows/Office, install KMS emulators, or contact KMS/MAS servers.

## Logs, Backups, Reports

Default locations:

```text
C:\ProgramData\LegitActivationCleaner\Logs
C:\ProgramData\LegitActivationCleaner\Backups
C:\ProgramData\LegitActivationCleaner\Reports
```

The ProgramData folder name is kept for compatibility with earlier builds; the public tool name is `DeActive by MyPC`.

## Compatibility Target

- Windows 10, Windows 11, Windows Server, LTSC, Enterprise editions where Windows PowerShell 5.1+ is available.
- Office 2007 through Microsoft 365, including MSI and Click-to-Run where relevant local licensing components exist.
- 32-bit and 64-bit Office paths.

Unsupported or missing components are skipped with log entries instead of crashing.

## SHA256

```text
Clean-MAS-Activation.ps1  B4567ECC3FBF5655B999D464B700BA5F2032154E65FD5CBF17DCB8DCA468EFEF
Clean-MAS-Activation.cmd  8FFD65C68ACFA71470C3CFD00B8A7D0C66A8B495D36CD9D56662E9185F8DBDD2
DeActive-by-MyPC.bat     6FD540C65395B12D3469427C7C33626EEF837DE93810C49A0359D36B84E61713
README.md                See CHECKSUMS.sha256
```

`README.md` cannot contain its own final full-file SHA256 without changing that SHA256. The authoritative full-file checksum list, including `README.md`, is in `CHECKSUMS.sha256`.
