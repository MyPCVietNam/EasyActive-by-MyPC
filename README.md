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
```

Real cleanup menu options use `-CreateRestorePoint` by default. If System Restore is disabled, the tool logs a warning and continues.

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
Clean-MAS-Activation.ps1  353A26122FFA38EEF240DF51FC8C256BC3410BBA3280214CA393AC1FBCBD1A0A
Clean-MAS-Activation.cmd  C3981DAD828B833611C7112928B87721026AE3E810AFB177F7EEFF3F7743920C
DeActive-by-MyPC.bat     0693164C6DD3F19460DA8A273CDCFCF4B1216987F18894FED9DD40277974D6CD
README.md                See CHECKSUMS.sha256
```

`README.md` cannot contain its own final full-file SHA256 without changing that SHA256. The authoritative full-file checksum list, including `README.md`, is in `CHECKSUMS.sha256`.
