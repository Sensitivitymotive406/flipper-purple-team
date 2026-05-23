# 01 - PowerShell Execution via Windows Run Dialog

## Attack overview

The Flipper Zero sends a WIN+R keystroke combination to open the Windows Run dialog, waits for it to open, then types a PowerShell command and presses ENTER. The entire sequence takes under two seconds of keyboard input.

The victim sees a brief flash of the Run dialog if they are looking at the screen. In a targeted scenario the attacker plugs in the Flipper while the target is away from the machine.

**MITRE ATT&CK:**
- T1059.001 - Command and Scripting Interpreter: PowerShell
- T1564.003 - Hide Artifacts: Hidden Window

---

## Forensic artifacts generated

This is what fires in the telemetry when the payload runs. These are the exact fields used to build the detection rules.

### Sysmon Event ID 1 (Process Create)

| Field | Value |
|-------|-------|
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `ParentImage` | `C:\Windows\explorer.exe` |
| `CommandLine` | contains `-WindowStyle Hidden` + evasion flags |
| `IntegrityLevel` | `Medium` (no UAC bypass) |

The `explorer.exe` parent is the key indicator. Legitimate PowerShell launched by a user from the taskbar or Start Menu has the same parent, but legitimate usage virtually never includes `-WindowStyle Hidden` combined with download or execution cradles.

### Windows Security Event 4688 (Process Create, if enabled)

Same process details as Sysmon Event ID 1. Requires "Audit Process Creation" + "Include command line" policy enabled.

### PowerShell Script Block Logging - Event ID 4104

If PowerShell Script Block Logging is enabled (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`), every script block executed is logged. The deobfuscated command appears here even if the command line used `-EncodedCommand`.

### USB device events

Before any of the above, Windows registers a new HID keyboard device. The Flipper Zero identifies itself as a USB HID keyboard with a spoofed USB descriptor.

- **Windows Event Log**: `Microsoft-Windows-DriverFrameworks-UserMode/Operational`, Event ID 2003
- **Device Manager**: new HID Keyboard Device entry, immediately removed when Flipper disconnects

---

## Detection rules

### SIGMA

File: [`sigma/win_badusb_powershell_run_dialog.yml`](sigma/win_badusb_powershell_run_dialog.yml)

Logic: `process_creation` where `Image` ends with `powershell.exe`, `ParentImage` ends with `explorer.exe`, `CommandLine` contains `-WindowStyle Hidden` AND any of the evasion/execution indicators.

Severity: **High**

### KQL (Defender for Endpoint / Microsoft Sentinel)

File: [`kql/BadUSBPowerShellRunDialog.kql`](kql/BadUSBPowerShellRunDialog.kql)

Two variants: `DeviceProcessEvents` for Defender for Endpoint, `SecurityEvent` (Event ID 4688) for Sentinel with Windows Security Events.

---

## Purple team exercise

1. Deploy Sysmon on the test machine with a config that logs process creation with command lines
2. Enable PowerShell Script Block Logging via Group Policy
3. Run the payload: plug in the Flipper Zero, select the `.txt` file in the BadUSB app, press OK
4. Within 10 seconds check your SIEM for the rule hit
5. The test payload writes `%TEMP%\badusb_test.txt` - verify the file exists to confirm execution

Expected result: SIGMA rule fires on Sysmon Event ID 1, KQL query returns one result in DeviceProcessEvents.

---

## Tuning notes

**False positives to expect:**
- Software installers that invoke PowerShell via `explorer.exe` (uncommon but possible)
- Some RMM tools that chain through the shell

**Tune by adding exclusions for:**
- Known installer hashes (`sha256` in Sysmon)
- Specific `CommandLine` patterns from approved RMM software

---

## References

- [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Flipper Zero BadUSB documentation](https://docs.flipper.net/bad-usb)
- [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Malware Archaeology Windows logging cheatsheet](https://www.malwarearchaeology.com/cheat-sheets)
