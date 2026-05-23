# 03 - Terminal Command Execution via Spotlight (macOS)

## Attack overview

The Flipper Zero sends CMD+Space to open Spotlight, types "Terminal", presses Enter, waits for
Terminal.app to open, then types a command and sends Enter. The entire keystroke sequence takes
under three seconds.

No privilege escalation is involved. The payload runs as the currently logged-in user. If the
screen is locked the attack fails - the payload requires an active unlocked session.

**MITRE ATT&CK:**
- T1059.004 - Command and Scripting Interpreter: Unix Shell
- T1200 - Hardware Additions

---

## Forensic artifacts generated

### Process creation (Sysmon for macOS / EDR)

The process chain that fires:

```
/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal
  -> /bin/zsh (interactive)
    -> /usr/bin/curl (or whatever the payload runs)
```

On Sysmon for macOS (Event ID 1):

| Field | Value |
|-------|-------|
| `Image` | `/bin/zsh` or `/bin/bash` |
| `ParentImage` | `.../Terminal.app/Contents/MacOS/Terminal` |
| `CommandLine` | command typed by the payload |

The shell that Terminal spawns is interactive (no `-c` flag). The child process it calls is where
the payload actually executes - that is the process to alert on.

### macOS Unified Log

USB HID device registration appears before any keystroke activity:

```
log show --predicate 'subsystem == "com.apple.iokit.IOUSBHost"' --last 5m
```

Look for a new HID keyboard device with a vendor/product ID consistent with Flipper Zero or
generic HID class. The device registration timestamp will precede the Terminal process creation
by 1-3 seconds.

Terminal launch via Spotlight appears in the log under WindowServer and Dock:

```
log show --predicate 'process == "Terminal" or process == "Spotlight"' --last 5m
```

### Shell history

Commands typed by the payload appear in `~/.zsh_history` or `~/.bash_history` with a timestamp
matching the event. The history entry is indistinguishable from a manually typed command.

### File system artifact

The test payload writes `/tmp/badusb_test.txt`. Verify execution by checking this file exists.

---

## Detection rules

### SIGMA

File: [`sigma/mac_badusb_terminal_execution.yml`](sigma/mac_badusb_terminal_execution.yml)

Logic: process_creation on macOS where `ParentImage` ends with `/Terminal` and a shell is
spawned, AND that shell subsequently spawns a network or execution tool (`curl`, `wget`,
`python3`, `osascript`, etc.) with command-line indicators of remote execution.

Severity: **medium** (high false positive rate without USB HID event correlation)

---

## Purple team exercise

1. Deploy Sysmon for macOS on the test machine with process creation logging enabled
2. Plug in the Flipper Zero, select the `.txt` file in the BadUSB app, press OK
3. Observe Terminal.app open and the command execute
4. Verify `/tmp/badusb_test.txt` exists
5. Check Sysmon logs for Event ID 1 matching the Terminal -> shell -> child chain

Expected result: SIGMA rule fires on the child process creation (curl/python/etc.) with
Terminal.app in the ancestor chain.

---

## Tuning notes

**False positives:**
- Developer workflows: `brew install`, `pip install`, any interactive curl call from Terminal
- CI scripts launched from Terminal during testing

**Tune by:**
- Adding USB HID device event correlation as a prerequisite (reduces FP rate significantly)
- Restricting `CommandLine` to known-bad patterns (base64 decode, pipe to sh, download-and-exec)
- Excluding known developer tool paths in `Image`

**Stronger signal:** correlate Sysmon Event ID 11 (file create in `/tmp/`) within 10 seconds
of a USB HID device registration from an unknown vendor.

---

## References

- [MITRE T1059.004](https://attack.mitre.org/techniques/T1059/004/)
- [Sysmon for macOS](https://github.com/Sysinternals/SysmonForMac)
- [Flipper Zero BadUSB documentation](https://docs.flipper.net/bad-usb)
- [Apple Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity)
