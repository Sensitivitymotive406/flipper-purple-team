# Contributing

## Adding a new entry

Each entry lives in its own numbered directory under the relevant attack category:

```
badusb/
  03-your-attack-name/
    payload.txt          required
    README.md            required
    sigma/
      win_your_rule.yml  required (at least one)
    kql/
      YourQuery.kql      strongly recommended
    elastic/
      your_rule.toml     optional
```

## Requirements for a payload

- Must be valid Flipper Zero BadUSB syntax (Rubber Ducky compatible)
- Must include a REM header with: title, target OS, MITRE techniques, legal disclaimer
- Must be safe to run in a test environment (no production C2, no destructive actions)
- Replace any hardcoded IPs/domains with localhost or clearly marked placeholders

## Requirements for a SIGMA rule

- Must follow current SigmaHQ format (v2 field names)
- `status: test` until validated against real telemetry
- Must include `author: descambiado` and a fresh UUID for `id:`
- False positives section must list at least one realistic scenario
- Target the specific traces from the paired payload, not a generic broad rule

Generate a fresh UUID: `python -c "import uuid; print(uuid.uuid4())"`

## Requirements for a README

The README for each entry must cover:

1. **Attack overview** - what the payload does and why it works
2. **Forensic artifacts** - exact event IDs, field names, and values that appear in telemetry
3. **Detection rules** - brief description of what each rule detects
4. **Purple team exercise** - step-by-step: deploy the payload, check the SIEM, validate the rule
5. **Tuning notes** - realistic false positives and how to exclude them

## Non-ASCII policy

Run before every commit:

```python
import sys
errors = []
for path in sys.argv[1:]:
    for i, line in enumerate(open(path, encoding='utf-8'), 1):
        for j, c in enumerate(line):
            if ord(c) > 127:
                errors.append(f'{path}:{i}:{j}: U+{ord(c):04X}')
if errors:
    [print(e) for e in errors]
    sys.exit(1)
print('clean')
```

## Upstream contributions

Good SIGMA rules from this repo will be submitted to SigmaHQ. Good KQL queries will be submitted to Azure/Azure-Sentinel. The PR descriptions will reference this repo so there is a traceable connection between attack and detection.
