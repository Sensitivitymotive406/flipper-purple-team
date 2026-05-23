# Sub-GHz Replay Attacks

## Detection scope

Sub-GHz replay attacks (garage doors, key fobs, barrier systems) operate below the layer where standard SIEM telemetry exists. There is no Windows event log entry for a garage door opening.

Detection is possible only via:

- **Physical access control systems** that log all badge/fob events - correlate unexpected opens with no corresponding badge swipe
- **RF monitoring systems** (SDR-based IDS) that detect retransmissions of captured signals
- **Video surveillance** correlated with physical access logs

## What Flipper Zero does

The Flipper Zero Sub-GHz module captures and replays RF signals in the 300-928 MHz range. Common targets:

| Target | Frequency | Protocol | Detectable? |
|--------|-----------|----------|-------------|
| Garage doors | 315/433/868 MHz | Fixed code / rolling code | Only via physical logs |
| Key fobs (older) | 433 MHz | Fixed code | Only via physical logs |
| TPMS sensors | 315/433 MHz | Proprietary | No |
| Temperature sensors | 433 MHz | Proprietary | No |

Rolling code systems (KeeLoq, etc.) are not replayable with stock Flipper Zero firmware. Fixed-code systems are.

## Physical access log correlation (KQL example)

If your physical access control system forwards events to your SIEM:

```kql
// Doors opened without a corresponding authorized badge event
let AuthorizedOpens =
    PhysicalAccessLog
    | where EventType =~ "BadgeAccess" and Result =~ "Granted"
    | project TimeGenerated, DoorId, BadgeId;
PhysicalAccessLog
| where EventType =~ "DoorOpen"
| join kind=leftanti AuthorizedOpens on DoorId
    , $left.TimeGenerated between ((AuthorizedOpens.TimeGenerated - 5s) .. (AuthorizedOpens.TimeGenerated + 5s))
| project TimeGenerated, DoorId, EventType
| sort by TimeGenerated desc
```

Adapt field names to your access control system's log schema.

## Hardening recommendations

- Upgrade fixed-code systems to rolling code
- Deploy CCTV at all RF-controlled entry points
- Log all door-open events regardless of authorization status
- Alert on door-open events outside business hours
