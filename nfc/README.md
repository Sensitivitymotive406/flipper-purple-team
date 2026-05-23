# NFC / RFID Cloning

## Detection scope

NFC/RFID badge cloning with Flipper Zero produces no telemetry in standard SIEM sources. The cloned badge looks identical to the original at the reader level.

Detection relies entirely on:

- **Physical access control system logs** - the cloned badge triggers events under the original badge ID
- **Behavioral anomaly** - original badge holder already badged in, but badge swipe detected at a second location

## Detectable patterns

### Simultaneous use of the same badge

The same badge ID appears at two different readers within a time window shorter than the travel time between them. This is the strongest indicator of cloning.

```kql
// Badge used at two locations simultaneously (within 2-minute window)
let Swipes =
    PhysicalAccessLog
    | where EventType =~ "BadgeAccess"
    | project TimeGenerated, DoorId, BadgeId, Location;
Swipes
| join kind=inner Swipes on BadgeId
| where DoorId != DoorId1
| where abs(datetime_diff('second', TimeGenerated, TimeGenerated1)) < 120
| where Location != Location1
| project TimeGenerated, BadgeId, Location, Location1, DoorId, DoorId1
| sort by TimeGenerated desc
```

### Badge access outside normal hours

```kql
PhysicalAccessLog
| where EventType =~ "BadgeAccess" and Result =~ "Granted"
| where hourofday(TimeGenerated) < 7 or hourofday(TimeGenerated) > 20
| where dayofweek(TimeGenerated) in (0d, 6d)  // weekend
| project TimeGenerated, BadgeId, DoorId, Location
| sort by TimeGenerated desc
```

## What Flipper Zero can clone

| Card type | Cloneable | Notes |
|-----------|-----------|-------|
| EM4100 / HID Prox (125kHz) | Yes | Most common legacy card, trivially cloned |
| HID iCLASS (13.56 MHz) | Partially | Standard iCLASS cloneable, SE/Elite not |
| MIFARE Classic 1K | Yes | Crypto1 is broken, full clone possible |
| MIFARE Plus / DESFire | No | AES-based, not cloneable with Flipper |
| Apple/Google Wallet NFC | No | Secure element protected |

## Hardening recommendations

- Migrate from 125kHz legacy cards to MIFARE DESFire EV2/EV3 or equivalent
- Implement multi-factor physical access (badge + PIN) for sensitive areas
- Enable anti-passback in access control systems
- Alert on after-hours badge activity and simultaneous location conflicts
