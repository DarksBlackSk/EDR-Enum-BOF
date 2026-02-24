# EDR-Enum-BOF — AdaptixC2 Extension

Service and driver enumeration BOF for [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2), ported from [CS-EDR-Enumeration](https://github.com/VirtualAllocEx/CS-EDR-Enumeration) by VirtualAllocEx.

Enumerates running Win32 services and kernel drivers via the Service Control Manager (SCM), then automatically cross-references the results against a signature database of **444 signatures across 48 security vendors** to identify AV, EDR, and EPP products present on the target.

**NOISE: \* MINIMAL** — runs entirely in-process inside the agent. No child processes, no PowerShell, no CLR load, no ETW providers triggered.

---

## Commands

| Command | Description |
|---|---|
| `edr_both` | Enumerate services + drivers (default) |
| `edr_svc` | Enumerate Win32 services only |
| `edr_drv` | Enumerate kernel drivers only |

---

## Output example

```
====================================================
  [~] THREAT LEVEL: MODERATE - AV + Telemetry
====================================================

Services matched (6):
  [AV]        Microsoft - Defender Core Service  (MDCoreSvc)
  [AV]        Microsoft - Defender Firewall  (mpssvc)
  [AV]        Microsoft - Security Health  (SecurityHealthService)
  [Telemetry] Microsoft - Sysmon 64  (Sysmon64)
  [AV]        Microsoft - Windows Defender AV  (WinDefend)
  [AV]        Microsoft - Security Center  (wscsvc)

Drivers matched (2):
  [Telemetry] Microsoft - Sysmon Driver  (SysmonDrv)
  [AV]        Microsoft - Defender Minifilter  (WdFilter)

88 services + 121 drivers enumerated  |  6 svc + 2 drv hits
```

### Threat levels

| Level | Meaning |
|---|---|
| `HIGH` | EDR detected — kernel callbacks, behavioral engine, cloud analytics likely active |
| `MODERATE` | AV + Telemetry — scanning and event forwarding to SOC |
| `LOW-MOD` | AV only — file scanning and heuristics |
| `LOW` | EPP / non-EDR — minimal real-time capability |
| `UNKNOWN` | No matches — may be agentless EDR, NDR, or custom service names |

### Signature database

444 signatures across 48 vendors including: CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender/MDE, Cortex XDR, Elastic, Symantec, Sophos, Trend Micro, Trellix/McAfee, ESET, Kaspersky, Bitdefender, Cylance, Fortinet, Cybereason, HarfangLab, Avast/AVG, Malwarebytes, Avira, Norton/Gen Digital, Check Point, Comodo/Xcitium, G Data, Emsisoft, Dr.Web, AhnLab, VIPRE, Cisco Secure Endpoint, Zscaler, and more.

---

## Requirements

- [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2)
- `x86_64-w64-mingw32-gcc` (MinGW cross-compiler)

---

## Build

```bash
# Install MinGW if needed
sudo apt install mingw-w64

# Compile
mkdir -p _bin
make all        # _bin/edr_enum_bof.x64.o & _bin/edr_enum_bof.x86.o
make x64        # produces _bin/edr_enum_bof.x64.o
make x86        # produces _bin/edr_enum_bof.x86.o
```

---

## Installation

1. Load the edr_enum.axs script into your Adaptix client.

<img width="1222" height="755" alt="image" src="https://github.com/user-attachments/assets/e550296a-704c-466c-9189-205ce8378226" />

2. Run against any Windows beacon:

```
edr_both
edr_svc
edr_drv
```

<img width="1541" height="459" alt="image" src="https://github.com/user-attachments/assets/54f001b2-d801-43fb-98f2-a157627a3acc" />

<img width="1685" height="876" alt="image" src="https://github.com/user-attachments/assets/dbb35754-6256-4734-aabe-10ab52ebfef4" />

---

## Project structure

```
edr_enum/
├── edr_enum.axs          # AdaptixC2 extension (JS) — load this in the C2
├── Makefile
├── _bin/
│   └── edr_enum_bof.x64.o
│   └── edr_enum_bof.x86.o
└── src/
    ├── edr_enum_bof.c    
    ├── beacon.h          
    ├── bofdefs.h         
    └── base.c           
```

---

## Credits

- [VirtualAllocEx](https://github.com/VirtualAllocEx) — original [CS-EDR-Enumeration](https://github.com/VirtualAllocEx/CS-EDR-Enumeration) for Cobalt Strike (signature database + BOF logic)
- [Adaptix-Framework](https://github.com/Adaptix-Framework) — AdaptixC2 and Extension-Kit
