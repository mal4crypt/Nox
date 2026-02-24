# FRIZZ - Industrial & IoT Protocol Fuzzing Suite

Frizz provide purpose-built fuzzers for industrial and IoT protocols like Modbus, CoAP, Zigbee, and BACnet.

## Modules

### MODX - Modbus TCP/RTU Fuzzer
Targets PLCs and SCADA systems using the Modbus protocol.

**Usage:**
```bash
python nox.py frizz modx --target <IP> --port 502 --confirm-legal
```

**Options:**
- `--target` (Required): Target IP or hostname.
- `--port`: Modbus port (default: 502).
- `--unit`: Unit ID (default: 1).
- `--type`: TCP or RTU (default: tcp).
- `--function`: Specific function code to fuzz.
- `--iterations`: Number of fuzz iterations (default: 100).
- `--output`: Result format (json|csv|txt).

## Requirements
- `pymodbus`
- `scapy`
- `rich`
