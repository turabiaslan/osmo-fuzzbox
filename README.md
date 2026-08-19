# osmo-fuzzbox
2G/3G Fuzzing Pipeline

# Osmo-FuzzBox 📡🔬

> **A Turnkey, Containerized GSM/2G Baseband Fuzzing Pipeline (Podman / Osmocom / USRP B210 / Boofuzz)**

Building the full Osmocom cellular stack from source—with UHD dependencies, firmware images, and dynamic L3 hooks—is notoriously brittle and time-consuming. 

**Baseband-FuzzBox** packages the entire Osmocom stack (`osmo-stp`, `osmo-hlr`, `osmo-mgw`, `osmo-msc`, `osmo-bsc`, `osmo-trx`, `osmo-bts-trx`), UHD hardware drivers, USRP FPGA firmware, and an `LD_PRELOAD` L3/MM mutation hook into a single, air-gappable container image.

---

## ⚠️ Mandatory Safety & RF Confinement

> **CAUTION:** Transmitting GSM bursts over licensed cellular spectrum without authorization is illegal. 
> All testing **MUST** take place inside a verified **Faraday cage** or via direct coaxial cabling with calibrated RF attenuators (30–40 dB minimum).

---

## 🏗️ System Architecture

```
+-----------------------------------------------------------------------------------+
| WINDOWS CONTROLLER (or Host)                                                      |
|                                                                                   |
|  +-----------------------+                    +--------------------------------+  |
|  | Boofuzz Orchestrator  |                    | ADB Crash Oracle / Logcat      |  |
|  | (controller/fuzzer.py)|                    | (Radio buffer monitor)         |  |
|  +-----------+-----------+                    +---------------+----------------+  |
+--------------|------------------------------------------------|-------------------+
               | TCP (Port 27017)                               | USB (ADB)
               v                                                v
+-------------------------------------------------------------+ |
| PODMAN CONTAINER (--net=host, --device=/dev/bus/usb)         | |
|                                                             | |
|  +-------------------------------------------------------+  | |
|  | osmo-msc (with injected fuzz_hook.so via LD_PRELOAD)  |  | |
|  +---------------------------+---------------------------+  | |
|                              | A-Interface (SCCP/M3UA)       | |
|  +---------------------------v---------------------------+  | |
|  | osmo-bsc                                              |  | |
|  +---------------------------+---------------------------+  | |
|                              | Abis over IP                  | |
|  +---------------------------v---------------------------+  | |
|  | osmo-bts-trx                                          |  | |
|  +---------------------------+---------------------------+  | |
|                              | TRXD (UDP)                    | |
|  +---------------------------v---------------------------+  | |
|  | osmo-trx-uhd (libusb + FPGA bitstream loader)         |  | |
|  +---------------------------+---------------------------+  | |
+------------------------------|------------------------------+ |
                               | USB 3.0 (Bulk I/Q Streaming)   |
                               v                                |
                    +--------------------+                      |
                    | USRP B210 (SDR)    |                      |
                    +----------+---------+                      |
                               |                                |
                      RF (In Faraday Cage)                      |
                               v                                |
                    +--------------------+                      |
                    | Target Phone / DUT +<---------------------+
                    +--------------------+
```

---

## 📦 Key Features

- **Zero-Compilation Runtime:** Encapsulates `libosmocore`, `libosmo-abis`, `libosmo-netif`, `libosmo-sccp`, `osmo-hlr`, `osmo-mgw`, `osmo-msc`, `osmo-bsc`, `osmo-trx`, and `osmo-bts`.
- **Air-Gappable:** Pre-bakes UHD FPGA firmware (`usrp_b200_fw.hex`) directly into the image. Exportable as a single `.tar` archive for offline lab hosts.
- **Non-Invasive Protocol Hooking:** Intercepts Mobility Management (MM) downlink transmissions via an `LD_PRELOAD` shim (`fuzz_hook.so`) without patching upstream Osmocom source files.
- **External Driver Compatibility:** Exposes a clean, synchronized TCP frame socket compatible with Boofuzz, Scapy, or custom mutation engines.

---

## 🚀 Quickstart

### Prerequisites
- **Host OS:** Linux (Fedora/RHEL/Ubuntu) with Podman or Docker.
- **Hardware:** Ettus USRP B210 SDR (USB 3.0 connection).
- **Target:** Programmable test SIM card (e.g., COMP128v1 / Milenage) + Android handset with ADB debug enabled.

### 1. Build the Container

```bash
# Clone the repository
git clone [https://github.com/](https://github.com/)<your-username>/baseband-fuzzbox.git
cd baseband-fuzzbox

# Build the container image (Rootful Podman required for USB & host networking)
sudo podman build -t localhost/baseband_fuzzer:v1 .
```

### 2. Export for Air-Gapped Environments (Optional)

```bash
# Save container image to an offline archive
sudo podman save -o baseband_fuzzer_v1.tar localhost/baseband_fuzzer:v1

# On the air-gapped lab machine:
sudo podman load -i baseband_fuzzer_v1.tar
```

### 3. Launch the Stack

```bash
sudo podman run --rm -it \
  --net=host \
  --device=/dev/bus/usb \
  -v /var/log/osmocom:/var/log/osmocom:Z \
  localhost/baseband_fuzzer:v1
```

---

## 🎮 Controller Setup (Boofuzz)

### 1. Offline Dependency Installation

To set up the controller on an air-gapped Windows or Linux controller:

```bash
# Generate wheelhouse on an internet-connected host:
pip download --only-binary=:all: boofuzz colorama tornado pyserial psutil -d ./wheelhouse

# Install on the air-gapped controller:
pip install --no-index --find-links ./wheelhouse boofuzz
```

### 2. Run the Fuzzer Campaign

```bash
# Activate your venv
python controller/fuzzer.py --host <FEDORA_HOST_IP> --port 27017
```

---

## 🔍 Test Execution & Crash Monitoring

Monitor the target phone's baseband radio interface via ADB to catch crashes and assertion failures:

```bash
# Stream and filter radio logcat output
adb logcat -v time -b radio -b main | grep -E "RIL|MODEM|CP_CRASH|Crash|FATAL|EXCEPTION"
```

---

## 📜 Repository Structure

```
├── Dockerfile              # Complete multi-phase build context
├── Makefile                # Build, export, and run shortcuts
├── entrypoint.sh           # Strict daemon startup orchestration
├── configs/                # Osmocom loopback configurations (*.cfg)
├── hook/
│   ├── fuzz_hook.c         # LD_PRELOAD L3/MM interception socket shim
│   └── Makefile            # Hook compilation rules
└── controller/
    ├── fuzzer.py           # Boofuzz TCP driver script
    └── crash_oracle.py     # ADB logcat telemetry monitor
```
