# restit

Turn simple command scripts into a custom REST API sensor.

## What is restit?

restit lets you create custom monitoring sensors by wrapping simple scripts (bash/python/...). Each script outputs metrics in a standardized format, and restit exposes them via a REST API with multiple output formats (JSON, PRTG, HTML, and plain text). It runs sensors on configurable schedules, caches results in memory and provides a lightweight HTTP server to query the data. This makes it ideal for environments where you need custom metrics without installing heavy monitoring agents, or when integrating with tools like PRTG that support HTTP data endpoints. The intent is that anyone with basic scripting skills can create their own monitoring REST API -> The complex bits are handled by the restit application. You only need to write some scripts to collect and output the data you need.

## Benefits

- **Simple script-based**: Write any script that outputs `VALUE SENSORNAME MESSAGE` format
- **Encrypted storage**: Scripts and results stored in encrypted vaults for obscuring purposes (prevent tampering)
- **Multiple output formats**: JSON, PRTG, HTML (styled UI), and plain text
- **Lightweight**: Single C binary, minimal dependencies
- **Auto-deployment**: Self-extracting installer with systemd service integration
- **Flexible scheduling**: Per-sensor schedule frequencies

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/oli4vr/restit.git
   cd restit
   ```

2. Create your custom scripts (e.g., `myscript.sh`) that output metrics in the format:
   ```
   VALUE SENSORNAME OPTIONAL_MESSAGE
   ```
   Example `df.sh`:
   ```bash
   #!/bin/bash
   df -m | grep '^/' | tr -d '%' | awk '{print $5,$6}'
   ```

3. Edit `main.yml` to add your sensors:
   ```yaml
   - category: oschecks
     type: disk_usage
     interval: 300
     script: df.sh
     shell: /usr/bin/bash
   - category: oschecks
     type: cpu_stats
     interval: 60
     script: cpu.sh
     shell: /usr/bin/bash
   ```

4. Build the application and create the installer package:
   ```bash
   make
   ```

5. Install on your Linux hosts (as root):

   ```bash
   sudo ./restit.DebianGNULinux13trixie.unknown.20260412.sh
   ```


   Or install the generated .rpm or .deb package


6. Query the API:
   ```bash
   curl http://127.0.0.1:40480/html
   curl http://127.0.0.1:40480/text
   curl http://127.0.0.1:40480/json
   curl http://127.0.0.1:40480/prtg
   ```

## main.yml Syntax

```yaml
- category: <group>
  type: <sensor_type>
  interval: <seconds>
  script: <script_path>
  shell: <interpreter>
  time_windows: 00:00-23:59       # optional, default is always
```

| Field | Description |
|-------|-------------|
| `category` | Logical grouping (e.g., `oschecks`, `network`, `application`) |
| `type` | Sensor type within category (e.g., `disk_usage`, `cpu_stats`) |
| `interval` | Pause in seconds between script runs |
| `script` | Path to your script file which will be added to the installer package |
| `shell` | Shell/interpreter to execute the script (e.g., `/usr/bin/bash`, `/usr/bin/python3`) |
| `time_windows` | Comma-separated `HH:MM-HH:MM` windows when the sensor is allowed to run (default `00:00-23:59`) |

Additional fields may be added in future releases — unknown keys are silently ignored.

### Time Windows

The `time_windows` key restricts when a sensor collects data. If the current time falls outside all specified windows, the last cached result is served and the script is skipped until the next window opens.

Example — only check backup logs outside the backup window:
```yaml
- category: backups
  type: log_check
  interval: 300
  script: check_backup.sh
  shell: /usr/bin/bash
  time_windows: 00:00-06:00,18:00-23:59
```

## Important Rules

- Command scripts can be max 7900 bytes (This will be unlimited in the future, once I upgrade to the new evlt code)
- Scripts must output `VALUE SENSORNAME OPTIONAL_MESSAGE` per line
- Each line becomes a separate sensor with its own entry in the output

## REST API Endpoints

All endpoints support filtering and search parameters.

### Base URL
- Default port: `40480`
- Configurable via `RestPort=` in `~/restit.cfg`

### Output Formats

| Endpoint | Format | Description |
|----------|--------|-------------|
| `/json` | JSON | Restit native JSON format (default) |
| `/prtg` | JSON | PRTG "HTTP Data Advanced" format |
| `/html` | HTML | Styled HTML page with modern UI |
| `/text` | Text | Plain text ASCII table |

### Filtering

Filter by category, type, or sensor name in the URL path:

```
http://127.0.0.1:40480/html/oschecks
http://127.0.0.1:40480/prtg/cpu_stats
```

### Search

Search for sensors containing a specific string:

```
http://127.0.0.1:40480/html?search=__PRODUCTION
```

### PRTG Thresholds

Add critical/warning thresholds when using `/prtg`:

| Parameter | Description |
|-----------|-------------|
| `crithigh` | Critical high threshold |
| `warnhigh` | Warning high threshold |
| `critlow` | Critical low threshold |
| `warnlow` | Warning low threshold |

Example:
```
http://127.0.0.1:40480/prtg/disk_usage?crithigh=90&warnhigh=80
```

## Build & Install

```bash
make          # Build the application
make bundle   # Create installer package (restit.*.sh)
make clean    # Remove build artifacts
```

## Uninstall

```bash
sudo ./restit.*.sh -u
```

## Package Formats

- **Installer script**: Self-extracting shell script with embedded tarball
- **RPM**: Generated if `rpmbuild` is installed
- **DEB**: Generated if `rpmbuild` and `alien` are installed

## Example Output

### Text Format Example (`/text`)

```
CATEGORY  TYPE       NAME              VALUE     MESSAGE
oschecks  fs_used    /                 29        
oschecks  perfstats  CPU_SYSTEM        2         
oschecks  perfstats  CPU_USER          4         
oschecks  perfstats  CPU_WAIT          0         
oschecks  perfstats  CPU_IDLE          94        
oschecks  perfstats  MEM_USED          19        
oschecks  perfstats  MEM_SWAPUSED      0         
oschecks  perfstats  MEM_CACHE         64        
```

### HTML Format (`/html`)

Human readable html format with css styling.
