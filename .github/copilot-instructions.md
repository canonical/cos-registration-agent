# cos-registration-agent: AI Agent Instructions

## Role
**Observer snap** - Reads configuration from confdb and registers devices with COS (Canonical Observability Stack).

## Key Responsibilities
1. **Device Registration:** Register device with COS server (setup action)
2. **Configuration Updates:** Update dashboards, alerts, TLS certs (update action)
3. **Device Removal:** Unregister from COS server (delete action)
4. **Configuration Priority:** Confdb → CLI args → config file → defaults

## Configuration Priority System

### Implementation (cli.py)
```python
# Device UID Priority (lines 213-222)
confdb_device_uid = get_device_uid()  # Try confdb first
if confdb_device_uid:
    device_id = confdb_device_uid
elif args.uid:                         # Then CLI arg
    device_id = args.uid
else:                                  # Finally machine-id
    device_id = get_machine_id()

# URL Priority (lines 236-242)
confdb_url = get_cos_registration_url()  # Try confdb first
if confdb_url:
    args.url = confdb_url
else:
    if not args.url:                      # Error if no CLI arg either
        logger.error("No COS URL provided")
```

### Why This Matters
- **Production:** Confdb provides consistent config across devices
- **Development/Testing:** CLI args override for one-off changes
- **Standalone/Legacy:** Config file works without confdb connection

## Confdb Utilities (confdb_utils.py)

### Core Functions
```python
get_device_uid() -> Optional[str]
    # Returns device-uid from confdb, None if unavailable

get_rob_cos_ip() -> Optional[str]
    # Returns rob-cos-ip, None if placeholder

get_model_name() -> Optional[str]
    # Returns model-name, None if placeholder

get_rob_cos_base_url() -> Optional[str]
    # COMPUTES: http://{rob-cos-ip}/{model-name}
    # Returns None if either component is placeholder

get_cos_registration_url() -> Optional[str]
    # COMPUTES: {base_url}{registration-server-endpoint}/
    # Returns None if base_url is None
```

### Placeholder Detection
```python
# In get_rob_cos_base_url():
if rob_cos_ip == "rob-cos-ip-placeholder":
    return None  # Don't use placeholder values
```

## Snapcraft.yaml Patterns

### Confdb Plug (Observer)
```yaml
plugs:
  device-cos-settings-observe:
    interface: confdb
    account: VX84EGFo6txXHSNk4l55reEiaU5n7I7R
    view: device-cos-settings/observe-device-cos-settings
    # No role = observer (read-only)
```

### Content Plug (Legacy Fallback)
```yaml
plugs:
  configuration-read:
    interface: content
    target: $SNAP_COMMON/configuration
```

## Usage Patterns

### With Confdb (Recommended)
```bash
# Connect confdb interface
sudo snap connect cos-registration-agent:device-cos-settings-observe

# Use without --url or --uid flags (reads from confdb)
cos-registration-agent setup
cos-registration-agent update
cos-registration-agent delete
```

### Without Confdb (Standalone)
```bash
# Must specify URL explicitly
cos-registration-agent --url http://192.168.1.100:8000/production-fleet-cos-registration-server/ setup
```

### Override Confdb (Testing)
```bash
# Use different URL than confdb
cos-registration-agent --url http://test-server:8000/test/ update

# Use different UID
cos-registration-agent --uid test-device-123 setup
```

## Adding New Confdb Fields

### 1. Add Getter Function (confdb_utils.py)
```python
def get_new_field() -> Optional[str]:
    """Get new-field from confdb."""
    data = get_confdb_value(":device-cos-settings-observe")
    if data:
        return data.get("new-field")
    return None
```

### 2. Use in CLI (cli.py)
```python
from cos_registration_agent.confdb_utils import get_new_field

# In main():
confdb_field = get_new_field()
if confdb_field:
    logger.info(f"Using field from confdb: {confdb_field}")
    args.field = confdb_field
```

### 3. Add Shell Helper (snap/local/get-confdb-config.sh)
```bash
case "$1" in
    new-field)
        snapctl get --view :device-cos-settings-observe new-field
        ;;
esac
```

## Hook Patterns

### Remove Hook (snap/hooks/remove)
```bash
# Computes URL from confdb to unregister
BASE_URL=$(/snap/cos-registration-agent/current/snap/local/get-confdb-config.sh)
if [ -n "$BASE_URL" ]; then
    cos-registration-agent delete --url "$BASE_URL"
fi
```

**Key:** Hook uses confdb to get URL, doesn't hardcode anything.

## Testing & Debugging

### Check Confdb Values
```bash
sudo snap run --shell cos-registration-agent
snapctl get --view :device-cos-settings-observe -d | jq
```

### Test Configuration Priority
```python
# In Python shell
from cos_registration_agent.confdb_utils import *
print(get_device_uid())              # From confdb
print(get_rob_cos_base_url())        # Computed from components
print(get_cos_registration_url())    # Full URL
```

### Debug Priority Logic
```bash
# Enable debug logging
cos-registration-agent --log-level DEBUG setup

# Should see logs like:
# INFO: Using device UID from confdb: abc123
# INFO: Using COS URL from confdb: http://...
```

### Test Without Confdb
```bash
# Disconnect confdb
sudo snap disconnect cos-registration-agent:device-cos-settings-observe

# Now must use CLI args
cos-registration-agent --url http://server/ setup
```

## Common Pitfalls

❌ **Storing URLs in confdb** - URLs are computed at runtime  
❌ **Missing None checks** - Always check if confdb functions return None  
❌ **Hardcoding view names** - Use `:device-cos-settings-observe` consistently  
❌ **Ignoring placeholders** - Functions return None for "...-placeholder" values  
❌ **Breaking priority order** - Always: confdb → CLI → config → defaults  

## Development Workflow

### 1. Build & Install
```bash
snapcraft
sudo snap install cos-registration-agent_*.snap --dangerous
```

### 2. Connect Interfaces
```bash
# Connect confdb (requires rob-cos-demo-configuration installed)
sudo snap connect cos-registration-agent:device-cos-settings-observe

# Connect content interface (legacy)
sudo snap connect cos-registration-agent:configuration-read rob-cos-demo-configuration:configuration-read
```

### 3. Verify Configuration
```bash
# Check what values are available
sudo snap run --shell cos-registration-agent
snapctl get --view :device-cos-settings-observe -d
```

### 4. Run Actions
```bash
# Setup (registers device)
sudo cos-registration-agent setup

# Update (patches configuration)
sudo cos-registration-agent update

# Delete (unregisters device)
sudo cos-registration-agent delete
```

## Code Style

### Logging Conventions
```python
logger.info(f"Using device UID from confdb: {confdb_device_uid}")
logger.info(f"Using device UID from command line argument: {args.uid}")
logger.info("Using device UID from machine-id")
logger.error("No COS URL provided via --url or confdb")
```

**Pattern:** Always log which source provided the value.

### Error Handling
```python
# In confdb_utils.py
try:
    cmd = ["snapctl", "get", "--view", view, "-d"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    
    if proc.returncode != 0:
        logger.warning(f"Could not read from confdb view {view}: {proc.stderr}")
        return None
        
except Exception as e:
    logger.error(f"Error reading from confdb: {e}")
    return None
```

**Pattern:** Warning for expected failures (confdb unavailable), error for unexpected.

## External Integration

### COS Server Expectations
- **Endpoint:** `{rob-cos-base-url}{registration-server-endpoint}/`
- **TLS:** Uses `REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt`
- **Authentication:** Device UID sent in requests

### rob-cos-demo-configuration Dependency
- **Confdb Schema:** Must be signed and acknowledged
- **Schema Revision:** Currently revision 8
- **Account:** `VX84EGFo6txXHSNk4l55reEiaU5n7I7R`
