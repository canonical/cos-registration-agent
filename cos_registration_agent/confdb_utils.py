"""Module to read configuration from confdb."""

import json
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


def get_confdb_value(view: str, key: Optional[str] = None) -> Optional[dict]:
    """Get configuration value from confdb view.

    Args:
    - view (str): The confdb view name (e.g., ':device-cos-settings-observe')
    - key (str, optional): Specific key to retrieve. If None, returns all data.

    Returns:
    - dict or str: The configuration data, or None if not available.
    """
    try:
        cmd = ["snapctl", "get", "--view", view, "-d"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        
        if proc.returncode != 0:
            logger.warning(
                f"Could not read from confdb view {view}: {proc.stderr}"
            )
            return None
        
        data = json.loads(proc.stdout)
        
        if key:
            return data.get(key)
        
        return data
    
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse confdb output: {e}")
        return None
    except Exception as e:
        logger.error(f"Error reading from confdb: {e}")
        return None


def get_rob_cos_base_url() -> Optional[str]:
    """Get rob-cos-base-url from confdb.

    Returns:
    - str: The base URL, or None if not available.
    """
    data = get_confdb_value(":device-cos-settings-observe")
    if data:
        return data.get("rob-cos-base-url")
    return None


def get_cos_registration_url() -> Optional[str]:
    """Get complete COS registration URL from confdb.
    
    Combines rob-cos-base-url and registration-server-endpoint.

    Returns:
    - str: The complete registration URL, or None if not available.
    """
    data = get_confdb_value(":device-cos-settings-observe")
    if not data:
        return None
    
    base_url = data.get("rob-cos-base-url")
    endpoint = data.get("registration-server-endpoint", "")
    
    if not base_url:
        return None
    
    # Ensure base_url doesn't end with / and endpoint doesn't start with /
    base_url = base_url.rstrip("/")
    endpoint = endpoint.lstrip("/")
    
    # Combine the URL parts
    if endpoint:
        return f"{base_url}{endpoint}/"
    else:
        return f"{base_url}/"
