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


def get_rob_cos_ip() -> Optional[str]:
    """Get rob-cos-ip from confdb.

    Returns:
    - str: The COS IP/hostname, or None if not available.
    """
    data = get_confdb_value(":device-cos-settings-observe")
    if data:
        return data.get("rob-cos-ip")
    return None


def get_model_name() -> Optional[str]:
    """Get model name from confdb.

    Returns:
    - str: The model name, or None if not available.
    """
    data = get_confdb_value(":device-cos-settings-observe")
    if data:
        return data.get("model-name")
    return None


def get_rob_cos_base_url() -> Optional[str]:
    """Get rob-cos-base-url computed from rob-cos-ip and model-name.
    
    Computes the base URL by combining rob-cos-ip and model-name:
    http://{rob-cos-ip}/{model-name}

    Returns:
    - str: The computed base URL, or None if components not available.
    """
    data = get_confdb_value(":device-cos-settings-observe")
    if not data:
        logger.debug("[get_rob_cos_base_url] No data from confdb")
        return None
    
    rob_cos_ip = data.get("rob-cos-ip")
    model_name = data.get("model-name")
    logger.debug(f"[get_rob_cos_base_url] rob-cos-ip from confdb: {rob_cos_ip}")
    logger.debug(f"[get_rob_cos_base_url] model-name from confdb: {model_name}")
    
    # Skip if either is missing or still a placeholder
    if not rob_cos_ip or rob_cos_ip == "rob-cos-ip-placeholder":
        logger.debug("[get_rob_cos_base_url] rob-cos-ip is missing or placeholder")
        return None
    if not model_name or model_name == "model-name-placeholder":
        logger.debug("[get_rob_cos_base_url] model-name is missing or placeholder")
        return None
    
    # Construct the base URL: http://ip/model-name
    base_url = f"http://{rob_cos_ip}/{model_name}"
    logger.debug(f"[get_rob_cos_base_url] computed base URL: {base_url}")
    return base_url


def get_device_uid() -> Optional[str]:
    """Get device UID from confdb.

    Returns:
    - str: The device UID, or None if not available.
    """
    data = get_confdb_value(":device-cos-settings-observe")
    if data:
        return data.get("device-uid")
    return None


def get_cos_registration_url() -> Optional[str]:
    """Get complete COS registration URL from confdb.
    
    Computes base URL from rob-cos-ip and model-name, then combines with
    registration-server-endpoint.

    Returns:
    - str: The complete registration URL, or None if not available.
    """
    # Get the computed base URL
    base_url = get_rob_cos_base_url()
    logger.debug(f"[get_cos_registration_url] base_url from get_rob_cos_base_url(): {base_url}")
    if not base_url:
        return None
    
    # Get endpoint from confdb
    data = get_confdb_value(":device-cos-settings-observe")
    endpoint = data.get("registration-server-endpoint", "") if data else ""
    logger.debug(f"[get_cos_registration_url] endpoint from confdb: {endpoint}")
    
    # Ensure base_url doesn't end with / and endpoint doesn't start with /
    base_url = base_url.rstrip("/")
    endpoint = endpoint.lstrip("/")
    
    # Combine the URL parts
    if endpoint:
        final_url = f"{base_url}{endpoint}/"
    else:
        final_url = f"{base_url}/"
    
    logger.debug(f"[get_cos_registration_url] final URL: {final_url}")
    return final_url
