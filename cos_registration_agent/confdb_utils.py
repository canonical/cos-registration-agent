"""Module to read configuration from device.yaml file synced via confdb."""

import logging
import os
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


def get_config_file_path() -> str:
    """Get the path to the device configuration file.

    Returns:
    - str: Path to device.yaml in $SNAP_COMMON
    """
    snap_common = os.environ.get("SNAP_COMMON", "")
    return os.path.join(snap_common, "device.yaml")


def read_device_config() -> Optional[dict]:
    """Read configuration from device.yaml file.

    Returns:
    - dict: The configuration data, or None if not available.
    """
    config_file = get_config_file_path()

    if not os.path.exists(config_file):
        logger.warning(f"Configuration file {config_file} not found")
        return None

    try:
        with open(config_file, "r") as f:
            data = yaml.safe_load(f)
            return data if data else None
    except (OSError, yaml.YAMLError) as e:  # noqa: B902
        logger.error(f"Failed to read configuration file: {e}")
        return None


def get_device_uid() -> Optional[str]:
    """Get device UID from configuration file.

    Returns:
    - str: The device UID, or None if not available.
    """
    data = read_device_config()
    if data:
        uid = data.get("uid")
        # Skip if still a placeholder
        if uid and uid != "robot-uid-placeholder":
            return uid
    return None


def get_cos_registration_url() -> Optional[str]:
    """Get complete COS registration URL from configuration file.

    Returns:
    - str: The complete registration URL, or None if not available.
    """
    data = read_device_config()
    if data:
        url = data.get("url")
        # Skip if still a placeholder
        if url and "placeholder" not in url:
            # Ensure URL ends with /
            return url if url.endswith("/") else f"{url}/"
    return None
