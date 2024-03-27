"""Module to retrieve the machine ip."""

import logging
import socket
import urllib.parse

logger = logging.getLogger(__name__)


def get_machine_ip_address(url: str) -> str:
    """Get the machine ip address."""
    try:
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or 80
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, port))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        logger.error("Failed to get machine id address:", e)
        raise e
