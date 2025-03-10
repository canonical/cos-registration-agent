"""Module to retrieve the machine ip."""

import logging
import urllib.parse
import socket
from pyroute2 import IPRoute

logger = logging.getLogger(__name__)


def get_machine_ip_address(url: str) -> str:
    """Get the machine ip address."""
    try:
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.hostname

        # Resolve hostname to IP address if needed
        try:
            host = socket.gethostbyname(host)
        except socket.gaierror as e:
            logger.error(f"Failed to resolve hostname {host}: {e}")
            raise

        with IPRoute() as ipr:
            route_info = ipr.route("get", dst=host)

        if len(route_info) < 1:
            raise ConnectionError(f"Couldn't reach {host}")

        # We cannot create sockets within snaps.
        # Using pyroute2, this for loop is necessary
        # to deal with the disgraceful tuple provided by IPRoute get.
        for attr in route_info[0]["attrs"]:
            if attr[0] == "RTA_PREFSRC":
                ip_address = attr[1]
        return ip_address
    except ConnectionError as e:
        logger.error("Failed to get machine id address:", e)
        raise e
