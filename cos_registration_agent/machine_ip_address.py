"""Module to retrieve the machine ip."""

import logging
import socket
import urllib.parse

from pyroute2 import IPRoute

logger = logging.getLogger(__name__)


def get_machine_ip_address(url: str) -> str:
    """Get the machine ip address.

    Args:
        url (str): The URL to resolve.

    Returns:
        str: The machine's source IP address used to reach the provided url.

    Raises:
        ValueError: when the URL does not have a hostname.
        ConnectionError: If the hostname cannot be resolved
          or the route can't be determined.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.hostname

        if host is None:
            raise ValueError(f"Invalid URL, no hostname found: {url}")

        # Resolve hostname to IP address if needed
        try:
            host = socket.gethostbyname(host)
        except socket.gaierror as e:
            logger.error(f"Failed to resolve hostname {host}: {e}")
            raise ConnectionError(f"Failed to resolve hostname {host}") from e

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
                break

        return ip_address
    except ConnectionError as e:
        logger.error("Failed to get machine id address:", e)
        raise e
