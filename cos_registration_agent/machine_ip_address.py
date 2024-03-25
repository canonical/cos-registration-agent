import logging
import socket

logger = logging.getLogger(__name__)


def get_machine_ip_address() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        logger.error("Failed to get machine id address:", e)
        raise e
