import logging

logger = logging.getLogger(__name__)


def get_machine_id() -> str:
    machine_id_path = "/etc/machine-id"
    try:
        with open(machine_id_path) as f:
            return f.read().rstrip()
    except OSError as e:
        logger.error(f"Failed to open {machine_id_path}.")
        raise e
