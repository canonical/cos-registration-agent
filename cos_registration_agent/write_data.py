import logging
import os

logger = logging.getLogger(__name__)


def write_data(data):
    snap_common_dir = os.environ.get('SNAP_COMMON')

    file_path = os.path.join(snap_common_dir, 'robot_id.txt')
    try:
        with open(file_path, 'w') as file:
            file.write(data)
            return True
    except OSError as e:
        logger.error(f"Failed to open {file_path}.")
        raise e
