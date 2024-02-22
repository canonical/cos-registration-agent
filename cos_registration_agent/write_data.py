import logging
import os

logger = logging.getLogger(__name__)


def write_data(data, filename, folder='SNAP_COMMON'):
    try:
        snap_common_dir = os.environ.get(folder)
    except KeyError as e:
        raise e

    file_path = os.path.join(snap_common_dir, f'{filename}')
    try:
        with open(file_path, 'w') as file:
            file.write(data)
            return True
    except OSError as e:
        logger.error(f"Failed to open {file_path}.")
        raise e
