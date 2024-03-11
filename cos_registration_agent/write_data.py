import logging
import os

logger = logging.getLogger(__name__)


def write_data(data, filename, snap_folder_env='SNAP_COMMON', folder='rob-cos-shared-data/'):
    """
    Write data to a file.
    Args:
    - data (str): The data to be written to the file.
    - filename (str): The name of the file to which the data will be written.
    - folder (str, optional): The folder in which the file will be saved.
    Returns:
    - None: if writing successfull.
    """

    try:
        snap_dir = os.environ.get(snap_folder_env)
    except KeyError as e:
        raise e

    file_path = os.path.join(snap_dir, folder, f'{filename}')

    try:
        with open(file_path, 'w') as file:
            file.write(data)
    except OSError as e:
        logger.error(f"Failed to open {file_path}.")
        raise e
