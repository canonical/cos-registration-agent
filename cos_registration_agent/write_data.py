import logging
import os

logger = logging.getLogger(__name__)


def write_data(data, filename, folder):
    """Write data to a file.

    Args:
    - data (str): the data to be written to the file.
    - filename (str): the name of the file to which the data will be written.
    - folder (str, optional): the folder in which the file will be saved.
      If the folder is a SNAP env path such as $SNAP_COMMON,
      it will be detected and the path built accordingly.
    Returns:
    - None: if writing successfull.

    """
    file_path = os.path.join(folder, filename)

    try:
        with open(file_path, "w") as file:
            file.write(data)
    except OSError as e:
        logger.error(f"Failed to open {file_path}.")
        raise e
