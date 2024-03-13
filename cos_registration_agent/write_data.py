import logging
import os

logger = logging.getLogger(__name__)


def write_data(data, filename, folder):
    """
    Write data to a file.
    Args:
    - data (str): The data to be written to the file.
    - filename (str): The name of the file to which the data will be written.
    - folder (str, optional): The folder in which the file will be saved. If the 
      folder is a SNAP env path such as $SNAP_COMMON, it will be detected and
      the path built accordingly
    Returns:
    - None: if writing successfull.
    """
    try:
      file_path = os.path.join(folder, filename)
    except Exception as e:
      logging.error(f"Failed to join folder and filename: {folder}, {filename}.")
      raise e

    try:
        with open(file_path, 'w') as file:
            file.write(data)
    except OSError as e:
        logger.error(f"Failed to open {file_path}.")
        raise e
