import logging
import os

logger = logging.getLogger(__name__)


def write_data(data, filename, folder="."):
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
    if folder.startswith('$'):
        env_variable = folder[1:].split('/')[0]  # Extract the environment variable name
        snap_dir = os.environ.get(env_variable)
        if not snap_dir:
            raise ValueError(f"Environment variable {env_variable} not found.")
        file_path = os.path.join(snap_dir, folder[len(env_variable)+2:], filename)
    else:
        file_path = os.path.join(folder, filename)

    try:
        with open(file_path, 'w') as file:
            file.write(data)
    except OSError as e:
        logger.error(f"Failed to open {file_path}.")
        raise e
