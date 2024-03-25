"""CLI interface for cos_registration_agent project."""

import logging

import configargparse
import os
from pathlib import Path

from cos_registration_agent.cos_registration_agent import CosRegistrationAgent
from cos_registration_agent.machine_id import get_machine_id
from cos_registration_agent.machine_ip_address import get_machine_ip_address
from cos_registration_agent.write_data import write_data
from cos_registration_agent.ssh_key_manager import SSHKeysManager

logger = logging.getLogger(__name__)

parser = configargparse.get_argument_parser()


def list_of_strings(arg):
    """Split list of strings arguments."""
    return arg.split(",")


action_subparsers = parser.add_subparsers(
    dest="action", help="Action to perform"
)

# Arguments to setup and register the cos device
setup_parser = action_subparsers.add_parser(
    "setup", help="Add custom device dashboards and register device"
)
setup_parser.add_argument("--url", help="COS base IP/URL", type=str)
setup_parser.add_argument(
    "--grafana-dashboards",
    help="path to the grafana dashboard",
    type=Path,
)
setup_parser.add_argument(
    "--foxglove-studio-dashboards",
    help="path to the foxglove dashboard",
    type=Path,
)
setup_parser.add_argument(
    "--device-grafana-dashboards",
    help="list of grafana dashboards used by this device",
    type=list_of_strings,
    default=[],
)
setup_parser.add_argument(
    "--device-foxglove-dashboards",
    help="list of foxglove dashboards used by this device",
    type=list_of_strings,
    default=[],
)

update_parser = action_subparsers.add_parser(
    "update", help="Update custom device infos"
)

# Arguments to update the cos device and its dashboards
update_parser.add_argument("--url", help="COS base IP/URL", type=str)
update_parser.add_argument(
    "--update-ssh-keys",
    help="Update device public ssh keys",
    action="store_true",
)
update_parser.add_argument(
    "--device-grafana-dashboards",
    help="Update device grafana dashboards list",
    type=list_of_strings,
)
update_parser.add_argument(
    "--device-foxglove-dashboards",
    help="Update device foxglove dashboards list",
    type=list_of_strings,
)
update_parser.add_argument(
    "--grafana-dashboards",
    help="Update grafana dashboards",
    type=list_of_strings,
)
update_parser.add_argument(
    "--foxglove-studio-dashboards",
    help="Update foxglove studio dashboards foxglove dashboard",
    type=list_of_strings,
)


writeuid_parser = action_subparsers.add_parser(
    "write-uid", help="Write device unique ID to $SNAP_COMMON"
)

parser.add_argument(
    "--shared-data-path",
    help="The path to which the relevant common devices app files \
          such as robot-unique-id are stored.",
    type=str,
    default=os.getcwd(),
)

delete_parser = action_subparsers.add_parser(
    "delete", help="Delete device from server"
)
delete_parser.add_argument("--url", help="COS base IP/URL", type=str)

parser.add_argument("--config", is_config_file=True, help="Config file path.")

parser.add_argument(
    "--robot-unique-id",
    help="Robot unique ID, default set to machine ID.",
    type=str,
)

parser.add_argument(
    "--log-level",
    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    help="set the logging level",
)

args = parser.parse_args()


def main():  # pragma: no cover

    if args.log_level:
        logging.basicConfig(level=getattr(logging, args.log_level))

    if args.robot_unique_id:
        device_id = args.robot_unique_id
    else:
        device_id = get_machine_id()

    logger.debug(f"Machine id: {device_id}")

    device_ip_address = get_machine_ip_address()
    logger.debug(f"Machine ip address: {device_ip_address}")

    if args.action == "write-uid":
        try:
            write_data(
                device_id,
                filename="device_id.txt",
                folder=args.shared_data_path,
            )
            return
        except Exception as e:
            logger.error(f"Failed to {args.action}: {e}")
            return

    cos_registration_agent = CosRegistrationAgent(args.url)
    ssh_key_manager = SSHKeysManager()

    try:
        if args.action == "setup":
            public_ssh_key = ssh_key_manager.setup(
                folder=args.shared_data_path
            )
            if args.grafana_dashboards:
                cos_registration_agent.add_dashboards(
                    dashboard_path=args.grafana_dashboards,
                    application="grafana",
                )
            if args.foxglove_studio_dashboards:
                cos_registration_agent.add_dashboards(
                    dashboard_path=args.foxglove_studio_dashboards,
                    application="foxglove",
                )
            cos_registration_agent.register_device(
                uid=device_id,
                address=device_ip_address,
                public_ssh_key=public_ssh_key,
                grafana_dashboards=args.device_grafana_dashboards,
                foxglove_dashboards=args.device_foxglove_dashboards,
            )
        elif args.action == "update":
            data_to_update = {}
            data_to_update["address"] = get_machine_ip_address()
            if args.update_ssh_keys:
                public_ssh_key = ssh_key_manager.setup(
                    folder=args.shared_data_path
                )
                data_to_update["public_ssh_key"] = public_ssh_key
            if args.device_grafana_dashboards:
                data_to_update[
                    "grafana_dashboards"
                ] = args.device_grafana_dashboards
            if args.device_foxglove_dashboards:
                data_to_update[
                    "foxglove_dashboards"
                ] = args.device_foxglove_dashboards
            if args.grafana_dashboards:
                cos_registration_agent.patch_dashboards(
                    args.grafana_dashboards
                )
            if args.foxglove_studio_dashboards:
                cos_registration_agent.patch_dashboards(
                    args.foxglove_dashboards
                )
            cos_registration_agent.patch_device(device_id, data_to_update)
        elif args.action == "delete":
            cos_registration_agent.delete_device(device_id)

    except Exception as e:
        logger.error(f"Failed to {args.action}: {e}")

    return
