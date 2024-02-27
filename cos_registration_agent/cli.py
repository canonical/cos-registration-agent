"""CLI interface for cos_registration_agent project."""

import logging

import configargparse

from cos_registration_agent.grafana import Grafana
from cos_registration_agent.machine_id import get_machine_id
from cos_registration_agent.write_data import write_data
from cos_registration_agent.generate_ssh_keys import generate_ssh_keypair
logger = logging.getLogger(__name__)

parser = configargparse.get_argument_parser()

action_subparsers = parser.add_subparsers(dest="action", help="Action to perform")

setup_parser = action_subparsers.add_parser("setup", help="Setup Grafana dashboards")
setup_parser.add_argument("--url", help="COS base IP/URL", type=str)

update_parser = action_subparsers.add_parser("update", help="Update Grafana dashboards")
update_parser.add_argument("--url", help="COS base IP/URL", type=str)

writeuid_parser = action_subparsers.add_parser("write-uid", help="Write device unique ID to $SNAP_COMMON")

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
        machine_id = args.robot_unique_id
    else:
        machine_id = get_machine_id()

    logger.debug(f"Machine id: {machine_id}")

    if  args.action == "write-uid":
        try:
            write_data(machine_id, filename="device_id.txt")
            return
        except Exception as e:
            logger.error(f"Failed to {args.action}: {e}")
            return

    if args.grafana_service_token is None:
        parser.error("--grafana_service_token argument is required")
    if args.grafana_dashboard is None:
        parser.error("--grafana_dashboard argument is required")

    grafana = Grafana(args.url, args.grafana_service_token, machine_id)

    try:
        if args.action == "setup":
            private_key, public_key = generate_ssh_keypair()
            write_data(private_key, "device_private_key", folder="SNAP_USER_COMMON")
            write_data(public_key, "device_public_key.pub", folder="SNAP_USER_COMMON")
            grafana.setup(args.grafana_dashboard)
        elif args.action == "update":
            grafana.update(args.grafana_dashboard)

    except Exception as e:
        logger.error(f"Failed to {args.action}: {e}")

    return
