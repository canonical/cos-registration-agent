"""CLI interface for cos_registration_agent project."""

import logging

import configargparse

from cos_registration_agent.grafana import Grafana
from cos_registration_agent.machine_id import get_machine_id
from cos_registration_agent.write_data import write_data

logger = logging.getLogger(__name__)

parser = configargparse.get_argument_parser()

parser.add_argument("--config", is_config_file=True, help="Config file path.")

parser.add_argument("--url", help="COS base IP/URL", type=str)

parser.add_argument(
    "--robot-unique-id",
    help="Robot unique ID, default set to machine ID.",
    type=str,
)

parser.add_argument(
    "action",
    choices=["setup", "update", "get-uid"],
    help="action to perform",
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

    write_data(machine_id)

    if not args.action == "get-uid":
        grafana = Grafana(args.url, args.grafana_service_token, machine_id)

        try:
            if args.action == "setup":
                grafana.setup(args.grafana_dashboard)
            elif args.action == "update":
                grafana.update(args.grafana_dashboard)

        except Exception as e:
            logger.error(f"Failed to {args.action}: {e}")

    return
