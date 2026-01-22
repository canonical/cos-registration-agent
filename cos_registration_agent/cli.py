"""CLI interface for cos_registration_agent project."""

import logging
import os
from pathlib import Path

import configargparse
from configargparse import ArgumentParser

from cos_registration_agent.cos_registration_agent import CosRegistrationAgent
from cos_registration_agent.machine_id import get_machine_id
from cos_registration_agent.machine_ip_address import get_machine_ip_address
from cos_registration_agent.ssh_key_manager import SSHKeysManager
from cos_registration_agent.write_data import write_data


def _parse_args() -> ArgumentParser.parse_args:

    parser = configargparse.get_argument_parser()

    action_subparsers = parser.add_subparsers(
        dest="action",
        help="Action to perform",
        parser_class=configargparse.ArgParser,
    )

    # Arguments to setup and register the cos device
    setup_parser = action_subparsers.add_parser(
        "setup", help="Register device and add custom dashboards"
    )
    setup_parser.add_argument(
        "--uid",
        help="Robot unique ID, default set to machine ID.",
        type=str,
    )
    setup_parser.add_argument("--url", help="COS base IP/URL", type=str)

    setup_parser.add_argument(
        "--device-grafana-dashboards",
        help="List of grafana dashboards used by this device",
        nargs="+",
        default=[],
    )
    setup_parser.add_argument(
        "--device-foxglove-dashboards",
        help="List of foxglove dashboards used by this device",
        nargs="+",
        default=[],
    )
    setup_parser.add_argument(
        "--device-loki-alert-rule-files",
        help="list of Loki alert rule files to render for this device",
        nargs="+",
        default=[],
    )
    setup_parser.add_argument(
        "--device-prometheus-alert-rule-files",
        help="list of Prometheus alert rule files to render for this device",
        nargs="+",
        default=[],
    )

    setup_parser.add_argument(
        "--generate-device-tls-certificate",
        help="generate a TLS certificate and key for this device",
        action="store_true",
    )

    setup_parser.add_argument(
        "-c",
        "--config",
        is_config_file=True,
        nargs="?",
        help="Config file path",
    )

    update_parser = action_subparsers.add_parser(
        "update", help="Update custom device data and dashboards"
    )

    # Arguments to update the cos device and its data
    update_parser.add_argument(
        "--uid",
        help="Robot unique ID, default set to machine ID.",
        type=str,
    )
    update_parser.add_argument("--url", help="COS base IP/URL", type=str)

    update_parser.add_argument(
        "--update-ssh-keys",
        help="Update device public ssh keys",
        action="store_true",
    )

    update_parser.add_argument(
        "--device-grafana-dashboards",
        help="Update device grafana dashboards list",
        nargs="+",
    )
    update_parser.add_argument(
        "--device-foxglove-dashboards",
        help="Update device foxglove dashboards list",
        nargs="+",
    )
    update_parser.add_argument(
        "--device-loki-alert-rule-files",
        help="Update device Loki alert rule files list",
        nargs="+",
        default=[],
    )
    update_parser.add_argument(
        "--device-prometheus-alert-rule-files",
        help="Update device Prometheus alert rule files list",
        nargs="+",
        default=[],
    )
    update_parser.add_argument(
        "--generate-device-tls-certificate",
        help="generate a TLS certificate and key for this device",
        action="store_true",
    )
    update_parser.add_argument(
        "-c",
        "--config",
        is_config_file=True,
        nargs="?",
        help="Config file path",
    )

    writeuid_parser = action_subparsers.add_parser(
        "write-uid", help="Write device unique ID to a file"
    )

    delete_parser = action_subparsers.add_parser(
        "delete", help="Delete device from server"
    )

    # Arguments to delete the cos device and its data
    delete_parser.add_argument(
        "--uid",
        help="Robot unique ID, default set to machine ID.",
        type=str,
    )
    delete_parser.add_argument("--url", help="COS base IP/URL", type=str)

    # Arguments shared between all the actions
    parser.add_argument(
        "--config", is_config_file=True, help="Config file path."
    )
    parser.add_argument("--url", help="COS base IP/URL", type=str)

    parser.add_argument(
        "--shared-data-path",
        help="The path to which the relevant common devices app files \
            such as robot-unique-id are stored.",
        type=str,
        default=os.getcwd(),
    )

    parser.add_argument(
        "--grafana-dashboards",
        help="Path to the grafana dashboard",
        type=Path,
    )

    parser.add_argument(
        "--foxglove-studio-dashboards",
        help="Path to the foxglove dashboard",
        type=Path,
    )

    parser.add_argument(
        "--loki-alert-rule-files",
        help="Path to the Loki alert rule files",
        type=Path,
    )

    parser.add_argument(
        "--prometheus-alert-rule-files",
        help="Path to the Prometheus alert rule files",
        type=Path,
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level",
    )

    parser.add_argument(
        "--token-file",
        help="Authorization bearer token file path",
        type=Path,
        default=None,
    )

    return parser.parse_args()


def handle_tls_certificate_polling(
    cos_registration_agent, device_ip_address
) -> None:
    """
    Handle the TLS certificate polling process.

    Args:
        cos_registration_agent: An instance of CosRegistrationAgent.
        device_ip_address: The IP address of the device.
    """
    logger = logging.getLogger(__name__)
    if not cos_registration_agent.request_device_tls_certificate(
        device_ip_address
    ):
        logger.error("Failed to submit CSR.")
        cos_registration_agent.delete_device()
        return

    success = False
    try:
        logger.info("Starting certificate polling...")
        # Default set to 10 minutes as on_update_status on
        # COS registration server is at least 5 minutes.
        success = cos_registration_agent.poll_for_certificate(
            timeout_seconds=600
        )
        if not success:
            logger.error("Timeout: failed to obtain signed certificate")
    except PermissionError as e:
        logger.error(f"CSR denied by the server: {e}")
    except RuntimeError as e:
        logger.error(f"Error during certificate polling: {e}")
    finally:
        if not success:
            cos_registration_agent.delete_device()
            return


def main():
    logger = logging.getLogger(__name__)
    args = _parse_args()
    # flake8: noqa
    if args.log_level:
        logging.basicConfig(level=getattr(logging, args.log_level))

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

    if args.uid:
        device_id = args.uid
    else:
        device_id = get_machine_id()

    logger.debug(f"Device id: {device_id}")

    device_ip_address = get_machine_ip_address(args.url)
    logger.debug(f"Device ip address: {device_ip_address}")

    certs_path = (
        args.shared_data_path
        if getattr(args, "generate_device_tls_certificate", False)
        else None
    )

    cos_registration_agent = CosRegistrationAgent(
        args.url, device_id, args.token_file, certs_dir=certs_path
    )

    ssh_key_manager = SSHKeysManager()
    try:
        if args.action == "setup":
            (
                private_ssh_key,
                public_ssh_key,
            ) = ssh_key_manager.generate_ssh_keypair()

            if args.grafana_dashboards:
                cos_registration_agent.patch_dashboards(
                    dashboard_path=args.grafana_dashboards,
                    application="grafana",
                )
            if args.foxglove_studio_dashboards:
                cos_registration_agent.patch_dashboards(
                    dashboard_path=args.foxglove_studio_dashboards,
                    application="foxglove",
                )
            if args.loki_alert_rule_files:
                cos_registration_agent.patch_rule_files(
                    rule_files_path=args.loki_alert_rule_files,
                    application="loki",
                )
            if args.prometheus_alert_rule_files:
                cos_registration_agent.patch_rule_files(
                    rule_files_path=args.prometheus_alert_rule_files,
                    application="prometheus",
                )
            try:
                cos_registration_agent.register_device(
                    address=device_ip_address,
                    public_ssh_key=public_ssh_key,
                    grafana_dashboards=args.device_grafana_dashboards,
                    foxglove_dashboards=args.device_foxglove_dashboards,
                    loki_alert_rule_files=args.device_loki_alert_rule_files,
                    prometheus_alert_rule_files=args.device_prometheus_alert_rule_files,
                )
            except SystemError as e:
                logger.error(f"Could not create device:{e}")
                return

            if args.generate_device_tls_certificate:
                handle_tls_certificate_polling(
                    cos_registration_agent, device_ip_address
                )

            ssh_key_manager.write_keys(
                private_ssh_key, public_ssh_key, folder=args.shared_data_path
            )

        elif args.action == "update":
            data_to_update = {}
            data_to_update["address"] = get_machine_ip_address(args.url)
            if args.update_ssh_keys:
                pass
                # TODO Retrieve the key from the shared folder
                # data_to_update["public_ssh_key"] = public_ssh_key
            if args.device_grafana_dashboards:
                data_to_update["grafana_dashboards"] = (
                    args.device_grafana_dashboards
                )
            if args.device_foxglove_dashboards:
                data_to_update["foxglove_dashboards"] = (
                    args.device_foxglove_dashboards
                )
            if args.device_loki_alert_rule_files:
                data_to_update["loki_alert_rule_files"] = (
                    args.device_loki_alert_rule_files
                )
            if args.device_prometheus_alert_rule_files:
                data_to_update["prometheus_alert_rule_files"] = (
                    args.device_prometheus_alert_rule_files
                )
            if args.grafana_dashboards:
                cos_registration_agent.patch_dashboards(
                    dashboard_path=args.grafana_dashboards,
                    application="grafana",
                )
            if args.foxglove_studio_dashboards:
                cos_registration_agent.patch_dashboards(
                    dashboard_path=args.foxglove_studio_dashboards,
                    application="foxglove",
                )
            if args.loki_alert_rule_files:
                cos_registration_agent.patch_rule_files(
                    rule_files_path=args.loki_alert_rule_files,
                    application="loki",
                )
            if args.prometheus_alert_rule_files:
                cos_registration_agent.patch_rule_files(
                    rule_files_path=args.prometheus_alert_rule_files,
                    application="prometheus",
                )
            cos_registration_agent.patch_device(data_to_update)

            if args.generate_device_tls_certificate:
                handle_tls_certificate_polling(
                    cos_registration_agent, device_ip_address
                )
        elif args.action == "delete":
            cos_registration_agent.delete_device()

    except Exception as e:
        logger.error(f"Failed to {args.action}: {e}")

    return
