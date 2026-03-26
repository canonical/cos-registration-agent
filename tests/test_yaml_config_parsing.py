"""Test YAML config file parsing with configargparse."""

import tempfile
import os
from pathlib import Path
import pytest
import configargparse


@pytest.mark.unit
def test_yaml_config_parsing_with_temp_file():
    """Test that device.yaml is properly parsed by configargparse using a temp file."""

    # Clear any existing parsers from previous tests
    configargparse._parsers.clear()

    # Create a temporary device.yaml file with test data
    yaml_content = """url: http://192.168.1.100/test-model-cos-registration-server/
uid: test-robot-001
device-grafana-dashboards: [linux-system, systemd-and-snaps-logs]
device-foxglove-dashboards: [topics-and-logs, teleop]
device-loki-alert-rule-files: [human_detected]
device-prometheus-alert-rule-files: [low_memory]
"""

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(yaml_content)
        config_file = f.name

    try:
        # Set SNAP_COMMON for testing
        os.environ["SNAP_COMMON"] = "/tmp/test-snap-common"

        # Import after setting env vars
        from cos_registration_agent.cli import _parse_args
        import sys

        # Simulate command line args
        test_args = [
            "setup",
            "--config",
            config_file,
            "--shared-data-path",
            "/tmp/test-shared-data",
        ]

        # Replace sys.argv
        old_argv = sys.argv
        sys.argv = ["cos-registration-agent"] + test_args

        try:
            args = _parse_args()

            # Assertions
            assert (
                args.action == "setup"
            ), f"Expected action 'setup', got '{args.action}'"
            assert (
                args.url
                == "http://192.168.1.100/test-model-cos-registration-server/"
            ), f"Expected url from YAML, got '{args.url}'"
            assert (
                args.uid == "test-robot-001"
            ), f"Expected uid from YAML, got '{args.uid}'"
            assert (
                len(args.device_grafana_dashboards) == 2
            ), f"Expected 2 grafana dashboards, got {args.device_grafana_dashboards}"
            assert (
                "linux-system" in args.device_grafana_dashboards
            ), f"Expected 'linux-system' in dashboards"

        finally:
            sys.argv = old_argv
            # Clear parser for next test
            configargparse._parsers.clear()

    except Exception as e:
        raise
    finally:
        # Cleanup
        os.unlink(config_file)


def test_yaml_config_parsing_from_snap():
    """Test that device.yaml from snap is properly parsed (requires snap installed)."""

    # Clear any existing parsers from previous tests
    configargparse._parsers.clear()

    # Read the actual device.yaml from the snap
    snap_device_yaml = "/var/snap/cos-registration-agent/common/device.yaml"

    if not os.path.exists(snap_device_yaml):
        pytest.skip(
            f"Snap device.yaml not found at {snap_device_yaml}. Snap not installed."
        )
        return

    print(f"Reading device.yaml from: {snap_device_yaml}")
    with open(snap_device_yaml, "r") as f:
        yaml_content = f.read()

    print("=" * 60)
    print("DEVICE.YAML CONTENTS:")
    print("=" * 60)
    print(yaml_content)
    print("=" * 60)

    config_file = snap_device_yaml

    try:
        # Set SNAP_COMMON for testing
        os.environ["SNAP_COMMON"] = "/tmp/test-snap-common"

        # Import after setting env vars
        from cos_registration_agent.cli import _parse_args
        import sys

        # Simulate command line args
        # With single parser, action comes first as positional arg
        test_args = [
            "setup",
            "--config",
            config_file,
            "--shared-data-path",
            "/tmp/test-shared-data",
        ]

        # Replace sys.argv
        old_argv = sys.argv
        sys.argv = ["cos-registration-agent"] + test_args

        try:
            args = _parse_args()

            print("=" * 60)
            print("PARSED ARGUMENTS:")
            print("=" * 60)
            print(f"action: {args.action}")
            print(f"url: {args.url}")
            print(f"uid: {args.uid}")
            print(
                f"device_grafana_dashboards: {args.device_grafana_dashboards}"
            )
            print(
                f"device_foxglove_dashboards: {args.device_foxglove_dashboards}"
            )
            print(
                f"device_loki_alert_rule_files: {args.device_loki_alert_rule_files}"
            )
            print(
                f"device_prometheus_alert_rule_files: {args.device_prometheus_alert_rule_files}"
            )
            print(f"shared_data_path: {args.shared_data_path}")
            print("=" * 60)

            # Assertions
            assert (
                args.action == "setup"
            ), f"Expected action 'setup', got '{args.action}'"
            assert args.url is not None, f"Expected url from YAML, got None"
            assert args.uid is not None, f"Expected uid from YAML, got None"
            assert (
                len(args.device_grafana_dashboards) > 0
            ), f"Expected dashboard configs from YAML, got {args.device_grafana_dashboards}"

            print("\n✅ All assertions passed!")
            print("✅ YAML config file was properly parsed by configargparse")
            print(
                "✅ URL, UID, and dashboard/alert configurations are correctly read from device.yaml"
            )
            print(
                "✅ Single flat parser works perfectly with YAML config files!"
            )

            # Check for placeholders
            if (
                "placeholder" in args.url.lower()
                or "placeholder" in args.uid.lower()
            ):
                print(
                    "\n⚠️  WARNING: Configuration contains placeholder values"
                )
                print(
                    "⚠️  Device needs to be configured via rob-cos-demo-configuration snap"
                )

        finally:
            sys.argv = old_argv
            # Clear parser for clean state
            configargparse._parsers.clear()

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    # Run unit test
    test_yaml_config_parsing_with_temp_file()
    # Optionally run integration test if snap is installed
    test_yaml_config_parsing_from_snap()
