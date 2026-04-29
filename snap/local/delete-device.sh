#!/bin/bash -eu

IDENTITY_TOKEN_FILE_PATH="${SNAP_COMMON}/rob-cos-shared-data/identity/token.txt"

DEVICE_CONFIG="$(snapctl get --view :confdb-configuration device || true)"
if [[ -z "${DEVICE_CONFIG}" ]] || [[ "${DEVICE_CONFIG}" == "null" ]]; then
  logger -t "${SNAP_NAME}" "Device configuration is empty in confdb view, skipping registration"
  exit 0
fi
. "${SNAP}/usr/bin/write-tmp-file.sh" "${DEVICE_CONFIG}" DEVICE_CONFIG_FILE

GLOBAL_ARGS=()
if [[ -f "${IDENTITY_TOKEN_FILE_PATH}" ]]; then
  GLOBAL_ARGS+=(--token-file "${IDENTITY_TOKEN_FILE_PATH}")
fi

"${SNAP}/bin/cos-registration-agent" "${GLOBAL_ARGS[@]}" delete -c "${DEVICE_CONFIG_FILE}"

logger -t "${SNAP_NAME}" "Successfully deleted the device."
