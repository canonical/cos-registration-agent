#!/bin/bash -eu

IDENTITY_TOKEN_FILE_PATH="${SNAP_COMMON}/rob-cos-shared-data/identity/token.txt"

DEVICE_CONFIG="$(snapctl get --view :confdb-configuration device)"
. "${SNAP}/usr/bin/write-tmp-file.sh" "${DEVICE_CONFIG}" DEVICE_CONFIG_FILE

GLOBAL_ARGS=()
if [[ -f "${IDENTITY_TOKEN_FILE_PATH}" ]]; then
  GLOBAL_ARGS+=(--token-file "${IDENTITY_TOKEN_FILE_PATH}")
fi

"${SNAP}/bin/cos-registration-agent" "${GLOBAL_ARGS[@]}" delete -c "${DEVICE_CONFIG_FILE}"

logger -t "${SNAP_NAME}" "Successfully deleted the device."
