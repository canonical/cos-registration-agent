#!/bin/bash -eu

IDENTITY_TOKEN_FILE_PATH="${SNAP_COMMON}/rob-cos-shared-data/identity/token.txt"

DEVICE_CONFIG="$(snapctl get --view :confdb-configuration device || true)"
if [[ -z "${DEVICE_CONFIG}" ]] || [[ "${DEVICE_CONFIG}" == "null" ]]; then
  logger -t "${SNAP_NAME}" "Device configuration is empty in confdb view, skipping deletion"
  exit 0
fi
. "${SNAP}/usr/bin/write-tmp-file.sh" "${DEVICE_CONFIG}" DEVICE_CONFIG_FILE

URL="$(sed -n 's/^url:[[:space:]]*//p' "${DEVICE_CONFIG_FILE}" | head -n 1)"
DEVICE_UID="$(sed -n 's/^uid:[[:space:]]*//p' "${DEVICE_CONFIG_FILE}" | head -n 1)"

if [[ -z "${URL}" ]] || [[ -z "${DEVICE_UID}" ]]; then
  logger -t "${SNAP_NAME}" "Missing url or uid in device configuration, cannot delete device"
  exit 1
fi

GLOBAL_ARGS=()
if [[ -f "${IDENTITY_TOKEN_FILE_PATH}" ]]; then
  GLOBAL_ARGS+=(--token-file "${IDENTITY_TOKEN_FILE_PATH}")
fi

"${SNAP}/bin/cos-registration-agent" "${GLOBAL_ARGS[@]}" delete --url "${URL}" --uid "${DEVICE_UID}"

logger -t "${SNAP_NAME}" "Successfully deleted the device."
