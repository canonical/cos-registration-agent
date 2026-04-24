#!/bin/sh -e

# Registration daemon that keeps trying to register until success
# Then disables itself

REGISTRATION_MARKER="${SNAP_COMMON}/.device-registered"
MAX_ATTEMPTS=999999  # Effectively unlimited
RETRY_INTERVAL=30  # seconds

logger -t "${SNAP_NAME}.registration-daemon" "Registration daemon started"

attempt=0

while [ $attempt -lt $MAX_ATTEMPTS ]; do
    attempt=$((attempt + 1))
    
    # Check if already registered
    if [ -f "${REGISTRATION_MARKER}" ]; then
        logger -t "${SNAP_NAME}.registration-daemon" "Device already registered"
        snapctl stop --disable ${SNAP_NAME}.registration-daemon
        exit 0
    fi
    
    # Try to register
    if ${SNAP}/usr/bin/register-device.sh 2>&1; then
        logger -t "${SNAP_NAME}.registration-daemon" "Registration successful, disabling daemon"
        touch "${REGISTRATION_MARKER}"
        snapctl stop --disable ${SNAP_NAME}.registration-daemon
        exit 0
    else
        EXIT_CODE=$?
        if [ $((attempt % 10)) -eq 0 ]; then
            # Log every 10th attempt to avoid spam
            logger -t "${SNAP_NAME}.registration-daemon" "Registration attempt ${attempt} failed (exit ${EXIT_CODE}), retrying..."
        fi
    fi
    
    sleep ${RETRY_INTERVAL}
done

logger -t "${SNAP_NAME}.registration-daemon" "Max registration attempts reached"
exit 1
