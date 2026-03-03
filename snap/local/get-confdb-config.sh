#!/usr/bin/bash -e

# Helper script to get configuration from confdb
# Returns values from the device-cos-settings confdb

get_confdb_rob_cos_ip() {
    snapctl get --view :device-cos-settings-observe rob-cos-ip 2>/dev/null || echo ""
}

get_confdb_model_name() {
    snapctl get --view :device-cos-settings-observe model-name 2>/dev/null || echo ""
}

get_confdb_url() {
    # Compute base URL from rob-cos-ip and model-name
    local rob_cos_ip=$(get_confdb_rob_cos_ip)
    local model_name=$(get_confdb_model_name)
    
    # Only return URL if both components are available and not placeholders
    if [ -n "$rob_cos_ip" ] && [ "$rob_cos_ip" != "rob-cos-ip-placeholder" ] && \
       [ -n "$model_name" ] && [ "$model_name" != "model-name-placeholder" ]; then
        echo "http://${rob_cos_ip}/${model_name}"
    else
        echo ""
    fi
}

get_confdb_device_uid() {
    snapctl get --view :device-cos-settings-observe device-uid 2>/dev/null || echo ""
}

# Parse argument to determine what to return
case "$1" in
    device-uid)
        get_confdb_device_uid
        ;;
    rob-cos-ip)
        get_confdb_rob_cos_ip
        ;;
    model-name)
        get_confdb_model_name
        ;;
    *)
        # Default: get computed URL (for backward compatibility)
        get_confdb_url
        ;;
esac
