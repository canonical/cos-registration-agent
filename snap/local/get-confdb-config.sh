#!/usr/bin/bash -e

# Helper script to get configuration from confdb
# Returns the rob-cos-base-url from the device-cos-settings confdb

get_confdb_url() {
    snapctl get --view :device-cos-settings-observe rob-cos-base-url 2>/dev/null || echo ""
}

get_confdb_url
