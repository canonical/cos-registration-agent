#!/bin/bash

# Usage: . write-confdb-map-to-tmp-dir.sh "$JSON_MAP" "file_extension" OUTPUT_VAR
#
# Creates a temporary directory and writes each key/value pair from JSON_MAP
# as a file named "<key>.<file_extension>" inside it.
# The path to the temp directory is stored in OUTPUT_VAR.
# Cleanup is handled automatically via a trap on EXIT.

_write_tmp_dir_json="${1:?missing json map}"
_write_tmp_dir_ext="${2:?missing file extension}"
_write_tmp_dir_output_var="${3:?missing output variable name}"

if [[ -z "${_write_tmp_dirs_init_done:-}" ]]; then
  _write_tmp_dirs=()
  trap 'rm -rf "${_write_tmp_dirs[@]}"' EXIT
  _write_tmp_dirs_init_done=1
fi

_write_tmp_dir_path="$(mktemp -d)"
_write_tmp_dirs+=("${_write_tmp_dir_path}")

while IFS= read -r _write_tmp_dir_key; do
  printf '%s' "$(printf '%s' "${_write_tmp_dir_json}" | jq -r --arg k "${_write_tmp_dir_key}" '.[$k]')" \
    > "${_write_tmp_dir_path}/${_write_tmp_dir_key}.${_write_tmp_dir_ext}"
done < <(printf '%s' "${_write_tmp_dir_json}" | jq -r 'keys[]')

printf -v "${_write_tmp_dir_output_var}" '%s' "${_write_tmp_dir_path}"

unset _write_tmp_dir_json
unset _write_tmp_dir_ext
unset _write_tmp_dir_output_var
unset _write_tmp_dir_path
unset _write_tmp_dir_key
