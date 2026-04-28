#!/bin/bash

# Usage: . write-tmp-file.sh "$CONTENT" OUTPUT_VAR
#
# Creates a temporary file and writes CONTENT into it.
# The path to the temp file is stored in OUTPUT_VAR.
# Cleanup is handled automatically via a trap on EXIT.

_write_tmp_file_content="${1:?missing content}"
_write_tmp_file_output_var="${2:?missing output variable name}"

_append_exit_trap() {
  local _new_exit_cmd="${1:?missing exit command}"
  local _current_exit_trap

  _current_exit_trap="$(trap -p EXIT | sed -E "s/^trap -- '(.*)' EXIT$/\1/")"
  if [[ -n "${_current_exit_trap}" ]]; then
    trap "${_current_exit_trap}; ${_new_exit_cmd}" EXIT
  else
    trap "${_new_exit_cmd}" EXIT
  fi
}

if [[ -z "${_write_tmp_file_init_done:-}" ]]; then
  _write_tmp_files=()
  _append_exit_trap 'rm -f "${_write_tmp_files[@]}" 2>/dev/null || true'
  _write_tmp_file_init_done=1
fi

_write_tmp_file_path="$(mktemp)"
printf '%s\n' "${_write_tmp_file_content}" > "${_write_tmp_file_path}"
_write_tmp_files+=("${_write_tmp_file_path}")

printf -v "${_write_tmp_file_output_var}" '%s' "${_write_tmp_file_path}"

unset _write_tmp_file_content
unset _write_tmp_file_output_var
unset _write_tmp_file_path
