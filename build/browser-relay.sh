#!/usr/bin/env bash
# Shared startup arguments for the Unix Common launchers. Never used for init.
configure_browser_relay() {
  local script_dir="$1"
  shift
  local enabled="${CYPHER_BROWSER_RELAY:-1}"
  local default_config="${script_dir}/config/browser-relay/common-mine.json"
  local config="${CYPHER_BROWSER_RELAY_CONFIG:-${default_config}}"
  local explicit_config=0 argument

  case "$enabled" in
    0|1) ;;
    *) echo "ERROR: CYPHER_BROWSER_RELAY must be 0 or 1" >&2; return 1 ;;
  esac
  while (($#)); do
    argument="$1"
    case "$argument" in
      --) break ;;
      --browser.public-relay) enabled=1 ;;
      --browser.public-relay=*)
        case "${argument#*=}" in
          1|t|T|true|TRUE|True) enabled=1 ;;
          0|f|F|false|FALSE|False) enabled=0 ;;
          *) echo "ERROR: invalid browser.public-relay boolean" >&2; return 1 ;;
        esac ;;
      --browser.public-relay.config)
        if (($# < 2)); then
          echo "ERROR: browser.public-relay.config requires an absolute path" >&2
          return 1
        fi
        shift
        config="$1"; explicit_config=1 ;;
      --browser.public-relay.config=*) config="${argument#*=}"; explicit_config=1 ;;
    esac
    shift
  done

  CYPHER_RELAY_ARGS=()
  if [[ "$enabled" == 0 ]]; then
    if [[ "$explicit_config" == 1 ]]; then
      echo "ERROR: browser.public-relay.config requires browser.public-relay" >&2
      return 1
    fi
    echo "==> Browser relay: OFF"
    return 0
  fi
  if [[ "$config" != /* || ! -f "$config" || -L "$config" ]]; then
    echo "ERROR: browser relay configuration must be an existing absolute regular file: $config" >&2
    return 1
  fi
  # The shipped configuration uses an automatic socket beside the JSON.
  # Custom configurations retain their operator-managed permissions.
  if [[ "$config" == "$default_config" ]]; then
    if [[ -L "${script_dir}/config" || -L "${script_dir}/config/browser-relay" ]]; then
      echo "ERROR: browser relay configuration directory must not be a symbolic link" >&2
      return 1
    fi
    chmod 700 "${script_dir}/config/browser-relay"
  fi
  CYPHER_RELAY_ARGS=(--browser.public-relay --browser.public-relay.config "$config")
  echo "==> Browser relay: ON ($config)"
}
