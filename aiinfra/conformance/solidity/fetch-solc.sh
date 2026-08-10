#!/bin/sh
set -eu

artifact='solc-linux-amd64-v0.8.30+commit.73712a01'
expected_sha256='f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7'
url="https://binaries.soliditylang.org/linux-amd64/${artifact}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../../.." && pwd)
toolchain_dir="${repo_root}/.codex-tmp/toolchains"
destination="${toolchain_dir}/${artifact}"

mkdir -p -- "${toolchain_dir}"
if [ -L "${destination}" ]; then
    printf '%s\n' "refusing symlinked compiler at ${destination}" >&2
    exit 1
fi
if [ -f "${destination}" ]; then
    actual_sha256=$(sha256sum -- "${destination}" | awk '{print $1}')
    if [ "${actual_sha256}" = "${expected_sha256}" ]; then
        chmod 0755 -- "${destination}"
        printf '%s\n' "${destination}"
        exit 0
    fi
    printf '%s\n' "refusing mismatched compiler at ${destination}" >&2
    exit 1
fi

temporary=$(mktemp "${toolchain_dir}/.${artifact}.XXXXXX")
cleanup() {
    rm -f -- "${temporary}"
}
trap cleanup EXIT HUP INT TERM

curl --fail --location --proto '=https' --tlsv1.2 --output "${temporary}" "${url}"
actual_sha256=$(sha256sum -- "${temporary}" | awk '{print $1}')
if [ "${actual_sha256}" != "${expected_sha256}" ]; then
    printf '%s\n' "solc SHA-256 mismatch: got ${actual_sha256}, want ${expected_sha256}" >&2
    exit 1
fi
chmod 0755 -- "${temporary}"
mv -- "${temporary}" "${destination}"
trap - EXIT HUP INT TERM
printf '%s\n' "${destination}"
