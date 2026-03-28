#!/usr/bin/env bash
set -euo pipefail

REPO="Ashfaaq98/ocsf-console-ir"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

BLUE="\033[1;34m"
GREEN="\033[1;32m"
RED="\033[1;31m"
RESET="\033[0m"

info() {
  printf "${BLUE}→ %s${RESET}\n" "$*"
}

success() {
  printf "${GREEN}✔ %s${RESET}\n" "$*"
}

error() {
  printf "${RED}✖ %s${RESET}\n" "$*" >&2
}

cleanup() {
  rm -rf "${TMPDIR_INSTALL}"
}

TMPDIR_INSTALL="$(mktemp -d)"
trap cleanup EXIT

OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "${OS_RAW}" in
  Linux)
    OS_NAME="Linux"
    ;;
  Darwin)
    OS_NAME="macOS"
    ;;
  *)
    error "Unsupported operating system: ${OS_RAW}. This installer supports Linux and macOS only."
    exit 1
    ;;
esac

case "${ARCH_RAW}" in
  x86_64|amd64)
    ARCH_NAME="amd64"
    ;;
  aarch64|arm64)
    ARCH_NAME="arm64"
    ;;
  *)
    error "Unsupported architecture: ${ARCH_RAW}."
    exit 1
    ;;
esac

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    error "Required command not found: $1"
    exit 1
  fi
}

require_cmd curl
require_cmd tar

info "Detecting latest release from GitHub"
RELEASE_JSON="${TMPDIR_INSTALL}/release.json"
curl -fsSL "${API_URL}" -o "${RELEASE_JSON}"

TAG_NAME="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${RELEASE_JSON}" | head -n1)"
if [[ -z "${TAG_NAME}" ]]; then
  error "Unable to determine the latest release tag from GitHub."
  exit 1
fi

VERSION="${TAG_NAME#v}"
ARCHIVE_NAME="console-ir_${VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz"
ARCHIVE_URL="https://github.com/${REPO}/releases/download/${TAG_NAME}/${ARCHIVE_NAME}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${TAG_NAME}/checksums.txt"

ARCHIVE_PATH="${TMPDIR_INSTALL}/${ARCHIVE_NAME}"
CHECKSUM_PATH="${TMPDIR_INSTALL}/checksums.txt"

info "Downloading ${ARCHIVE_NAME}"
curl -fsSL "${ARCHIVE_URL}" -o "${ARCHIVE_PATH}"

info "Downloading checksums"
curl -fsSL "${CHECKSUM_URL}" -o "${CHECKSUM_PATH}"

info "Verifying checksum"
if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "${TMPDIR_INSTALL}"
    sha256sum -c <(grep "  ${ARCHIVE_NAME}\$" "${CHECKSUM_PATH}")
  )
elif command -v shasum >/dev/null 2>&1; then
  EXPECTED_SUM="$(grep "  ${ARCHIVE_NAME}\$" "${CHECKSUM_PATH}" | awk '{print $1}')"
  ACTUAL_SUM="$(shasum -a 256 "${ARCHIVE_PATH}" | awk '{print $1}')"
  if [[ "${EXPECTED_SUM}" != "${ACTUAL_SUM}" ]]; then
    error "Checksum verification failed for ${ARCHIVE_NAME}."
    exit 1
  fi
else
  error "No checksum tool available. Install sha256sum or shasum."
  exit 1
fi

success "Checksum verified"

info "Extracting archive"
tar -xzf "${ARCHIVE_PATH}" -C "${TMPDIR_INSTALL}"

BIN_PATH="${TMPDIR_INSTALL}/console-ir"
if [[ ! -f "${BIN_PATH}" ]]; then
  error "Expected binary not found after extraction."
  exit 1
fi

info "Installing to ${INSTALL_DIR}"
if [[ -w "${INSTALL_DIR}" ]]; then
  install -m 0755 "${BIN_PATH}" "${INSTALL_DIR}/console-ir"
else
  sudo install -m 0755 "${BIN_PATH}" "${INSTALL_DIR}/console-ir"
fi

success "console-ir ${TAG_NAME} installed successfully"
printf "Run: console-ir --help\n"
