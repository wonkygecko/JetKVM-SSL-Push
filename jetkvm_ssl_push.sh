#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Kyle Britton <kyleb@wonkygecko.dev>
# JetKVM SSL Push - A small Bash utility to automatically download TLS 
# bundles from Certmate and push them to one or more JetKVM hosts over SSH.
#
# This script is released under the GNU General Public License v2 or later.
# See the project's `LICENSE` file for the full text.
#
# Short notice:
#   You may redistribute and/or modify this program under the terms of
#   the GNU General Public License as published by the Free Software
#   Foundation; either version 2 of the License, or (at your option) any
#   later version.
#

set -euo pipefail

# ----------------------------
# Logging function with timestamps
# ----------------------------
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# ----------------------------
# 1. dotenv loader
# ----------------------------
load_dotenv() {
  local envfile="$1"
  if [[ ! -f "$envfile" ]]; then
    log "[-] Missing environment file: $envfile" >&2
    exit 1
  fi

  # read KEY=VALUE lines, ignore comments/blank
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    # skip comments / blank lines
    [[ "$key" =~ ^[[:space:]]*$ || "$key" =~ ^# ]] && continue

    # trim whitespace safely without xargs
    key="${key#"${key%%[![:space:]]*}"}"   # remove leading space
    key="${key%"${key##*[![:space:]]}"}"   # remove trailing space
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    # strip surrounding quotes if present
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"

    export "$key"="$value"
  done < "$envfile"
}

# ----------------------------
# 2. load .env from script dir
# ----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.jetkvm.env"
load_dotenv "$ENV_FILE"
log "[+] Loaded environment from $ENV_FILE"

# ----------------------------
# 3. validate required variables
# ----------------------------
REQUIRED_VARS=("CERTMATE_TOKEN" "CERTMATE_BASE" "SSH_KEY" "JETKVM_USER" "JETKVM_HOSTS")
for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    log "[-] Missing required variable: $var" >&2
    exit 1
  fi
done
log "[+] All required environment variables present"

# ----------------------------
# 4. dry-run mode support
# ----------------------------
DRY_RUN="${DRY_RUN:-false}"
if [[ "$DRY_RUN" == "true" ]]; then
  log "[!] Running in DRY-RUN mode - no changes will be made"
fi

# ----------------------------
# 5. turn JETKVM_HOSTS into array
#    (each line: host|certname)
# ----------------------------
# Split space-separated host entries into an array
read -r -a HOSTS <<< "$JETKVM_HOSTS"

# Ensure at least one host is defined
if [[ ${#HOSTS[@]} -eq 0 ]]; then
  log "[-] No hosts defined in JETKVM_HOSTS in $ENV_FILE"
  exit 1
fi

# ----------------------------
# 6. SSH configuration
# ----------------------------
# dedicated known_hosts file stored alongside the script
KNOWN_HOSTS_FILE="$SCRIPT_DIR/jetkvm_known_hosts"
mkdir -p "$(dirname "$KNOWN_HOSTS_FILE")" || true
touch "$KNOWN_HOSTS_FILE" 2>/dev/null || true
chmod 644 "$KNOWN_HOSTS_FILE" 2>/dev/null || true

SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=5 -o UserKnownHostsFile=$KNOWN_HOSTS_FILE"

# create workdir early so we can save logs during connectivity checks
WORKDIR="$(mktemp -d)"
KEEP_ERRORS=false
trap 'if [[ "$KEEP_ERRORS" == "false" ]]; then rm -rf "$WORKDIR"; fi' EXIT

# ----------------------------
# 7. validate SSH connectivity
# ----------------------------
log "[+] Validating SSH connectivity..."
for entry in "${HOSTS[@]}"; do
  JETKVM_HOST="${entry%%|*}"
  if [[ "$DRY_RUN" != "true" ]]; then
    SSH_CONN_LOG="$WORKDIR/ssh_conn_${JETKVM_HOST}.log"

    # If host is not already present in our dedicated known_hosts, prompt to add it
    if ! ssh-keygen -F "$JETKVM_HOST" -f "$KNOWN_HOSTS_FILE" >/dev/null 2>&1; then
      log "[-] No host key for ${JETKVM_HOST} in ${KNOWN_HOSTS_FILE}"
      if command -v ssh-keyscan >/dev/null 2>&1; then
        KEYS="$(ssh-keyscan -t ecdsa,rsa,ed25519 "$JETKVM_HOST" 2>/dev/null || true)"
        if [[ -z "$KEYS" ]]; then
          log "    ! ssh-keyscan failed to retrieve host key for ${JETKVM_HOST}"
          KEEP_ERRORS=true
          exit 1
        fi
        log "    Host key(s) for ${JETKVM_HOST}:"
        echo "$KEYS" | ssh-keygen -lf - 2>/dev/null || true

        # prompt the user to accept the key
        read -r -p "    Accept and add host key to ${KNOWN_HOSTS_FILE}? [y/N] " resp || resp="n"
        if [[ "$resp" =~ ^[Yy]$ ]]; then
          echo "$KEYS" >> "$KNOWN_HOSTS_FILE"
          chmod 644 "$KNOWN_HOSTS_FILE" 2>/dev/null || true
          log "    [+] Added host key for ${JETKVM_HOST} to ${KNOWN_HOSTS_FILE}"
        else
          log "    [-] Host key not accepted for ${JETKVM_HOST}; aborting"
          KEEP_ERRORS=true
          exit 1
        fi
      else
        log "    ! ssh-keyscan not available; cannot fetch host key for ${JETKVM_HOST}"
        KEEP_ERRORS=true
        exit 1
      fi
    fi

    if ! ssh $SSH_OPTS "${JETKVM_USER}@${JETKVM_HOST}" "exit" 2>"$SSH_CONN_LOG"; then
      log "[-] Cannot connect to ${JETKVM_HOST} via SSH"
      log "[-] SSH stderr (first 200 bytes):"
      head -c 200 "$SSH_CONN_LOG" 2>/dev/null || true
      echo
      log "[-] Full SSH stderr saved to: $SSH_CONN_LOG"
      KEEP_ERRORS=true
      exit 1
    fi
    log "    [OK] ${JETKVM_HOST}"
  else
    log "    [DRY-RUN] Would check ${JETKVM_HOST}"
  fi
done

# ----------------------------
# 7.b ensure tls_mode is set to 'custom' on remote
# ----------------------------
ensure_remote_tls_custom() {
  local host="$1"
  log "    - ensuring remote /data/jetkvm_config.json has tls_mode=custom on ${host}"
  local ssh_err="$WORKDIR/ssh_tls_${host}.err"
  local ssh_out
  ssh_out=$(ssh -T $SSH_OPTS "${JETKVM_USER}@${host}" 2>"$ssh_err" <<'REMOTE'
set -e
CONFIG="/data/jetkvm_config.json"
if [[ ! -f "$CONFIG" ]]; then
  echo "NO_CONFIG"
  exit 0
fi
  # BusyBox-only fallback using sed/awk: check or insert tls_mode, set to "custom"
  if grep -q '"tls_mode"' "$CONFIG"; then
    # if already set to custom, report OK; otherwise replace value
    if grep -q '"tls_mode"[[:space:]]*:[[:space:]]*"custom"' "$CONFIG"; then
      echo "OK"
    else
      tmp=$(mktemp)
      sed -E 's/("tls_mode"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"custom"/' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG" && echo "UPDATED" || echo "SED_FAILED"
    fi
  else
    # Do not insert tls_mode if missing; report and skip
    echo "NO_ENTRY"
  fi
REMOTE
)

  # ssh failed to run at all
  if [[ $? -ne 0 ]]; then
    log "    ! SSH failure while ensuring tls_mode on ${host} - see $ssh_err"
    return 1
  fi

  case "$ssh_out" in
    UPDATED)
      log "    [+] tls_mode set to 'custom' on ${host}"
      ;;
    OK)
      log "    [OK] tls_mode already 'custom' on ${host}"
      ;;
    NO_CONFIG)
      log "    ! No /data/jetkvm_config.json found on ${host}; skipping tls_mode update"
      ;;
    NO_ENTRY)
      log "    ! 'tls_mode' not found in /data/jetkvm_config.json on ${host}; not inserting (skipping)"
      ;;
    SED_FAILED|AWK_FAILED|BAD_FORMAT)
      log "    ! Failed to update /data/jetkvm_config.json on ${host}; see $ssh_err"
      ;;
    *)
      log "    ! Unexpected output while checking tls_mode on ${host}: $ssh_out"
      ;;
  esac
  return 0
}

# ----------------------------
# 8. constants / paths
# ----------------------------
REMOTE_DIR="/userdata/jetkvm/tls"
REMOTE_CERT="${REMOTE_DIR}/user-defined.crt"
REMOTE_KEY="${REMOTE_DIR}/user-defined.key"

WORKDIR="$(mktemp -d)"
KEEP_ERRORS=false
trap 'if [[ "$KEEP_ERRORS" == "false" ]]; then rm -rf "$WORKDIR"; fi' EXIT

# ----------------------------
# 9. download with retry logic
# ----------------------------
download_with_retry() {
  local url="$1" output="$2" max_attempts=3
  for attempt in $(seq 1 $max_attempts); do
    HTTP_CODE=$(curl -sS -w "%{http_code}" \
      -H "Authorization: Bearer ${CERTMATE_TOKEN}" \
      -o "$output" "$url")
    if [[ "$HTTP_CODE" == "200" ]]; then
      return 0
    fi
    log "    ! Attempt $attempt failed (HTTP $HTTP_CODE)"
    [[ $attempt -lt $max_attempts ]] && sleep 2
  done
  return 1
}

# ----------------------------
# 10. main loop
# ----------------------------
SUCCESS_COUNT=0
FAIL_COUNT=0

for entry in "${HOSTS[@]}"; do
  JETKVM_HOST="${entry%%|*}"
  CERT_NAME="${entry##*|}"

  log "==> Processing ${JETKVM_HOST} (cert: ${CERT_NAME})"

  ZIPFILE="$WORKDIR/${CERT_NAME}.zip"
  CERTDIR="$WORKDIR/${CERT_NAME}"
  mkdir -p "$CERTDIR"

  log "    - downloading from certmate..."
  # Note: /tls endpoint is used to download the certificate bundle in ZIP format
  if ! download_with_retry "${CERTMATE_BASE}/${CERT_NAME}/tls" "$ZIPFILE"; then
    ERROR_FILE="$WORKDIR/error_${CERT_NAME}.txt"
    cp "$ZIPFILE" "$ERROR_FILE" 2>/dev/null || true
    log "    ! Failed to download ${CERT_NAME} after retries"
    log "    ! Error details saved to: $ERROR_FILE"
    KEEP_ERRORS=true
    ((FAIL_COUNT++))
    continue
  fi

  # quick sanity check: is it actually a zip?
  if ! file "$ZIPFILE" | grep -qi 'Zip archive data'; then
    log "    ! Downloaded file is not a ZIP. Contents:"
    head -c 200 "$ZIPFILE" || true
    echo
    ERROR_FILE="$WORKDIR/error_${CERT_NAME}.txt"
    cp "$ZIPFILE" "$ERROR_FILE"
    log "    ! Error details saved to: $ERROR_FILE"
    KEEP_ERRORS=true
    ((FAIL_COUNT++))
    continue
  fi

  log "    - unpacking..."
  unzip -oq "$ZIPFILE" -d "$CERTDIR"

  FULLCHAIN="$CERTDIR/fullchain.pem"
  PRIVKEY="$CERTDIR/privkey.pem"

  if [[ ! -f "$FULLCHAIN" || ! -f "$PRIVKEY" ]]; then
    log "    ! ERROR: ${CERT_NAME} archive did not contain fullchain.pem and privkey.pem"
    ((FAIL_COUNT++))
    continue
  fi

  # Verify certificate and display expiry
  if command -v openssl >/dev/null 2>&1; then
    CERT_EXPIRY=$(openssl x509 -enddate -noout -in "$FULLCHAIN" 2>/dev/null | cut -d= -f2 || echo "unknown")
    log "    - Certificate expires: $CERT_EXPIRY"
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log "    [DRY-RUN] Would upload cert/key to ${JETKVM_HOST}"
    log "    [DRY-RUN] Would restart service on ${JETKVM_HOST}"
    log "    [OK] ${JETKVM_HOST} (dry-run)"
    ((SUCCESS_COUNT++))
    continue
  fi

  # Ensure remote JetKVM is configured to use a custom TLS mode before uploading
  ensure_remote_tls_custom "${JETKVM_HOST}" || log "    ! Warning: ensure_remote_tls_custom failed for ${JETKVM_HOST} (continuing)"

  log "    - uploading cert/key to ${JETKVM_HOST}..."
  # upload cert
  if ! ssh -T $SSH_OPTS "${JETKVM_USER}@${JETKVM_HOST}" "cat > ${REMOTE_CERT}" < "$FULLCHAIN" 2>"$WORKDIR/ssh_error.log"; then
    log "    ! Failed to upload certificate to ${JETKVM_HOST}"
    log "    ! SSH error: $(cat "$WORKDIR/ssh_error.log")"
    KEEP_ERRORS=true
    ((FAIL_COUNT++))
    continue
  fi
  
  # upload key
  if ! ssh -T $SSH_OPTS "${JETKVM_USER}@${JETKVM_HOST}" "cat > ${REMOTE_KEY}" < "$PRIVKEY" 2>"$WORKDIR/ssh_error.log"; then
    log "    ! Failed to upload key to ${JETKVM_HOST}"
    log "    ! SSH error: $(cat "$WORKDIR/ssh_error.log")"
    KEEP_ERRORS=true
    ((FAIL_COUNT++))
    continue
  fi

  log "    - restarting service on ${JETKVM_HOST}..."
  if ! ssh -T $SSH_OPTS "${JETKVM_USER}@${JETKVM_HOST}" 2>"$WORKDIR/ssh_error.log" <<'EOSSH'
set -e
if systemctl list-unit-files 2>/dev/null | grep -q jetkvm; then
  systemctl restart jetkvm
elif systemctl list-unit-files 2>/dev/null | grep -q kvm; then
  systemctl restart kvm
else
  # last resort: kill the app, supervisor should bring it back
  pkill -f jetkvm_app || true
fi
EOSSH
  then
    log "    ! Failed to restart service on ${JETKVM_HOST}"
    log "    ! SSH error: $(cat "$WORKDIR/ssh_error.log")"
    KEEP_ERRORS=true
    ((FAIL_COUNT++))
    continue
  fi

  log "    [OK] ${JETKVM_HOST} updated"
  ((SUCCESS_COUNT++))
done

# ----------------------------
# 11. summary
# ----------------------------
log "[+] Summary: $SUCCESS_COUNT/${#HOSTS[@]} hosts updated successfully"
if [[ $FAIL_COUNT -gt 0 ]]; then
  log "[-] $FAIL_COUNT host(s) failed - check logs above for details"
  if [[ "$KEEP_ERRORS" == "true" ]]; then
    log "[-] Error files preserved in: $WORKDIR"
  fi
  exit 1
fi

log "[+] All JetKVM hosts processed successfully."