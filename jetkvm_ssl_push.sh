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

# Improved ERR trap: log the failing command, exit code, and caller info
ERR_trap() {
  rc=$?
  # caller returns: <line> <function> <sourcefile>
  caller_info=$(caller 0 || true)
  cleanup_host_tmp_dir "${CURRENT_HOST_TMP_DIR:-}"
  log "[!] ERROR - exit $rc - command: ${BASH_COMMAND:-unknown} - caller: ${caller_info}"
}
trap 'ERR_trap' ERR

# ----------------------------
# Logging function with timestamps
# ----------------------------
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# ----------------------------
# secure helpers for temp data
# ----------------------------
safe_name() {
  local input="$1"
  local safe="${input//[^A-Za-z0-9._-]/_}"
  [[ -n "$safe" ]] || safe="entry"
  printf '%s' "$safe"
}

secure_wipe_directory() {
  local dir="$1"
  [[ -d "$dir" ]] || return
  if command -v shred >/dev/null 2>&1; then
    while IFS= read -r -d '' file; do
      shred -u "$file" 2>/dev/null || rm -f "$file" 2>/dev/null || true
    done < <(find "$dir" -type f -print0 2>/dev/null || true)
  fi
  rm -rf "$dir" 2>/dev/null || true
}

cleanup_host_tmp_dir() {
  local dir="$1"
  [[ -n "${dir:-}" ]] || return
  secure_wipe_directory "$dir"
  if [[ "${CURRENT_HOST_TMP_DIR:-}" == "$dir" ]]; then
    CURRENT_HOST_TMP_DIR=""
  fi
}

record_error_note() {
  local host="$1"
  local cert="$2"
  local message="$3"
  local host_safe cert_safe
  host_safe=$(safe_name "$host")
  cert_safe=$(safe_name "$cert")
  local note_file="${ERROR_NOTE_DIR}/${host_safe}_${cert_safe}.log"
  mkdir -p "$ERROR_NOTE_DIR"
  {
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "Host: $host"
    echo "Certificate: $cert"
    echo
    echo "$message"
  } > "$note_file"
  log "    ! Error details saved to: $note_file"
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

JETKVM_AUTOACCEPT_NEW_HOSTKEYS="${JETKVM_AUTOACCEPT_NEW_HOSTKEYS:-false}"
JETKVM_AUTOACCEPT_NEW_HOSTKEYS="${JETKVM_AUTOACCEPT_NEW_HOSTKEYS,,}"

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
ERROR_NOTE_DIR="$WORKDIR/error_notes"
CURRENT_HOST_TMP_DIR=""
ENSURE_TLS_MODE_RESULT=""
trap 'if [[ "$KEEP_ERRORS" == "false" ]]; then secure_wipe_directory "$WORKDIR"; fi' EXIT

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

        ACCEPT_KEY="false"
        if [[ "$JETKVM_AUTOACCEPT_NEW_HOSTKEYS" == "true" ]]; then
          ACCEPT_KEY="true"
          log "    [AUTO] JETKVM_AUTOACCEPT_NEW_HOSTKEYS=true, automatically trusting host key for ${JETKVM_HOST}"
        else
          # prompt the user to accept the key
          read -r -p "    Accept and add host key to ${KNOWN_HOSTS_FILE}? [y/N] " resp || resp="n"
          if [[ "$resp" =~ ^[Yy]$ ]]; then
            ACCEPT_KEY="true"
          fi
        fi

        if [[ "$ACCEPT_KEY" == "true" ]]; then
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
ENSURE_TLS_MODE_RESULT=""
ensure_remote_tls_custom() {
  local host="$1"
  log "    - ensuring remote /data/kvm_config.json has tls_mode=custom on ${host}"
  local ssh_err="$WORKDIR/ssh_tls_${host}.err"
  local ssh_out
  if ! ssh_out=$(ssh -T $SSH_OPTS "${JETKVM_USER}@${host}" 2>"$ssh_err" <<'REMOTE'
set -e
CONFIG="/data/kvm_config.json"
  if [ ! -f "$CONFIG" ]; then
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
        sed 's/\("tls_mode"[[:space:]]*:[[:space:]]*\)"[^"]*"/\1"custom"/' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG" && echo "UPDATED" || echo "SED_FAILED"
    fi
  else
    # Do not insert tls_mode if missing; report and skip
    echo "NO_ENTRY"
  fi
REMOTE
  ); then
    log "    ! SSH failure while ensuring tls_mode on ${host} - see $ssh_err"
    ENSURE_TLS_MODE_RESULT="SSH_FAILURE"
    return 1
  fi

  ENSURE_TLS_MODE_RESULT="$ssh_out"
  case "$ssh_out" in
    UPDATED)
      log "    [+] tls_mode set to 'custom' on ${host}"
      return 0
      ;;
    OK)
      log "    [OK] tls_mode already 'custom' on ${host}"
      return 0
      ;;
    NO_CONFIG)
      log "    ! No /data/kvm_config.json found on ${host}; skipping tls_mode update"
      return 1
      ;;
    NO_ENTRY)
      log "    ! 'tls_mode' not found in /data/kvm_config.json on ${host}; not inserting (skipping)"
      return 1
      ;;
    SED_FAILED|AWK_FAILED|BAD_FORMAT)
      log "    ! Failed to update /data/kvm_config.json on ${host}; see $ssh_err"
      return 1
      ;;
    *)
      log "    ! Unexpected output while checking tls_mode on ${host}: $ssh_out"
      return 1
      ;;
  esac
}

# ----------------------------
# compare remote cert/key to local files
# ----------------------------
compare_remote_certs() {
  local host="$1" local_cert="$2" local_key="$3" host_tmp_dir="$4"
  local remote_cert_tmp="$host_tmp_dir/remote_cert.pem"
  local remote_key_tmp="$host_tmp_dir/remote_key.pem"
  local ssh_err_cert="$WORKDIR/ssh_cert_err_$(safe_name "$host").log"
  local ssh_err_key="$WORKDIR/ssh_key_err_$(safe_name "$host").log"

  log "    - checking existing cert/key on ${host}"

  # fetch remote cert
  rm -f "$remote_cert_tmp" "$remote_key_tmp" "$ssh_err_cert" "$ssh_err_key"
  if ! ssh -T $SSH_OPTS "${JETKVM_USER}@${host}" "cat '${REMOTE_CERT}'" > "$remote_cert_tmp" 2>"$ssh_err_cert"; then
    # if remote cert doesn't exist or cannot be read, treat as update needed
    log "    ! Could not read remote cert on ${host} (will upload). SSH stderr: $(head -c200 "$ssh_err_cert" 2>/dev/null || true)"
    return 1
  fi

  # fetch remote key
  if ! ssh -T $SSH_OPTS "${JETKVM_USER}@${host}" "cat '${REMOTE_KEY}'" > "$remote_key_tmp" 2>"$ssh_err_key"; then
    log "    ! Could not read remote key on ${host} (will upload). SSH stderr: $(head -c200 "$ssh_err_key" 2>/dev/null || true)"
    return 1
  fi

  # compare files
  if cmp -s "$local_cert" "$remote_cert_tmp" && cmp -s "$local_key" "$remote_key_tmp"; then
    log "    [OK] No update required on ${host} (cert/key identical)"
    rm -f "$remote_cert_tmp" "$remote_key_tmp" 2>/dev/null || true
    return 0
  else
    log "    - Remote cert/key differ from downloaded files on ${host} (will upload)"
    rm -f "$remote_cert_tmp" "$remote_key_tmp" 2>/dev/null || true
    return 1
  fi
}

# ----------------------------
# 8. constants / paths
# ----------------------------
REMOTE_DIR="/userdata/jetkvm/tls"
REMOTE_CERT="${REMOTE_DIR}/user-defined.crt"
REMOTE_KEY="${REMOTE_DIR}/user-defined.key"

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

  HOST_TMP_DIR="$(mktemp -d "$WORKDIR/host.XXXXXX")"
  ZIPFILE="$HOST_TMP_DIR/cert_bundle.zip"
  CERTDIR="$HOST_TMP_DIR/certs"
  mkdir -p "$CERTDIR"
  CURRENT_HOST_TMP_DIR="$HOST_TMP_DIR"

  log "    - downloading from certmate..."
  # Note: /tls endpoint is used to download the certificate bundle in ZIP format
  if ! download_with_retry "${CERTMATE_BASE}/${CERT_NAME}/tls" "$ZIPFILE"; then
    log "    ! Failed to download ${CERT_NAME} after retries"
    record_error_note "$JETKVM_HOST" "$CERT_NAME" "Failed to download bundle after retries (last HTTP status: ${HTTP_CODE:-unknown})."
    KEEP_ERRORS=true
      ((FAIL_COUNT++)) || true
    cleanup_host_tmp_dir "$HOST_TMP_DIR"
    continue
  fi

  # quick sanity check: is it actually a zip?
  if ! file "$ZIPFILE" | grep -qi 'Zip archive data'; then
    file_type=$(file "$ZIPFILE" 2>/dev/null || echo "unknown data")
    log "    ! Downloaded file is not a ZIP (detected: $file_type)"
    record_error_note "$JETKVM_HOST" "$CERT_NAME" "Downloaded file is not a ZIP (detected: $file_type)."
    KEEP_ERRORS=true
    ((FAIL_COUNT++)) || true
    cleanup_host_tmp_dir "$HOST_TMP_DIR"
    continue
  fi

  log "    - unpacking..."
  if ! unzip -oq "$ZIPFILE" -d "$CERTDIR"; then
    log "    ! Failed to unpack ${ZIPFILE}"
    record_error_note "$JETKVM_HOST" "$CERT_NAME" "Failed to unpack downloaded archive (zip file rejected by unzip)."
    KEEP_ERRORS=true
    ((FAIL_COUNT++)) || true
    cleanup_host_tmp_dir "$HOST_TMP_DIR"
    continue
  fi

  FULLCHAIN="$CERTDIR/fullchain.pem"
  PRIVKEY="$CERTDIR/privkey.pem"

  if [[ ! -f "$FULLCHAIN" || ! -f "$PRIVKEY" ]]; then
    log "    ! ERROR: ${CERT_NAME} archive did not contain fullchain.pem and privkey.pem"
    record_error_note "$JETKVM_HOST" "$CERT_NAME" "Archive missing expected fullchain.pem or privkey.pem files."
    KEEP_ERRORS=true
    ((FAIL_COUNT++)) || true
    cleanup_host_tmp_dir "$HOST_TMP_DIR"
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
    ((SUCCESS_COUNT++)) || true
    cleanup_host_tmp_dir "$HOST_TMP_DIR"
    continue
  fi

  REMOTE_DIFFERS=true
  NEEDS_RESTART=false
  TLS_MODE_UPDATED=false

  # Ensure remote JetKVM is configured to use a custom TLS mode before uploading
  if ! ensure_remote_tls_custom "${JETKVM_HOST}"; then
    record_error_note "$JETKVM_HOST" "$CERT_NAME" "Failed to ensure remote tls_mode is 'custom' (status: ${ENSURE_TLS_MODE_RESULT:-unknown})."
    KEEP_ERRORS=true
    ((FAIL_COUNT++)) || true
    cleanup_host_tmp_dir "$HOST_TMP_DIR"
    continue
  fi
  if [[ "${ENSURE_TLS_MODE_RESULT:-}" == "UPDATED" ]]; then
    NEEDS_RESTART=true
    TLS_MODE_UPDATED=true
  fi

  # Compare downloaded cert/key with existing remote files; skip upload/restart if identical
  if compare_remote_certs "${JETKVM_HOST}" "$FULLCHAIN" "$PRIVKEY" "$HOST_TMP_DIR"; then
    REMOTE_DIFFERS=false
    if [[ "$NEEDS_RESTART" != "true" ]]; then
      log "    [OK] ${JETKVM_HOST} (no update required)"
      ((SUCCESS_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
    fi
    log "    - tls_mode changed; restarting ${JETKVM_HOST} even though cert/key already match"
  fi

  if [[ "$REMOTE_DIFFERS" == "true" ]]; then
    log "    - uploading cert/key to ${JETKVM_HOST}..."
    # upload cert
    if ! ssh -T $SSH_OPTS "${JETKVM_USER}@${JETKVM_HOST}" "cat > ${REMOTE_CERT}" < "$FULLCHAIN" 2>"$WORKDIR/ssh_error.log"; then
      log "    ! Failed to upload certificate to ${JETKVM_HOST}"
      log "    ! SSH error: $(cat "$WORKDIR/ssh_error.log")"
      KEEP_ERRORS=true
        ((FAIL_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
    fi
    
    # upload key
    if ! ssh -T $SSH_OPTS "${JETKVM_USER}@${JETKVM_HOST}" "cat > ${REMOTE_KEY}" < "$PRIVKEY" 2>"$WORKDIR/ssh_error.log"; then
      log "    ! Failed to upload key to ${JETKVM_HOST}"
      log "    ! SSH error: $(cat "$WORKDIR/ssh_error.log")"
      KEEP_ERRORS=true
      ((FAIL_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
    fi
    NEEDS_RESTART=true
  fi

  if [[ "$NEEDS_RESTART" != "true" ]]; then
    log "    [OK] ${JETKVM_HOST} (no update required)"
    ((SUCCESS_COUNT++)) || true
    cleanup_host_tmp_dir "$HOST_TMP_DIR"
    continue
  fi

  log "    - restarting service on ${JETKVM_HOST}..."
  SSH_RESTART_STATUS=$(ssh -T $SSH_OPTS "${JETKVM_USER}@${JETKVM_HOST}" 2>"$WORKDIR/ssh_error.log" <<'EOSSH'
set -e
STATUS="UNKNOWN"
# Prefer systemctl where available (some hosts may have it)
if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files 2>/dev/null | grep -q 'jetkvm\.service'; then
    if systemctl restart jetkvm >/dev/null 2>&1; then
      STATUS="SERVICE_RESTART:jetkvm"
    else
      STATUS="SERVICE_FAILED:jetkvm"
    fi
  elif systemctl list-unit-files 2>/dev/null | grep -q 'kvm\.service'; then
    if systemctl restart kvm >/dev/null 2>&1; then
      STATUS="SERVICE_RESTART:kvm"
    else
      STATUS="SERVICE_FAILED:kvm"
    fi
  fi
fi

if [ "$STATUS" = "UNKNOWN" ]; then
  # BusyBox-based JetKVM: reboot the device via backgrounded shell
  if command -v busybox >/dev/null 2>&1; then
    if sh -c '(sleep 1; busybox reboot) >/dev/null 2>&1 &' ; then
      STATUS="REBOOT_TRIGGERED:busybox"
    else
      STATUS="REBOOT_FAILED:busybox"
    fi
  elif command -v reboot >/dev/null 2>&1; then
    if sh -c '(sleep 1; reboot) >/dev/null 2>&1 &' ; then
      STATUS="REBOOT_TRIGGERED:reboot"
    else
      STATUS="REBOOT_FAILED:reboot"
    fi
  else
    STATUS="NO_REBOOT_CMD"
  fi
fi

echo "$STATUS"
EOSSH
  )
  SSH_RC=$?
  if [[ $SSH_RC -ne 0 ]]; then
    log "    ! Failed to restart service on ${JETKVM_HOST}"
    log "    ! SSH error: $(cat "$WORKDIR/ssh_error.log")"
    KEEP_ERRORS=true
    ((FAIL_COUNT++)) || true
    cleanup_host_tmp_dir "$HOST_TMP_DIR"
    continue
  fi

  case "$SSH_RESTART_STATUS" in
    SERVICE_RESTART:jetkvm)
      log "    [OK] Restarted jetkvm.service via systemctl"
      ;;
    SERVICE_RESTART:kvm)
      log "    [OK] Restarted kvm.service via systemctl"
      ;;
    REBOOT_TRIGGERED:busybox)
      log "    [OK] Reboot scheduled via busybox on ${JETKVM_HOST}"
      ;;
    REBOOT_TRIGGERED:reboot)
      log "    [OK] Reboot scheduled via reboot on ${JETKVM_HOST}"
      ;;
    SERVICE_FAILED:jetkvm)
      log "    [INFO] systemctl restart jetkvm failed on ${JETKVM_HOST}; please investigate."
      record_error_note "$JETKVM_HOST" "$CERT_NAME" "systemctl restart jetkvm failed on host."
      KEEP_ERRORS=true
      ((FAIL_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
      ;;
    SERVICE_FAILED:kvm)
      log "    [INFO] systemctl restart kvm failed on ${JETKVM_HOST}; please investigate."
      record_error_note "$JETKVM_HOST" "$CERT_NAME" "systemctl restart kvm failed on host."
      KEEP_ERRORS=true
      ((FAIL_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
      ;;
    REBOOT_FAILED:busybox)
      log "    [INFO] Failed to trigger busybox reboot on ${JETKVM_HOST}; please reboot manually."
      record_error_note "$JETKVM_HOST" "$CERT_NAME" "Failed to execute busybox reboot on host."
      KEEP_ERRORS=true
      ((FAIL_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
      ;;
    REBOOT_FAILED:reboot)
      log "    [INFO] Failed to execute reboot command on ${JETKVM_HOST}; please reboot manually."
      record_error_note "$JETKVM_HOST" "$CERT_NAME" "Failed to execute reboot command on host."
      KEEP_ERRORS=true
      ((FAIL_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
      ;;
    NO_REBOOT_CMD)
      log "    [INFO] No reboot command available on ${JETKVM_HOST}; please reboot manually."
      record_error_note "$JETKVM_HOST" "$CERT_NAME" "No reboot command available on host; manual reboot required."
      KEEP_ERRORS=true
      ((FAIL_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
      ;;
    *)
      log "    [INFO] Unknown restart status '${SSH_RESTART_STATUS}' on ${JETKVM_HOST}"
      record_error_note "$JETKVM_HOST" "$CERT_NAME" "Unknown restart status '${SSH_RESTART_STATUS}' returned while restarting."
      KEEP_ERRORS=true
      ((FAIL_COUNT++)) || true
      cleanup_host_tmp_dir "$HOST_TMP_DIR"
      continue
      ;;
  esac

  if [[ "$REMOTE_DIFFERS" == "true" ]]; then
    log "    [OK] ${JETKVM_HOST} updated"
  elif [[ "$TLS_MODE_UPDATED" == "true" ]]; then
    log "    [OK] ${JETKVM_HOST} tls_mode set to 'custom' and service restarted"
  else
    log "    [OK] ${JETKVM_HOST}"
  fi
  ((SUCCESS_COUNT++)) || true
  cleanup_host_tmp_dir "$HOST_TMP_DIR"
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
