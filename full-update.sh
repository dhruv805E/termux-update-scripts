#!/bin/bash
set -euo pipefail # Exit on error, unset variable, pipe failure

echo "DEBUG exec ARGS: Script started. Total args: $#. All args: [$*]"
echo "DEBUG exec ARGS: \$1=[$1], \$2=[$2], \$3=[$3], \$4=[$4], \$5=[$5], \$6=[$6], \$7=[$7]"

# Save original arguments before they are shifted by the parsing loop
ORIGINAL_ARGS=("$@")

# === Default Configuration ===
DEFAULT_LOG_DIR="logs"
DEFAULT_RETENTION_DAYS=7
DEFAULT_VENV_DIR="myenv" # Default for your "myenv"
DEFAULT_DEPENDENCIES=("git" "python" "pip" "curl" "proot-distro" "awk" "tee" "grep" "df" "find" "date" "realpath" "cmp" "coreutils" "jq") # Make sure this line is complete and not truncated
DEFAULT_SCRIPT_URL="https://raw.githubusercontent.com/dhruv805E/termux-update-scripts/main/full-update.sh" # CHANGE THIS if yo>
DEFAULT_REPO_DIR="~/myproject" # EXAMPLE: Path inside PRoot (e.g. /root/myproject or /home/user/myproject), adjust as needed
DEFAULT_EXPECTED_HASH_URL="https://raw.githubusercontent.com/dhruv805E/termux-update-scripts/main/full-update.sh.sha256" # CHA>
DEFAULT_REQUIRED_SPACE_MB=500
DEFAULT_GIT_REMOTE="origin"
DEFAULT_GIT_BRANCH="main"
DEFAULT_MAX_RETRIES=3
DEFAULT_INITIAL_RETRY_DELAY=5 # seconds
MAX_TOTAL_WAIT_TIME=300 # Max total seconds for retries

# === Script Variables (will be set from defaults or args) ===
LOG_DIR="$DEFAULT_LOG_DIR"
RETENTION_DAYS="$DEFAULT_RETENTION_DAYS"
VENV_DIR="$DEFAULT_VENV_DIR"
SCRIPT_URL="$DEFAULT_SCRIPT_URL"
REPO_DIR="$DEFAULT_REPO_DIR"
EXPECTED_HASH_URL="$DEFAULT_EXPECTED_HASH_URL"
REQUIRED_SPACE_MB="$DEFAULT_REQUIRED_SPACE_MB"
GIT_REMOTE="$DEFAULT_GIT_REMOTE"
GIT_BRANCH="$DEFAULT_GIT_BRANCH"
MAX_RETRIES="$DEFAULT_MAX_RETRIES"
INITIAL_RETRY_DELAY="$DEFAULT_INITIAL_RETRY_DELAY"

FORCE=false
NOTIFY=false
PROOT_DISTRO=""
PROOT_DISTRO_SPECIFIED_VIA_ARG=false

SCRIPT_FILE="$(realpath "$0")"
SCRIPT_NAME="$(basename "$0")"
LOGFILE="" # Will be set after LOG_DIR is confirmed

# === Function Definitions ===
usage() {
  echo "Usage: $SCRIPT_NAME [options]"
  echo ""
  echo "Performs updates within a PRoot distro (e.g., Ubuntu) on a NON-ROOTED device."
  echo "Focuses on PRoot guest OS packages, Git repositories, and Python virtual environments."
  echo "Host (Termux) package management is NOT handled by this script."
  echo ""
  echo "Options:"
  echo "  -f, --force             Continue script execution even if non-critical errors occur."
  echo "  -n, --notify            Enable Telegram notifications (requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars)."
  echo "  -d, --distro DISTRO     Specify the PRoot distro to update (e.g., ubuntu). If not set, attempts auto-detection."
  echo "      --repo-dir PATH     Path to the Git repository (inside the PRoot distro) to update (Default: \"$DEFAULT_REPO_DIR\")."
  echo "      --venv-dir NAME     Name of the Python venv directory inside the PRoot user's home (Default: \"$DEFAULT_VENV_DIR\")."
  echo "      --git-remote REMOTE Git remote to pull from (Default: \"$DEFAULT_GIT_REMOTE\")."
  echo "      --git-branch BRANCH Git branch to pull (Default: \"$DEFAULT_GIT_BRANCH\")."
  echo "      --log-dir PATH      Directory to store log files (Default: \"$DEFAULT_LOG_DIR\")."
  echo "  -h, --help              Display this help message and exit."
  echo ""
  echo "IMPORTANT: This script is for NON-ROOTED devices. Ensure all Termux dependencies"
  echo "           (${DEFAULT_DEPENDENCIES[*]}) are installed manually using 'pkg install <package>'."
  echo ""
  echo "Example (Focus on Ubuntu PRoot):"
  echo "  $SCRIPT_NAME --distro ubuntu --repo-dir /root/myproject --venv-dir myenv --notify"
  exit 0
}

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"; }

notify_error() {
  local error_message="[ERROR] $1"
  log "$error_message"
  send_notification "[Update Error] $1 on $(hostname)"
  if [[ "$FORCE" != true ]]; then log "Exiting due to error (--force not used)."; exit 1; else log "Continuing execution due to --force flag."; return 1; fi
}

send_notification() {
  if [[ "$NOTIFY" == true && -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
    local text_to_send="$1"
    local encoded_text
    if command -v jq &>/dev/null; then
        encoded_text=$(printf '%s' "$text_to_send" | jq -s -R -r @uri)
    else
        # Basic URL encoding fallback
        encoded_text=$(printf %s "$text_to_send" | awk 'BEGIN{while(getline l){gsub(/%/, "%25", l); gsub(/ /, "%20", l); gsub(/#/, "%23", l); gsub(/\$/, "%24", l); gsub(/&/, "%26", l); gsub(/\+/, "%2B", l); gsub(/,/, "%2C", l); gsub(/\//, "%2F", l); gsub(/:/, "%3A", l); gsub(/;/, "%3B", l); gsub(/=/, "%3D", l); gsub(/\?/, "%3F", l); gsub(/@/, "%40", l); gsub(/</, "%3C", l); gsub(/>/, "%3E", l); gsub(/\[/, "%5B", l); gsub(/\]/, "%5D", l); gsub(/\\/, "%5C", l); gsub(/\^/, "%5E", l); gsub(/`/, "%60", l); gsub(/{/, "%7B", l); gsub(/\|/, "%7C", l); gsub(/}/, "%7D", l); gsub(/~/, "%7E", l); print l}}')
        log "Warning: jq not found for robust URL encoding of Telegram message. Using basic fallback."
    fi

    local api_url="https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage"
    local payload="chat_id=$TELEGRAM_CHAT_ID&text=$encoded_text&parse_mode=Markdown"

    response=$(curl -sS -w "\n%{http_code}" -X POST "$api_url" -d "$payload" --connect-timeout 10 --max-time 15) || {
      log "[ERROR] curl command failed to connect to Telegram API."; return 1;
    }
    http_code=$(echo "$response" | tail -n1); http_body=$(echo "$response" | sed '$ d')
    if [[ "$http_code" -ne 200 ]]; then log "[ERROR] Failed to send Telegram notification. HTTP Code: $http_code. Response: $http_body"; return 1; fi
    log "Telegram notification sent successfully."
  elif [[ "$NOTIFY" == true ]]; then log "Warning: Telegram notification requested (--notify) but TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID environment variables are not set or empty."; return 1; fi
  return 0
}

retry() {
  local n=0; local delay=$INITIAL_RETRY_DELAY; local command_to_run=("$@"); local exit_code=0; local total_wait=0
  log "Attempting command: ${command_to_run[*]}"
  until "${command_to_run[@]}"; do
    exit_code=$?; ((n++)); total_wait=$((total_wait + delay))
    if ((n >= MAX_RETRIES || total_wait >= MAX_TOTAL_WAIT_TIME)); then log "[ERROR] Command failed after $n attempts and $total_wait seconds with exit code $exit_code: ${command_to_run[*]}"; return $exit_code; fi
    local jitter_ms=$((RANDOM % 1000)); local jitter_sec; jitter_sec=$(awk "BEGIN {print $jitter_ms/1000}")
    log "Command failed with exit code $exit_code. Retrying attempt $(($n + 1))/$MAX_RETRIES in $delay sec + $jitter_sec sec jitter (total wait: $total_wait sec)..."
    sleep "$delay"; sleep "$jitter_sec"; delay=$((delay * 2))
  done
  log "Command succeeded: ${command_to_run[*]}"; return 0
}

# === Argument Parsing ===
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -f|--force) FORCE=true; shift ;;
    -n|--notify) NOTIFY=true; shift ;;
    -d=*|--distro=*) PROOT_DISTRO="${key#*=}"; PROOT_DISTRO_SPECIFIED_VIA_ARG=true; shift ;;
    -d|--distro) PROOT_DISTRO="$2"; PROOT_DISTRO_SPECIFIED_VIA_ARG=true; shift; shift ;;
    --repo-dir=*) REPO_DIR="${key#*=}"; shift ;;
    --repo-dir) REPO_DIR="$2"; shift; shift ;;
    --venv-dir=*) VENV_DIR="${key#*=}"; shift ;;
    --venv-dir) VENV_DIR="$2"; shift; shift ;;
    --git-remote=*) GIT_REMOTE="${key#*=}"; shift ;;
    --git-remote) GIT_REMOTE="$2"; shift; shift ;;
    --git-branch=*) GIT_BRANCH="${key#*=}"; shift ;;
    --git-branch) GIT_BRANCH="$2"; shift; shift ;;
    --log-dir=*) LOG_DIR="${key#*=}"; shift ;;
    --log-dir) LOG_DIR="$2"; shift; shift ;;
    --retention=*) RETENTION_DAYS="${key#*=}"; shift ;; 
    --retention) RETENTION_DAYS="$2"; shift; shift ;; 
    --req-space=*) REQUIRED_SPACE_MB="${key#*=}"; shift ;; 
    --req-space) REQUIRED_SPACE_MB="$2"; shift; shift ;; 
    -h|--help) usage ;;
    *) echo "[ERROR] Unknown option: $1" >&2; usage ;;
  esac
done


if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]]; then echo "[ERROR] --retention value '$RETENTION_DAYS' is not a valid number." >&2; usage; fi
if ! [[ "$REQUIRED_SPACE_MB" =~ ^[0-9]+$ ]]; then echo "[ERROR] --req-space value '$REQUIRED_SPACE_MB' is not a valid number." >&2; usage; fi


# === Setup Logging ===  <-- MOVED HERE
mkdir -p "$LOG_DIR" # Ensure LOG_DIR exists (using final value of LOG_DIR from args or default)
LOGFILE="$LOG_DIR/update_$(date '+%Y-%m-%d_%H-%M-%S').log" # Define LOGFILE path

# Define trap now that LOGFILE is set, if trap function uses log()
SCRIPT_TRAP_EXIT_CODE=0
cleanup_and_exit() {
    local exit_code=$? 
    if [[ "$SCRIPT_TRAP_EXIT_CODE" -ne 0 ]]; then exit_code="$SCRIPT_TRAP_EXIT_CODE"; fi
    # Using echo here initially in case log() itself has issues or LOGFILE isn't writable
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Script exiting with code: $exit_code" | tee -a "$LOGFILE" # log() might be safer if it's robust
    if (( exit_code != 0 && exit_code != 130 && exit_code != 143 )); then 
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Script interrupted or exited with error." | tee -a "$LOGFILE"
    elif (( exit_code == 130 || exit_code == 143 )); then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] Script interrupted by signal (Ctrl+C or Term)." | tee -a "$LOGFILE"
    fi
}
trap 'cleanup_and_exit' EXIT SIGINT SIGTERM
# Now it's safe to use the log() function.

log "DEBUG exec PARSED: PROOT_DISTRO=[$PROOT_DISTRO], NOTIFY=[$NOTIFY], REPO_DIR=[$REPO_DIR], VENV_DIR=[$VENV_DIR], PROOT_DISTRO_SPECIFIED_VIA_ARG=[$PROOT_DISTRO_SPECIFIED_VIA_ARG]"



# === Debug Parsed Arguments (NOW IT'S SAFE TO LOG) ===
log "DEBUG exec PARSED: PROOT_DISTRO=[$PROOT_DISTRO], NOTIFY=[$NOTIFY], REPO_DIR=[$REPO_DIR], VENV_DIR=[$VENV_DIR], PROOT_DISTRO_SPECIFIED_VIA_ARG=[$PROOT_DISTRO_SPECIFIED_VIA_ARG]"

# === Initial Log Messages ===
log "=== Starting Update Script ($SCRIPT_NAME) for NON-ROOTED device ==="
log "Run options: FORCE=$FORCE, NOTIFY=$NOTIFY, PROOT_DISTRO='$PROOT_DISTRO' (Specified: $PROOT_DISTRO_SPECIFIED_VIA_ARG)"
log "Config: REPO_DIR='$REPO_DIR', VENV_DIR='$VENV_DIR', GIT_REMOTE='$GIT_REMOTE', GIT_BRANCH='$GIT_BRANCH'"


# === Detect Distro If Not Set ===
if [[ -z "$PROOT_DISTRO" ]]; then
  log "No PRoot distribution specified via --distro. Attempting auto-detection..."
  if ! command -v proot-distro &> /dev/null; then
      log "[WARNING] 'proot-distro' command not found. Cannot auto-detect or manage PRoot distributions. PRoot steps will be skipped."
      PROOT_DISTRO="" 
  else
      INSTALLED_DISTROS=($(proot-distro list | awk '/installed/ {print $1}'))
      NUM_INSTALLED=${#INSTALLED_DISTROS[@]}
      if [[ $NUM_INSTALLED -eq 1 ]]; then PROOT_DISTRO="${INSTALLED_DISTROS[0]}"; log "Auto-detected installed PRoot distribution: $PROOT_DISTRO";
      elif [[ $NUM_INSTALLED -gt 1 ]]; then log "[ERROR] Multiple PRoot distributions installed: ${INSTALLED_DISTROS[*]}"; SCRIPT_TRAP_EXIT_CODE=1; notify_error "Please specify which distribution to update using the --distro <name> option."; # Exits
      else log "No installed PRoot distributions found. PRoot-related updates will be skipped."; PROOT_DISTRO=""; fi
  fi
else log "Using specified PRoot distribution: $PROOT_DISTRO"; fi


# === Preflight Checks ===
log "\n=== Running Preflight Checks ==="
log "Checking internet connectivity..."
if ! curl -fsSL --connect-timeout 5 "$SCRIPT_URL" -o /dev/null; then SCRIPT_TRAP_EXIT_CODE=1; notify_error "No internet connection or unable to reach script URL: $SCRIPT_URL"; fi
log "Internet connection check passed."

log "Checking disk space (required: ${REQUIRED_SPACE_MB}MB on partition for '$LOG_DIR')..."
# Use a more portable df command: df -kP shows sizes in 1K blocks, $4 is usually 'Available'
AVAILABLE_SPACE_KB=$(df -kP "$LOG_DIR" 2>/dev/null | awk 'NR==2 {print $4}')

if [[ -z "$AVAILABLE_SPACE_KB" || ! "$AVAILABLE_SPACE_KB" =~ ^[0-9]+$ ]]; then
  # If df failed, AVAILABLE_SPACE_KB will likely be empty or non-numeric
  SCRIPT_TRAP_EXIT_CODE=1; notify_error "Could not determine available disk space for '$LOG_DIR', or the value was non-numeric. df output field was: '$AVAILABLE_SPACE_KB'"
else
  AVAILABLE_SPACE_MB=$((AVAILABLE_SPACE_KB / 1024))
  if ((AVAILABLE_SPACE_MB < REQUIRED_SPACE_MB)); then
    SCRIPT_TRAP_EXIT_CODE=1; notify_error "Low disk space: only ${AVAILABLE_SPACE_MB}MB available on the partition for '$LOG_DIR', but ${REQUIRED_SPACE_MB}MB is required."
  fi
  log "Disk space check passed (${AVAILABLE_SPACE_MB}MB available on the partition for '$LOG_DIR')."
fi

log "Checking Termux dependencies: ${DEFAULT_DEPENDENCIES[*]}"
MISSING_DEPS_MSG="The following Termux dependencies are missing:"
MISSING_DEPS_LIST=""
HAS_MISSING_DEPS=false
for dep in "${DEFAULT_DEPENDENCIES[@]}"; do
  if ! command -v "$dep" &>/dev/null; then
    log "[Warning] Termux Dependency '$dep' is missing."
    MISSING_DEPS_LIST+=" $dep"
    HAS_MISSING_DEPS=true
  fi
done
if [[ "$HAS_MISSING_DEPS" == true ]]; then
  SCRIPT_TRAP_EXIT_CODE=1; notify_error "$MISSING_DEPS_MSG $MISSING_DEPS_LIST. Please install them manually in Termux (e.g., 'pkg install${MISSING_DEPS_LIST}')."
else log "All required Termux dependencies are present."; fi


# === Self-update with Hash Verification (Hardened Version) ===
log "\n=== Checking for Script Updates ==="
TEMP_SCRIPT=$(mktemp); TEMP_HASH_FILE="$TEMP_SCRIPT.sha256"
TEMP_FILES_TO_CLEAN+=("$TEMP_SCRIPT" "$TEMP_HASH_FILE") # Add to global cleanup

EXPECTED_HASH=""; log "Fetching expected hash from $EXPECTED_HASH_URL"
if curl -fsSL --retry 3 --connect-timeout 15 "$EXPECTED_HASH_URL" -o "$TEMP_HASH_FILE"; then
  EXPECTED_HASH=$(awk '{print $1}' "$TEMP_HASH_FILE" | head -n 1)
  if [[ -z "$EXPECTED_HASH" ]]; then log "Warning: Hash file '$TEMP_HASH_FILE' is empty or invalid. Skipping hash check."; else log "Expected hash fetched: $EXPECTED_HASH"; fi
else log "Warning: Failed to fetch hash from $EXPECTED_HASH_URL. Skipping hash check."; fi

log "Fetching remote script from $SCRIPT_URL"
if curl -fsSL --retry 3 --connect-timeout 30 "$SCRIPT_URL" -o "$TEMP_SCRIPT"; then
  if ! cmp -s "$TEMP_SCRIPT" "$SCRIPT_FILE"; then
    log "New script version found. Verifying integrity..."; VERIFIED=false
    if [[ -n "$EXPECTED_HASH" ]]; then
      DOWNLOADED_HASH=""
      if command -v sha256sum &>/dev/null; then DOWNLOADED_HASH=$(sha256sum "$TEMP_SCRIPT" | awk '{print $1}');
      elif command -v shasum &>/dev/null; then DOWNLOADED_HASH=$(shasum -a 256 "$TEMP_SCRIPT" | awk '{print $1}');
      else SCRIPT_TRAP_EXIT_CODE=1; notify_error "No SHA256 tool (sha256sum or shasum from coreutils) found! Cannot verify script integrity."; fi
      log "Downloaded script hash: $DOWNLOADED_HASH"
      if [[ "$DOWNLOADED_HASH" != "$EXPECTED_HASH" ]]; then FORCE=false; SCRIPT_TRAP_EXIT_CODE=1; notify_error "Hash mismatch! Expected '$EXPECTED_HASH', got '$DOWNLOADED_HASH'. Aborting update."; fi
      log "Hash verification successful."; VERIFIED=true
    else
      log "Skipping hash verification (expected hash unavailable)."
      if [[ "${FORCE:-false}" != true ]]; then SCRIPT_TRAP_EXIT_CODE=1; notify_error "Cannot verify script integrity (hash unavailable) and --force not used. Aborting update."; fi
      log "Proceeding without hash verification due to --force flag."; VERIFIED=true
    fi
    if [[ "$VERIFIED" == true ]]; then
      if grep -q "^#!/bin/bash" "$TEMP_SCRIPT"; then
        log "Shebang validation passed."; log "Replacing current script at $SCRIPT_FILE"
        cp "$TEMP_SCRIPT" "$SCRIPT_FILE" && chmod +x "$SCRIPT_FILE"
        if [[ $? -eq 0 ]]; then
            log "Script updated successfully. Re-running...";
            # Clean up *before* exec, and remove trap for current process
            rm -f "$TEMP_SCRIPT" "$TEMP_HASH_FILE"
            # Remove from global cleanup array if you were using one for TEMP_FILES_TO_CLEAN
            # TEMP_FILES_TO_CLEAN=() 

            # --- BEGIN NEW DEBUG LINES ---
            log "DEBUG EXEC: Preparing to exec. Current script's SCRIPT_FILE is: [$SCRIPT_FILE]"
            log "DEBUG EXEC: Current script's arguments were (\$# is $#): [$(printf "'%s' " "$@")]"
            # --- END NEW DEBUG LINES ---

            trap - EXIT SIGINT SIGTERM # Disable trap for the current process before exec
            exec "$SCRIPT_FILE" "${ORIGINAL_ARGS[@]}"

        else
            SCRIPT_TRAP_EXIT_CODE=1; notify_error "Failed to copy updated script to $SCRIPT_FILE."
        fi
      else SCRIPT_TRAP_EXIT_CODE=1; notify_error "Downloaded script failed validation (missing shebang). Aborting update."; fi
    fi
  else log "Script is already up to date."; fi
else SCRIPT_TRAP_EXIT_CODE=1; notify_error "Failed to fetch script from $SCRIPT_URL. Check URL or connection."; 
fi
# If we didn't exec, remove temp files (trap will also try, but good to do it here)
rm -f "$TEMP_SCRIPT" "$TEMP_HASH_FILE"
# Remove from array if successfully cleaned
TEMP_FILES_TO_CLEAN=()


# === Log Rotation ===
log "\n=== Checking for Log Rotation (Retention: $RETENTION_DAYS days) ==="
log "Finding logs in '$LOG_DIR' older than $RETENTION_DAYS days..."
find "$LOG_DIR" -type f -name "update_*.log" -mtime "+$((RETENTION_DAYS - 1))" -print -exec rm {} \; 2>&1 | tee -a "$LOGFILE" || log "[Warning] Log rotation command encountered an issue."
log "Log rotation check complete."


# === Main Update Process ===
log "\n=== Starting Main Update Tasks for PRoot Distro: $(date) ==="
UPDATE_ERRORS=0 

# --- PRoot Distro Filesystem Check/Update (Non-Root) ---
if [[ -n "$PROOT_DISTRO" ]]; then
    log "\n=== Task: PRoot Distro Filesystem Check ($PROOT_DISTRO) ==="
    if ! command -v proot-distro &> /dev/null; then 
        log "[Skipped] 'proot-distro' command (Termux) not found."
    # WORKAROUND: Check if distro is accessible via login, as 'list' is unreliable on this system
    elif proot-distro login "$PROOT_DISTRO" -- true &>/dev/null; then
      log "Verified PRoot distro '$PROOT_DISTRO' is accessible (login test successful)."
      log "Running 'proot-distro upgrade $PROOT_DISTRO' (non-root, may have limited effect on OS packages)..."
      # This command might perform some filesystem checks or minor updates without root.
      if ! retry proot-distro upgrade "$PROOT_DISTRO"; then 
          log "[Warning] 'proot-distro upgrade $PROOT_DISTRO' encountered an issue. This is sometimes normal on non-rooted devices. Continuing to update packages inside the guest OS."
      else 
          log "'proot-distro upgrade $PROOT_DISTRO' completed."
      fi
    else 
      # This means proot-distro is installed, but the specified PROOT_DISTRO is not login-able.
      SCRIPT_TRAP_EXIT_CODE=1; notify_error "Specified PRoot distro '$PROOT_DISTRO' is not accessible via login. Please ensure it is correctly installed and usable (e.g., try 'proot-distro login $PROOT_DISTRO' manually)." || ((UPDATE_ERRORS++))
    fi
# ... (rest of the script, including the "else" for the "if [[ -n "$PROOT_DISTRO" ]]" part)

else 
    log "\n=== Task: PRoot Distro Filesystem Check [Skipped] (No distro specified) ==="
fi

# --- PRoot Guest OS Package Update Task ---
if [[ -n "$PROOT_DISTRO" && $UPDATE_ERRORS -eq 0 ]]; then
    log "\n=== Task: PRoot Guest OS Package Update (inside $PROOT_DISTRO) ==="
    # Note: `sudo` inside the proot is fine if your proot user has sudo rights *within that guest environment*,
    # or if the default proot user (often root) doesn't strictly need sudo for apt.
    # For wide compatibility, keeping sudo. User can remove if their proot user is root.
    read -r -d '' GUEST_OS_UPDATE_CMDS <<EOF
set -euo pipefail
echo "[INFO] Updating package lists inside $PROOT_DISTRO..."
if command -v sudo &> /dev/null; then SUDO_CMD="sudo"; else SUDO_CMD=""; fi
\$SUDO_CMD apt update -y
echo "[INFO] Upgrading packages inside $PROOT_DISTRO..."
\$SUDO_CMD apt full-upgrade -y
echo "[INFO] Removing unused packages inside $PROOT_DISTRO..."
\$SUDO_CMD apt autoremove -y
echo "[INFO] PRoot Guest OS package update sequence completed."
EOF
    log "Executing Guest OS package updates inside $PROOT_DISTRO..."
    if ! proot-distro login "$PROOT_DISTRO" -- bash -c "$GUEST_OS_UPDATE_CMDS" 2>&1 | tee -a "$LOGFILE"; then
        notify_error "PRoot Guest OS package update failed for '$PROOT_DISTRO'." || ((UPDATE_ERRORS++))
    else log "PRoot Guest OS package update for '$PROOT_DISTRO' completed successfully."; fi
else
    if [[ -n "$PROOT_DISTRO" ]]; then log "\n=== Task: PRoot Guest OS Package Update [Skipped due to previous errors or missing distro] ==="; fi
fi

# --- Git Repository Update Task (inside PRoot Distro) ---
if [[ -n "$PROOT_DISTRO" && $UPDATE_ERRORS -eq 0 ]]; then
    log "\n=== Task: Git Repository Update (inside $PROOT_DISTRO: $REPO_DIR) ==="
    read -r -d '' GIT_PULL_COMMAND <<EOF
set -euo pipefail
# Expand ~ to user's home directory inside proot if REPO_DIR starts with ~/
actual_repo_dir="\$HOME/\${REPO_DIR#\~\/}"
if [[ "\$REPO_DIR" != "~/"* ]]; then # If it doesn't start with ~/, use as is
    actual_repo_dir="\$REPO_DIR"
fi
echo "[INFO] Target Git repository path inside PRoot: \$actual_repo_dir"
if [ ! -d "\$actual_repo_dir" ]; then echo "[ERROR] Repository directory '\$actual_repo_dir' does not exist inside $PROOT_DISTRO."; exit 1; fi
if [ ! -d "\$actual_repo_dir/.git" ]; then echo "[ERROR] No git repository found at '\$actual_repo_dir' inside $PROOT_DISTRO."; exit 1; fi
echo "[INFO] Changing to \$actual_repo_dir and pulling from $GIT_REMOTE $GIT_BRANCH..."
cd "\$actual_repo_dir"
git pull "$GIT_REMOTE" "$GIT_BRANCH"
echo "[INFO] Git pull complete for \$actual_repo_dir. Current status (short):"; git status -s
EOF
    log "Executing Git pull inside $PROOT_DISTRO for repository $REPO_DIR..."
    # Bind /dev/urandom for git operations that might need entropy
    if ! proot-distro login "$PROOT_DISTRO" --bind /dev/urandom:/dev/random --bash -c "$GIT_PULL_COMMAND" 2>&1 | tee -a "$LOGFILE"; then
        notify_error "Git pull failed in $PROOT_DISTRO at $REPO_DIR. Check log." || ((UPDATE_ERRORS++))
    else log "Git repository update in $PROOT_DISTRO at $REPO_DIR successful."; fi
else
    if [[ -n "$PROOT_DISTRO" ]]; then log "\n=== Task: Git Repository Update [Skipped due to previous errors or missing distro] ==="; fi
fi

# --- Python Virtual Environment Update Task (inside PRoot Distro) ---
if [[ -n "$PROOT_DISTRO" && $UPDATE_ERRORS -eq 0 ]]; then
    log "\n=== Task: Python Virtualenv Update (inside $PROOT_DISTRO: $VENV_DIR) ==="
    # VENV_DIR is the name of the venv dir, usually inside the user's home in proot
    # Let's assume user's home dir is /root or $HOME if not root (e.g. /home/user)
    read -r -d '' PY_UPDATE_COMMANDS <<EOF
export PATH="\$HOME/.local/bin:\$PATH" 
set -euo pipefail
# Construct VENV_PATH based on whether VENV_DIR is absolute or relative
if [[ "$VENV_DIR" == /* ]]; then # Absolute path
    VENV_PATH_INSIDE_PROOT="$VENV_DIR"
else # Relative to home
    VENV_PATH_INSIDE_PROOT="\$HOME/$VENV_DIR"
fi
echo "[INFO] Target Python virtualenv path inside PRoot: \$VENV_PATH_INSIDE_PROOT"
VENV_ACTIVATE="\$VENV_PATH_INSIDE_PROOT/bin/activate"
echo "[INFO] Checking for virtual environment at \$VENV_PATH_INSIDE_PROOT..."
if [ ! -f "\$VENV_ACTIVATE" ]; then echo "[ERROR] Virtualenv activation script not found: \$VENV_ACTIVATE." >&2; exit 1; fi
echo "[INFO] Activating virtualenv: \$VENV_PATH_INSIDE_PROOT"; source "\$VENV_ACTIVATE"
echo "[INFO] Upgrading pip, setuptools, wheel in \$VENV_PATH_INSIDE_PROOT..."
if ! pip install --no-cache-dir --upgrade pip setuptools wheel; then echo "[ERROR] Failed to upgrade pip/setuptools/wheel." >&2; exit 1; fi
echo "[INFO] Checking for outdated packages in \$VENV_PATH_INSIDE_PROOT..."
outdated_packages=\$(pip list --outdated --format=freeze 2>/dev/null | cut -d '=' -f1 | tr '\n' ' ')
outdated_packages=\$(echo \$outdated_packages | xargs) 
if [ -n "\$outdated_packages" ]; then
    echo "[INFO] Found outdated packages: \$outdated_packages"; echo "[INFO] Attempting to upgrade..."
    if ! pip install --no-cache-dir -U \$outdated_packages; then echo "[ERROR] Failed to upgrade some packages." >&2; exit 1; fi
    echo "[INFO] Outdated packages upgrade attempt finished."
else echo "[INFO] All pip packages in \$VENV_PATH_INSIDE_PROOT are up to date."; fi
echo "[INFO] Python virtualenv update in \$VENV_PATH_INSIDE_PROOT completed successfully."
exit 0 
EOF
    log "Executing Python virtualenv updates inside $PROOT_DISTRO..."
    if ! proot-distro login "$PROOT_DISTRO" --bash -c "$PY_UPDATE_COMMANDS" 2>&1 | tee -a "$LOGFILE"; then
        notify_error "Python virtualenv update within $PROOT_DISTRO for $VENV_DIR failed. Check log." || ((UPDATE_ERRORS++))
    else log "Python virtualenv update within $PROOT_DISTRO for $VENV_DIR completed successfully."; fi
else
    if [[ -n "$PROOT_DISTRO" ]]; then log "\n=== Task: Python Virtualenv Update [Skipped due to previous errors or missing distro] ==="; fi
fi

# === Summary ===
log "\n=== Update Script Summary ==="
if (( UPDATE_ERRORS > 0 )); then
  final_message="Process completed with $UPDATE_ERRORS error(s). Please check log: $LOGFILE"
  log "[FAILURE] $final_message"; send_notification "[Update Failed] $final_message on $(hostname)"
else
  final_message="All tasks completed successfully."
  log "[SUCCESS] $final_message"; send_notification "[Update Success] $final_message on $(hostname)"
fi
log "\n=== Full Update Script Finished for NON-ROOTED device: $(date) ==="
SCRIPT_TRAP_EXIT_CODE=0 # Indicate normal exit
trap - EXIT SIGINT SIGTERM # Cleanly remove trap for normal exit
exit $UPDATE_ERRORS
