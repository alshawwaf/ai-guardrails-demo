#!/usr/bin/env bash
# AI Guard Demo Kit: one-shot lab installer for a Linux host behind a Check Point gateway.
#
#   bash aiguard-lab-install.sh --mgmt 10.1.1.100
#
# Everything is automatic by default:
#   1. unpacks the kit (from this self-extracting file, or uses the repo it sits in)
#   2. finds the gateway's HTTPS Inspection outbound CA and trusts it on this host:
#      already trusted here, or sent by the gateway, or (with --mgmt) read from the
#      management server through the Management API; its fingerprints are printed
#   3. installs Docker if missing and makes it trust the CA. It never restarts a
#      Docker daemon that is already in use (that restarts every container on the
#      host) unless you pass --restart-docker: the CA goes to /etc/docker/certs.d,
#      which Docker reads on every pull, and a pull of the base image checks it
#   4. writes .env (admin sign-in, app keys, management defaults) if missing
#   5. checks the management server: certificate, name/IP match, API access
#   6. builds the image (the CA goes into the image trust store) and starts it
#   7. checks the container sees inspected TLS to the AI providers
#   8. prints the URL, the admin sign-in, and what is left to do
#   9. in a terminal: runs the guided setup (aiguard setup: you type the Guard API key
#      and project ID, then APPROVE) and the guided demo in the container
# The Management API key is asked once (hidden), when the CA has to be read from the
# management server or for the guided setup; it stays in memory only: never stored,
# logged or put on a command line (the container gets it as an environment variable).
#
# Options (all optional):
#   --mgmt HOST            management server (SMS/MDS) address, e.g. 10.1.1.100
#   --mgmt-port N          management web API port (default 443)
#   --mgmt-name NAME       name to verify the management certificate against
#   --mgmt-type SMS|MDS    server type (default SMS)
#   --domain NAME          MDS domain
#   --gateway NAME         gateway object to pre-select (e.g. GW; found through the
#                          Management API when the installer used it)
#   --ca FILE              outbound CA (PEM or DER) to trust instead of auto-detecting
#   --dir DIR              install folder (default ~/ai-guardrails-demo)
#   --port N               web console port (default 9000)
#   --admin-email EMAIL    sign-in e-mail (default admin@aiguard.lab)
#   --project-id ID        AI Guardrails project ID for the guided setup (else asked)
#   --no-setup             stop after the install: no guided setup and demo here
#                          (also skipped when this is not run from a terminal)
#   --restart-docker       allow restarting Docker, and with it every running
#                          container, if Docker cannot verify the registry's TLS
#                          without a restart (default: stop and say so)
#   --skip-build           prepare everything but do not build/start the container
#   --skip-docker          do not install or touch Docker (implies --skip-build)
#   --uninstall            stop and remove the container and image (keeps data)
#   -h, --help             this help
# Environment: AIGUARD_MGMT_API_KEY_ENV=NAME reads the Management API key from the
# environment variable NAME instead of asking (for runs without a terminal).
# Tests and special labs: AIGUARD_PROBE_HOSTS="host[:port] ..." overrides the hosts
# used to detect the outbound CA.
case "$(head -c 4096 -- "$0" 2>/dev/null || true)" in *$'\r'*) printf '%s\n' "This file has Windows (CRLF) line endings, so bash cannot run it." "Fix: sed -i 's/\r\$//' \"$0\"   then run it again (next time copy it in binary mode: scp/SFTP)." >&2; exit 2 ;; esac # CRLF guard: this line ends in a comment so it still parses with CRLF
set -Eeuo pipefail

PAYLOAD_MARKER="__AIGUARD_PAYLOAD_BELOW__"
ORIG_PWD="$PWD"
ORIG_ARGS=("$@")
DIR="${HOME}/ai-guardrails-demo" DIR_OPT=""
APP_PORT_OPT=""
ADMIN_EMAIL="admin@aiguard.lab"
MGMT="" MGMT_PORT="443" MGMT_NAME="" MGMT_TYPE="" DOMAIN="" GATEWAY="" CA_OPT=""
SKIP_BUILD=0 SKIP_DOCKER=0 UNINSTALL=0 RESTART_DOCKER=0 NO_SETUP=0 PROJECT_ID=""
PROBE_HOSTS="${AIGUARD_PROBE_HOSTS:-api.openai.com api.anthropic.com pypi.org download.pytorch.org registry-1.docker.io}"
PUBLIC_CA_RE='(google trust services|digicert|let.s encrypt|isrg|sectigo|comodo|usertrust|globalsign|amazon|microsoft|entrust|godaddy|starfield|baltimore|identrust|cloudflare|certainly|buypass|actalis|ssl\.com|harica|certum|quovadis|swisssign|telia|wisekey|trustwave|secom|t-systems|d-trust|geotrust|thawte|rapidssl|zerossl|apple|cisco)'
# registries Docker gets the CA for in /etc/docker/certs.d/<registry>/ (read on every pull)
DOCKER_REGISTRIES="registry-1.docker.io docker.io index.docker.io auth.docker.io production.cloudflare.docker.com ghcr.io"

# the comment block at the top of this file, up to the first command
usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }
bad_usage() { echo "$1 (see --help)" >&2; exit 2; }
need_val() {  # need_val OPTION "$@": the option must be followed by a value
  if [ $# -lt 2 ] || [ -z "$2" ]; then bad_usage "Option $1 needs a value"; fi
  case "$2" in --*) bad_usage "Option $1 needs a value (got $2)" ;; esac
}
while [ $# -gt 0 ]; do
  case "$1" in
    --mgmt) need_val "$@"; MGMT="$2"; shift 2 ;;
    --mgmt-port) need_val "$@"; MGMT_PORT="$2"; shift 2 ;;
    --mgmt-name) need_val "$@"; MGMT_NAME="$2"; shift 2 ;;
    --mgmt-type) need_val "$@"; MGMT_TYPE="$(printf '%s' "$2" | tr '[:lower:]' '[:upper:]')"; shift 2 ;;
    --domain) need_val "$@"; DOMAIN="$2"; shift 2 ;;
    --gateway) need_val "$@"; GATEWAY="$2"; shift 2 ;;
    --ca) need_val "$@"; CA_OPT="$2"; shift 2 ;;
    --dir) need_val "$@"; DIR_OPT="$2"; shift 2 ;;
    --port) need_val "$@"; APP_PORT_OPT="$2"; shift 2 ;;
    --admin-email) need_val "$@"; ADMIN_EMAIL="$2"; shift 2 ;;
    --project-id) need_val "$@"; PROJECT_ID="$2"; shift 2 ;;
    --no-setup) NO_SETUP=1; shift ;;
    --restart-docker) RESTART_DOCKER=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --skip-docker) SKIP_DOCKER=1; SKIP_BUILD=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) bad_usage "Unknown option: $1" ;;
  esac
done

is_port() { case "$1" in ''|*[!0-9]*|??????*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
is_host() { case "$1" in ''|*[!A-Za-z0-9._:-]*) return 1 ;; esac; }
abspath() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$ORIG_PWD" "$1" ;; esac; }
is_port "$MGMT_PORT" || bad_usage "--mgmt-port must be a port number (1-65535)"
[ -z "$APP_PORT_OPT" ] || is_port "$APP_PORT_OPT" || bad_usage "--port must be a port number (1-65535)"
[ -z "$MGMT" ] || is_host "$MGMT" || bad_usage "--mgmt must be an IP address or host name"
[ -z "$MGMT_NAME" ] || is_host "$MGMT_NAME" || bad_usage "--mgmt-name must be a host name"
case "$MGMT_TYPE" in ""|SMS|MDS) ;; *) bad_usage "--mgmt-type must be SMS or MDS" ;; esac
case "$DOMAIN" in *[\"\\]*|*[[:cntrl:]]*) bad_usage "--domain must not contain quotes, backslashes or control characters" ;; esac
case "$PROJECT_ID" in *[!A-Za-z0-9._-]*) bad_usage "--project-id takes letters, digits, '.', '_' and '-' only" ;; esac
# step 9 (guided setup and demo in the container) needs a terminal and the container
SETUP=0; if [ "$NO_SETUP" = 0 ] && [ "$SKIP_BUILD" = 0 ] && [ -t 0 ]; then SETUP=1; fi
# relative paths are relative to where the installer was started (it changes folder later)
[ -z "$CA_OPT" ] || CA_OPT="$(abspath "$CA_OPT")"
[ -z "$DIR_OPT" ] || DIR="$(abspath "$DIR_OPT")"
while [ "$DIR" != "/" ] && [ "${DIR%/}" != "$DIR" ]; do DIR="${DIR%/}"; done
read -r -a PROBE_LIST <<<"$PROBE_HOSTS" || true

TS="$(date +%Y%m%d-%H%M%S)"
LOG="${HOME}/aiguard-install-${TS}.log"
(umask 077; : >>"$LOG")
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
WORK="$(mktemp -d)"
API="$WORK/api"   # Management API session files (mode 0600 in this 0700 folder)
exec 3>&1 4>&2
exec > >(tee -a "$LOG") 2>&1
TEE_PID=$!
finish() {  # end an open API session, remove the scratch folder; let tee write the last lines before the shell exits
  local rc=$?
  if [ -s "$API/sid.hdr" ]; then api_logout >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
  exec 1>&3 2>&4
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$TEE_PID" 2>/dev/null || break; sleep 0.2; done
  exit "$rc"
}
trap finish EXIT
trap 'echo; echo "FAILED at line $LINENO: $BASH_COMMAND"; echo "Full log: $LOG"' ERR

say()  { printf '\n\033[1;35m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mOK\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m  %s\n' "$*"; }
die()  { printf '\n\033[31mSTOPPED:\033[0m %s\n' "$1"; shift; for l in "$@"; do printf '    %s\n' "$l"; done; printf '    Log: %s\n' "$LOG"; exit 1; }
SUDO=""; if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi
is_kit() { [ -f "$1/app.py" ] && [ -f "$1/aiguard/__init__.py" ] && [ -f "$1/scripts/lab_run_web.sh" ]; }
rerun_cmd() {  # rerun_cmd [EXTRA]: the command that started this installer, plus EXTRA (printed as is)
  local q
  printf -v q '%q ' bash "$0" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"}
  q="${q% }"
  if [ -n "${1:-}" ]; then q="$q $1"; fi
  printf '%s' "$q"
}

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
  say "Removing the container and image (data in $DIR is kept)"
  if ! command -v docker >/dev/null 2>&1; then
    warn "Docker is not installed: no container or image to remove"
  else
    if $SUDO docker rm -f aiguard-web >/dev/null 2>&1; then ok "container removed"; else warn "no container"; fi
    if $SUDO docker rmi aiguard-web:lab >/dev/null 2>&1; then ok "image removed"; else warn "no image"; fi
  fi
  echo "    The outbound CA stays trusted on this host (/usr/local/share/ca-certificates/aiguard-outbound-ca-*.crt,"
  echo "    and for Docker /etc/docker/certs.d/*/aiguard-outbound-ca.crt)."
  echo "    To remove it too: sudo rm /usr/local/share/ca-certificates/aiguard-outbound-ca-*.crt && sudo update-ca-certificates --fresh"
  echo "                      sudo rm -f /etc/docker/certs.d/*/aiguard-outbound-ca.crt"
  exit 0
fi

# ---------------------------------------------------------------- 0. host basics
say "Checking this host"
[ "$(uname -s)" = "Linux" ] || die "This installer is for Linux hosts." "On Windows/macOS use the CLI: python -m aiguard setup"
command -v apt-get >/dev/null || die "apt-get not found." "This installer supports Ubuntu/Debian. Install Docker, curl and openssl yourself, then rerun."
PAYLOAD_LINE="$(awk -v m="$PAYLOAD_MARKER" '$0 == m { print NR; exit }' "$SELF" 2>/dev/null || true)"
if [ -n "$PAYLOAD_LINE" ]; then
  # the kit replaces $DIR on an update: never a home folder, or a folder that is not a kit
  if [ "$DIR" = "/" ] || [ "$DIR" = "${HOME%/}" ]; then
    die "--dir $DIR is not allowed (the kit folder is replaced on every update)." "Use a folder of its own, e.g. --dir $HOME/ai-guardrails-demo"
  fi
  if [ -e "$DIR" ] && { [ ! -d "$DIR" ] || { [ -n "$(ls -A "$DIR" 2>/dev/null)" ] && ! is_kit "$DIR"; }; }; then
    die "$DIR exists and is not an AI Guard Demo Kit folder, so it is not replaced." \
        "Use --dir with a new or empty folder, or the folder of an earlier install."
  fi
fi
if [ -n "$SUDO" ]; then
  echo "    sudo is needed for: CA trust store, Docker install, docker commands."
  sudo -v || die "sudo failed." "Run as a user with sudo rights."
fi
NEED=""
for t in curl openssl tar base64 awk timeout; do command -v "$t" >/dev/null || NEED="$NEED $t"; done
[ -x /usr/sbin/update-ca-certificates ] || command -v update-ca-certificates >/dev/null || NEED="$NEED update-ca-certificates"
if [ -n "$NEED" ]; then
  echo "    installing:$NEED"
  { $SUDO apt-get update -qq && $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl openssl ca-certificates tar coreutils gawk; } >"$WORK/apt.log" 2>&1 \
    || die "Could not install:$NEED (apt-get)." "$(tail -n 3 "$WORK/apt.log")" "Fix apt (sources, proxy), or install them yourself, then rerun."
fi
ok "$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Linux}") || echo Linux) · $(uname -m) · user $(id -un)"
HOST_IP="$({ ip route get 1.1.1.1 2>/dev/null || true; } | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
[ -n "$HOST_IP" ] || HOST_IP="$({ hostname -I 2>/dev/null || true; } | awk '{print $1}')"
ok "this host's address towards the internet: ${HOST_IP:-unknown}"

# helpers for certificates; they print nothing (and never fail) when a file is not a certificate
subj()   { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//' || true; }
iss()    { openssl x509 -in "$1" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//' || true; }
fp()     { openssl x509 -in "$1" -noout -fingerprint "-$2" 2>/dev/null | cut -d= -f2 || true; }
cn_of()  { printf '%s\n' "$1" | awk -F, '{for(i=1;i<=NF;i++) if($i ~ /^CN=/){print substr($i,4); exit}}'; }
is_ca_selfsigned() { local s; s="$(subj "$1")"; [ -n "$s" ] && [ "$s" = "$(iss "$1")" ]; }
is_ca_cert() { is_ca_selfsigned "$1" || [[ "$(openssl x509 -in "$1" -noout -ext basicConstraints 2>/dev/null || true)" == *CA:TRUE* ]]; }
public_issuer() { grep -Eq "$PUBLIC_CA_RE" <<<"$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"; }
# split_chain FILE DIR: each certificate in FILE to DIR/cN.pem. CRs, spaces, blank lines and text
# around the markers (a PEM pasted into a terminal) are dropped, so openssl can read it.
split_chain() {
  awk -v d="$2" '{ gsub(/\r/, ""); sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "") }
    /-----BEGIN CERTIFICATE-----/ { sub(/^.*-----BEGIN CERTIFICATE-----/, "-----BEGIN CERTIFICATE-----"); n++; inb = 1 }
    /-----END CERTIFICATE-----/ { sub(/-----END CERTIFICATE-----.*$/, "-----END CERTIFICATE-----") }
    inb && $0 != "" { print > (d "/c" n ".pem") }
    /-----END CERTIFICATE-----/ { inb = 0 }' "$1"
}
verifies() {  # verifies ANCHOR LEAF [MORE_CERTS]: ANCHOR (and only ANCHOR) validates the presented chain
  local extra=()
  if [ -n "${3:-}" ] && [ -s "$3" ]; then extra=(-untrusted "$3"); fi
  openssl verify -no_check_time -trusted "$1" ${extra[@]+"${extra[@]}"} "$2" >/dev/null 2>&1
}
verifies_partial() {  # like verifies, but ANCHOR may be an intermediate CA (curl and Go accept that, Python does not)
  local extra=()
  if [ -n "${3:-}" ] && [ -s "$3" ]; then extra=(-untrusted "$3"); fi
  openssl verify -no_check_time -partial_chain -trusted "$1" ${extra[@]+"${extra[@]}"} "$2" >/dev/null 2>&1
}
find_in_store() {  # find_in_store ISSUER_DN LEAF CHAIN -> a system store certificate with that name that validates the chain
  local f
  for f in /etc/ssl/certs/*.pem /usr/local/share/ca-certificates/*.crt; do
    [ -f "$f" ] || continue
    if [ "$(subj "$f")" = "$1" ] && verifies "$f" "$2" "$3"; then printf '%s\n' "$f"; return 0; fi
  done
  return 1
}

declare -a ANCHORS=()   # normalized PEM copies in $WORK, one per distinct certificate
add_anchor() {  # add_anchor FILE
  local s a out
  s="$(fp "$1" sha256)"; [ -n "$s" ] || return 0
  for a in ${ANCHORS[@]+"${ANCHORS[@]}"}; do [ "$(fp "$a" sha256)" != "$s" ] || return 0; done
  out="$WORK/anchor-$((${#ANCHORS[@]} + 1)).pem"
  openssl x509 -in "$1" -out "$out" 2>/dev/null || return 0
  ANCHORS+=("$out")
}

# --ca is checked before anything is changed
if [ -n "$CA_OPT" ]; then
  [ -f "$CA_OPT" ] || die "--ca $CA_OPT not found."
  if grep -q "PRIVATE KEY" "$CA_OPT"; then die "--ca $CA_OPT contains a private key. Use the public certificate only."; fi
  mkdir -p "$WORK/ca-opt"
  if grep -q "BEGIN CERTIFICATE" "$CA_OPT"; then
    split_chain "$CA_OPT" "$WORK/ca-opt"
  else
    openssl x509 -inform DER -in "$CA_OPT" -out "$WORK/ca-opt/c1.pem" 2>/dev/null || true
  fi
  for c in "$WORK"/ca-opt/c*.pem; do if [ -f "$c" ] && is_ca_cert "$c"; then add_anchor "$c"; fi; done
  [ "${#ANCHORS[@]}" -gt 0 ] || die "--ca $CA_OPT holds no CA certificate (PEM or DER)." "Export the gateway's outbound CA itself (Trusted Root store on win_client), not a server certificate."
fi

# ---------------------------------------------------------------- 1. unpack
say "Unpacking the kit into $DIR"
UPDATED=0
if [ -n "$PAYLOAD_LINE" ]; then
  mkdir -p "$WORK/src"
  SRC="$WORK/src/ai-guardrails-demo"
  if ! tail -n +"$((PAYLOAD_LINE + 1))" "$SELF" | base64 -d 2>"$WORK/unpack.err" \
       | tar xz --no-same-owner --no-same-permissions -C "$WORK/src" 2>>"$WORK/unpack.err" \
     || [ ! -f "$SRC/app.py" ]; then
    die "The embedded kit is damaged." "Copy aiguard-lab-install.sh again in binary mode (SFTP/scp, not copy-paste)."
  fi
  if [ -d "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
    BAK="${DIR}.bak-${TS}"; if [ -e "$BAK" ]; then BAK="${BAK}-$$"; fi
    cp -a "$DIR" "$BAK"
    # keep this host's settings, data and CA files; replace the code
    for keep in .env instance logs; do if [ -e "$DIR/$keep" ]; then cp -a "$DIR/$keep" "$SRC/"; fi; done
    for crt in "$DIR"/certs/*.crt; do if [ -f "$crt" ]; then cp -a "$crt" "$SRC/certs/"; fi; done
    rm -rf "$DIR"
    ok "updated (previous copy kept in $BAK)"
    UPDATED=1
  fi
  mkdir -p "$(dirname "$DIR")"
  if [ -d "$DIR" ]; then rmdir "$DIR"; fi   # an empty folder given with --dir
  mv "$SRC" "$DIR"
  ok "kit $(grep -m1 -o '__version__ = "[^"]*"' "$DIR/aiguard/__init__.py" 2>/dev/null | cut -d'"' -f2 || true) in $DIR"
else
  REPO="$(cd "$(dirname "$SELF")/.." && pwd)"
  [ -f "$REPO/app.py" ] || die "No embedded kit and no repository next to this script." "Use the aiguard-lab-install.sh file, or run scripts/lab_install.sh from the repository."
  if [ -n "$DIR_OPT" ] && [ "$DIR" != "$REPO" ]; then warn "--dir is ignored when running from the repository"; fi
  DIR="$REPO"; UPDATED=1
  ok "using the repository at $DIR"
fi
cd "$DIR"
mkdir -p certs instance/aiguard logs data

# ---------------------------------------------------------------- management server (steps 2 and 5)
MGMT_PROBED=0 MGMT_TLS=0 MGMT_CERT_PROBLEM=1 MGMT_NAME_OK="" MGMT_VNAME="" MGMT_SHA1="" MGMT_API=""
# mgmt_probe: certificate, the name that verifies, API access. Writes instance/aiguard/mgmt-ca.pem,
# not .env (step 5 does that with mgmt_record), so it can run before .env exists.
mgmt_probe() {
  local m="$WORK/mgmt" leaf msubj mcn msan top c is_ip dns body code sni=()
  MGMT_PROBED=1
  mkdir -p "$m"
  if [ -n "$MGMT_NAME" ]; then sni=(-servername "$MGMT_NAME"); fi
  timeout 15 openssl s_client -connect "$MGMT:$MGMT_PORT" ${sni[@]+"${sni[@]}"} -showcerts </dev/null >"$m/raw" 2>/dev/null || true
  if grep -q "BEGIN CERTIFICATE" "$m/raw"; then split_chain "$m/raw" "$m"; fi
  if [ ! -f "$m/c1.pem" ]; then
    warn "no TLS answer from $MGMT:$MGMT_PORT (route, firewall, or the Gaia portal is on another port)"
    MGMT_API=000
    return 0
  fi
  MGMT_TLS=1
  leaf="$m/c1.pem"; cat "$m"/c*.pem >"$m/presented.pem"
  msubj="$(subj "$leaf")"; mcn="$(cn_of "$msubj")"
  msan="$(openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ' || true)"
  MGMT_SHA1="$(fp "$leaf" sha1)"
  echo "    certificate: $msubj"
  echo "    SAN:         ${msan:-none}"
  echo "    SHA-1:       $MGMT_SHA1   (compare on the SMS: api fingerprint)"
  # trust anchor for the management connection, checked the way the web console (Python) does,
  # without partial chains: a root that validates the leaf (sent by the server, or saved here
  # earlier), else the leaf itself (enough when it is self-signed)
  top=""
  for c in "$m"/c*.pem; do
    if [ "$c" != "$leaf" ] && is_ca_selfsigned "$c" && verifies "$c" "$leaf" "$m/presented.pem"; then top="$c"; fi
  done
  if [ -z "$top" ] && [ -s instance/aiguard/mgmt-ca.pem ] && verifies instance/aiguard/mgmt-ca.pem "$leaf" "$m/presented.pem"; then
    top="instance/aiguard/mgmt-ca.pem"; ok "keeping instance/aiguard/mgmt-ca.pem ($(subj "$top"))"
  fi
  if [ -z "$top" ]; then
    top="$leaf"
    if ! is_ca_selfsigned "$leaf"; then
      warn "the server sent only its own certificate, signed by \"$(iss "$leaf")\", which it did not send."
      warn "curl accepts that, the web console does not: save that CA certificate (PEM) as $DIR/instance/aiguard/mgmt-ca.pem, then rerun this installer."
    fi
  fi
  if [ "$top" != "instance/aiguard/mgmt-ca.pem" ]; then cp "$top" instance/aiguard/mgmt-ca.pem; fi
  chmod 644 instance/aiguard/mgmt-ca.pem
  # which name will verify?
  is_ip=0; if grep -Eq '^[0-9]+(\.[0-9]+){3}$' <<<"$MGMT"; then is_ip=1; fi
  if [ -n "$MGMT_NAME" ]; then MGMT_NAME_OK="$MGMT_NAME"
  elif [ "$is_ip" = 1 ] && grep -qxF "IPAddress:$MGMT" <<<"${msan//,/$'\n'}"; then MGMT_NAME_OK="(IP in SAN)"
  elif [ "$is_ip" = 0 ] && grep -qiF "$MGMT" <<<"$msan$mcn"; then MGMT_NAME_OK="(name in certificate)"
  else
    dns="$(sed -n 's/^DNS://p' <<<"${msan//,/$'\n'}" | awk 'NR == 1')"
    if [ -z "$dns" ] && [ -n "$mcn" ] && ! grep -Eq '^[0-9.]+$' <<<"$mcn"; then dns="$mcn"; fi
    MGMT_NAME_OK="$dns"
  fi
  MGMT_CERT_PROBLEM=0
  case "$MGMT_NAME_OK" in
    "") if [ -n "$msan" ]; then warn "the certificate does not name $MGMT (SAN: $msan): it cannot be verified when connecting by IP."
        else warn "the certificate names only \"$mcn\" with no SAN: it cannot be verified when connecting by IP."; fi
        warn "Fix on the management server: ICA-signed Gaia portal certificate with SAN IP $MGMT (sk164382), then rerun this installer."
        MGMT_CERT_PROBLEM=1 ;;
    "("*) ok "certificate matches $MGMT $MGMT_NAME_OK" ;;
    *) ok "will verify the certificate as \"$MGMT_NAME_OK\" while connecting to $MGMT" ;;
  esac
  [ "$MGMT_CERT_PROBLEM" = 0 ] || return 0
  MGMT_VNAME="$MGMT"; case "$MGMT_NAME_OK" in "("*) ;; *) MGMT_VNAME="$MGMT_NAME_OK" ;; esac
  body="$(curl -sS --max-time 15 --cacert instance/aiguard/mgmt-ca.pem --connect-to "$MGMT_VNAME:$MGMT_PORT:$MGMT:$MGMT_PORT" \
          -H 'Content-Type: application/json' -d '{}' -w '\n%{http_code}' "https://$MGMT_VNAME:$MGMT_PORT/web_api/login" 2>"$WORK/m.err" || true)"
  code="${body##*$'\n'}"
  MGMT_API="${code:-000}"
  case "$code" in
    400|401) ok "Management API answers and accepts calls from this host (HTTP $code to an empty login)";;
    403) if grep -qiE "permission to access|forbidden" <<<"$body"; then
           MGMT_API=refused
           warn "Management API refuses this host (HTTP 403)."
           warn "SmartConsole > Manage & Settings > Blades > Management API > Advanced Settings > Accept API calls from: All IP addresses that can be used for GUI clients; publish; on the SMS: api restart"
         else ok "Management API answers (HTTP 403 to an empty login)"; fi ;;
    000|"") warn "could not verify/reach the API: $(tr '\n' ' ' < "$WORK/m.err" | cut -c1-200)";;
    *) warn "Management API answered HTTP $code";;
  esac
}
mgmt_record() {  # step 5: the management settings in .env
  set_env AIGUARD_MGMT_SERVER "$MGMT"; set_env AIGUARD_MGMT_PORT "$MGMT_PORT"
  [ "$MGMT_TLS" = 1 ] || return 0
  set_env AIGUARD_MGMT_CA_FILE /app/instance/aiguard/mgmt-ca.pem
  set_env AIGUARD_MGMT_FINGERPRINT_SHA1 "$MGMT_SHA1"
  case "$MGMT_NAME_OK" in ""|"("*) unset_env AIGUARD_MGMT_SERVER_NAME ;; *) set_env AIGUARD_MGMT_SERVER_NAME "$MGMT_NAME_OK" ;; esac
}

# Management API session. Request bodies reach curl on its stdin (printf is a shell builtin) and
# replies go through a pipe straight into JSON_AWK, which prints only the fields asked for. So the
# API key, the session id and the replies are never on a command line, in the log or on stdout,
# and no reply is written to disk: certificate replies also hold the outbound CA's PKCS#12 with
# its private key (base64-certificate), which is never kept. The session id is only in
# $API/sid.hdr (mode 0600, in the 0700 work folder), sent with curl -H @file.
#
# JSON_AWK: a JSON reader in POSIX awk (mawk, gawk, busybox), so neither jq nor python3 is needed.
# Input: the reply, then a last line with the HTTP code (curl -w). Output: "HTTP <code>", then
# what -v mode asks for: sid (writes the header file named by arg), uids, cert (writes arg.pem,
# or arg.b64 for base64 that is not PEM text, plus a meta line), gateways; "err" for an error reply.
# JSON strings never span lines, so each line is split at its quotes and parsed on its own.
JSON_AWK='
function odd_bs(t,   l, n) { l = length(t); n = 0; while (n < l && substr(t, l - n, 1) == "\\") n++; return n % 2 }
function hexv(h,   i, v) { v = 0; h = tolower(h); for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1; return v }
function unesc(t,   out, i, c, h) {
  out = ""
  while ((i = index(t, "\\")) > 0) {
    out = out substr(t, 1, i - 1); c = substr(t, i + 1, 1)
    if (c == "u") {
      h = substr(t, i + 2, 4)
      if (h ~ /^00[2-7][0-9A-Fa-f]$/) { out = out sprintf("%c", hexv(h)) } else { out = out "?" }
      t = substr(t, i + 6); continue
    }
    if (c == "n") { out = out "\n" } else if (c == "r") { out = out "\r" } else if (c == "t") { out = out "\t" }
    else if (c != "b" && c != "f") { out = out c }
    t = substr(t, i + 2)
  }
  return out t
}
function clean(t) { gsub(/[\t\r\n]+/, " ", t); t = substr(t, 1, 160); return (t == "") ? "-" : t }
function emit(s) { OUT[++NO] = s }
function inobj() { return depth >= 3 && typ[1] == "{" && key[1] == "objects" && typ[2] == "[" }
function opened() { if (depth == 3 && typ[3] == "{" && inobj()) { OUID = ""; OTYPE = ""; ONAME = ""; OMATCH = 0 } }
function closed() {
  if (depth == 3 && typ[3] == "{" && inobj()) {
    if (mode == "uids" && OUID != "") emit("uid\t" OUID)
    if (mode == "gateways" && ONAME != "" && (OTYPE == "simple-gateway" || OTYPE == "simple-cluster")) emit("gw\t" clean(ONAME) "\t" OMATCH)
  }
}
function value(v, isstr,   k) {
  if (depth < 1) return
  if (typ[depth] == "{") { k = key[depth] } else { k = (depth > 1) ? key[depth - 1] : "" }
  if (depth == 1) {
    if (k == "is-default") { DEFAULT = (v == "true"); return }
    if (!isstr) return
    if (k == "sid") SID = v
    else if (k == "code") CODE = unesc(v)
    else if (k == "message") MSG = unesc(v)
    else if (k == "name") NAME = unesc(v)
    else if (k == "issued-by") ISSUED = unesc(v)
    else if (k == "base64-public-certificate") PUB = v
  } else if (isstr && inobj()) {
    if (depth == 3 && k == "uid") OUID = v
    else if (depth == 3 && k == "type") OTYPE = v
    else if (depth == 3 && k == "name") ONAME = unesc(v)
    if (gw != "" && index(k, "ipv4-address") == 1 && v == gw) OMATCH = 1
  }
}
function structural(t,   i, c, l, lit) {
  lit = ""; l = length(t)
  for (i = 1; i <= l; i++) {
    c = substr(t, i, 1)
    if (index("{}[],: \t\r", c) == 0) { lit = lit c; continue }
    if (lit != "") { value(lit, 0); lit = "" }
    if (c == "{" || c == "[") { depth++; typ[depth] = c; key[depth] = ""; wantkey[depth] = (c == "{"); opened() }
    else if (c == "}" || c == "]") { closed(); if (depth > 0) depth-- }
    else if (c == "," && typ[depth] == "{") wantkey[depth] = 1
  }
  if (lit != "") value(lit, 0)
}
function parse(line,   np, k, seg, instr) {
  np = split(line, P, "\"")
  instr = 0
  for (k = 1; k <= np; k++) {
    seg = P[k]
    if (!instr) { structural(seg); instr = 1; continue }
    while (k < np && odd_bs(seg)) { k++; seg = seg "\"" P[k] }
    if (k == np) break
    if (depth >= 1 && typ[depth] == "{" && wantkey[depth]) { key[depth] = seg; wantkey[depth] = 0 }
    else value(seg, 1)
    instr = 0
  }
}
NR > 1 { parse(prev) }
{ prev = $0 }
END {
  print "HTTP " prev
  if (mode == "sid" && SID != "" && SID !~ /[^A-Za-z0-9._~+\/=-]/ && length(SID) <= 512) {
    printf "X-chkp-sid: %s\n", SID > arg; close(arg); print "sid\tok"
  }
  if (mode == "cert") {
    if (PUB != "") {
      p = unesc(PUB); gsub(/\\r/, "", p); gsub(/\\n/, "\n", p); gsub(/\r/, "", p)
      if (index(p, "-----BEGIN CERTIFICATE-----") > 0) { print p > (arg ".pem"); close(arg ".pem") }
      else { gsub(/[ \t\n]/, "", p); print p > (arg ".b64"); close(arg ".b64") }
    }
    print "meta\t" (DEFAULT ? 1 : 0) "\t" clean(NAME) "\t" clean(ISSUED)
  }
  for (i = 1; i <= NO; i++) print OUT[i]
  if (CODE != "" || MSG != "") print "err\t" clean(CODE " " MSG)
}'
api_call() {  # api_call COMMAND MODE [ARG [GW]] <BODY: prints "HTTP <code>" and what MODE extracts (see JSON_AWK)
  local sid=()
  if [ -s "$API/sid.hdr" ]; then sid=(-H "@$API/sid.hdr"); fi
  { curl -sS --max-time 20 --cacert instance/aiguard/mgmt-ca.pem --connect-to "$MGMT_VNAME:$MGMT_PORT:$MGMT:$MGMT_PORT" \
         -H 'Content-Type: application/json' ${sid[@]+"${sid[@]}"} --data-binary @- \
         -w '\n%{http_code}' "https://$MGMT_VNAME:$MGMT_PORT/web_api/$1" 2>"$API/curl.err" || true; } \
    | { umask 077; awk -v mode="$2" -v arg="${3:-}" -v gw="${4:-}" "$JSON_AWK"; } || true
}
api_code() { local l; while IFS= read -r l; do case "$l" in "HTTP "*) printf '%s' "${l#HTTP }"; return 0 ;; esac; done <<<"$1"; }
api_get() {  # api_get OUTPUT TAG: the values of api_call's "TAG<TAB>value" lines
  local l
  while IFS= read -r l; do case "$l" in "$2"$'\t'*) printf '%s\n' "${l#*$'\t'}" ;; esac; done <<<"$1"
}
api_logout() {  # end the API session (also from the EXIT trap)
  [ -s "$API/sid.hdr" ] || return 0
  printf '{}' | api_call logout none >/dev/null || true
  rm -f "$API/sid.hdr"
}
API_KEY="" KEY_WHY=""   # the Management API key: kept in memory only, for the CA and the guided setup
read_api_key() {  # sets API_KEY: from the variable named by AIGUARD_MGMT_API_KEY_ENV, else asked once on the terminal
  local var="${AIGUARD_MGMT_API_KEY_ENV:-}"
  API_KEY=""
  if [ -n "$var" ]; then
    if [[ ! "$var" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then KEY_WHY="AIGUARD_MGMT_API_KEY_ENV must be the name of an environment variable"; return 1; fi
    API_KEY="${!var:-}"
    case "$var" in PATH|HOME|USER|LOGNAME|SHELL|PWD|TERM|LANG) ;; *) unset "$var" 2>/dev/null || true ;; esac   # not passed on to the commands below
    if [ -z "$API_KEY" ]; then KEY_WHY="AIGUARD_MGMT_API_KEY_ENV names $var, which is empty or not set"; return 1; fi
  elif { : </dev/tty; } 2>/dev/null; then
    sleep 0.3   # let tee print the lines above first
    { printf '    Management API key (typing is hidden; not stored; Enter to skip): '; } 2>/dev/null >/dev/tty || true
    IFS= read -rs API_KEY </dev/tty || API_KEY=""
    { printf '\n'; } 2>/dev/null >/dev/tty || true
    API_KEY="${API_KEY%$'\r'}"
    if [ -z "$API_KEY" ]; then KEY_WHY="no key typed"; return 1; fi
  else
    KEY_WHY="no terminal to ask on (for unattended runs set AIGUARD_MGMT_API_KEY_ENV to the name of a variable holding it)"; return 1
  fi
  case "$API_KEY" in *[[:cntrl:]]*) API_KEY=""; KEY_WHY="the key contains control characters"; return 1 ;; esac
  return 0
}
detect_gateway() {  # sets GATEWAY from the API session: the gateway whose addresses include this host's default gateway
  local gw_ip out name m names=() matches=()
  gw_ip="$({ ip route show default 2>/dev/null || true; } | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')"
  out="$(printf '{"details-level":"full","limit":500}' | api_call show-gateways-and-servers gateways "" "$gw_ip")"
  if [ "$(api_code "$out")" != 200 ]; then
    warn "could not list the gateways (show-gateways-and-servers): choose it in the web console"; return 0
  fi
  while IFS=$'\t' read -r name m; do
    [ -n "$name" ] || continue
    names+=("$name"); if [ "$m" = 1 ]; then matches+=("$name"); fi
  done < <(api_get "$out" gw)
  if [ "${#matches[@]}" -eq 1 ]; then
    GATEWAY="${matches[0]}"; ok "gateway: $GATEWAY (its addresses include this host's default gateway $gw_ip)"
  elif [ "${#matches[@]}" -eq 0 ] && [ "${#names[@]}" -eq 1 ]; then
    GATEWAY="${names[0]}"; ok "gateway: $GATEWAY (the only gateway on the management server)"
  elif [ "${#names[@]}" -eq 0 ]; then
    warn "no gateway objects found on the management server"
  else
    warn "gateway not chosen automatically (${#matches[@]} of ${#names[@]} include this host's default gateway ${gw_ip:-unknown}): ${names[*]}"
    warn "pick it in the web console, or rerun with --gateway NAME"
  fi
}
# ca_from_mgmt: the outbound CA from the management server (read-only API session). Only a
# certificate that validates the chain the gateway presents to this host is trusted.
ca_from_mgmt() {
  local key dom out code line uid n=0 f dflt nm best="" best_score=0 best_hosts="" best_nm="" score k full part hosts
  local -a uids=()
  say "Reading the outbound CA from the management server $MGMT:$MGMT_PORT"
  if [ "$MGMT_PROBED" = 0 ]; then mgmt_probe; fi
  if [ "$MGMT_CERT_PROBLEM" = 1 ]; then warn "the Management API is not used: its certificate cannot be verified (see above)"; return 1; fi
  case "$MGMT_API" in 400|401|403) ;; *) warn "the Management API is not used: it does not accept calls from this host (see above)"; return 1 ;; esac
  if [ -z "$API_KEY" ] && ! read_api_key; then warn "no Management API key: $KEY_WHY"; return 1; fi
  mkdir -p "$API"; chmod 700 "$API"
  key="${API_KEY//\\/\\\\}"; key="${key//\"/\\\"}"
  dom=""; if [ -n "$DOMAIN" ]; then dom=",\"domain\":\"$DOMAIN\""; fi   # MDS: outbound certificates are per domain
  out="$(printf '{"api-key":"%s","read-only":true,"session-name":"aiguard-installer"%s}' "$key" "$dom" | api_call login sid "$API/sid.hdr")"
  key=""
  code="$(api_code "$out")"; line="$(api_get "$out" err)"
  if [ "$code" != 200 ] || [ ! -s "$API/sid.hdr" ]; then
    case "$code:$line" in
      *err_login_failed*) API_KEY=""
                          warn "the Management API key was not accepted (err_login_failed)."
                          warn "Check it in SmartConsole: Manage & Settings > Permissions & Administrators > Administrators (Authentication: API Key)${DOMAIN:+, domain $DOMAIN}." ;;
      403:*) warn "the Management API refuses this host (HTTP 403)."
             warn "SmartConsole > Manage & Settings > Blades > Management API > Advanced Settings > Accept API calls from: All IP addresses that can be used for GUI clients; publish; on the SMS: api restart" ;;
      000:*|:*) warn "could not reach the Management API: $(tr '\n' ' ' <"$API/curl.err" | cut -c1-200)" ;;
      *) warn "Management API login failed (HTTP $code${line:+: $line})" ;;
    esac
    return 1
  fi
  ok "signed in to the Management API (read-only session \"aiguard-installer\"${DOMAIN:+, domain $DOMAIN})"
  out="$(printf '{"details-level":"standard","limit":50}' | api_call show-outbound-inspection-certificates uids)"
  code="$(api_code "$out")"
  if [ "$code" != 200 ]; then warn "show-outbound-inspection-certificates failed (HTTP $code: $(api_get "$out" err))"; api_logout; return 1; fi
  while IFS= read -r uid; do uids+=("$uid"); done < <(api_get "$out" uid)
  if [ "${#uids[@]}" -eq 0 ]; then warn "the management server has no outbound inspection certificate objects${DOMAIN:+ in domain $DOMAIN}"; api_logout; return 1; fi
  for uid in "${uids[@]}"; do
    case "$uid" in ""|*[!A-Za-z0-9-]*) continue ;; esac
    n=$((n+1)); f="$API/oc-$n"
    out="$(printf '{"uid":"%s"}' "$uid" | api_call show-outbound-inspection-certificate cert "$f")"
    code="$(api_code "$out")"
    if [ "$code" != 200 ]; then warn "show-outbound-inspection-certificate $uid: HTTP $code $(api_get "$out" err)"; continue; fi
    IFS=$'\t' read -r dflt nm _ <<<"$(api_get "$out" meta)"
    if [ ! -s "$f.pem" ] && [ -s "$f.b64" ]; then   # base64 of the PEM text, or of the DER certificate
      base64 -d "$f.b64" >"$f.bin" 2>/dev/null || true
      if grep -q -e "-----BEGIN CERTIFICATE-----" "$f.bin" 2>/dev/null; then
        awk '{ gsub(/\\r/, ""); gsub(/\\n/, "\n"); gsub(/\r/, ""); print }' "$f.bin" >"$f.pem"
      else
        openssl x509 -inform DER -in "$f.bin" -out "$f.pem" 2>/dev/null || true
      fi
    fi
    if [ -z "$(subj "$f.pem")" ]; then warn "\"$nm\": no readable base64-public-certificate"; continue; fi
    full=0 part=0 hosts=""
    for k in ${MISS_HP[@]+"${!MISS_HP[@]}"}; do
      if verifies "$f.pem" "${MISS_DIR[$k]}/c1.pem" "${MISS_DIR[$k]}/presented.pem"; then full=1; hosts="$hosts ${MISS_HP[$k]%%:*}"
      elif verifies_partial "$f.pem" "${MISS_DIR[$k]}/c1.pem" "${MISS_DIR[$k]}/presented.pem"; then part=1; hosts="$hosts ${MISS_HP[$k]%%:*}"; fi
    done
    score=0; if [ "$full" = 1 ]; then score=3; elif [ "$part" = 1 ]; then score=1; fi
    if [ "$score" -gt 0 ] && [ "$dflt" = 1 ]; then score=$((score + 1)); fi
    if [ "$score" -gt 0 ]; then echo "    \"$nm\"$([ "$dflt" = 1 ] && echo ' (default)'): $(subj "$f.pem") - validates the chain of:$hosts"
    else echo "    \"$nm\"$([ "$dflt" = 1 ] && echo ' (default)'): $(subj "$f.pem") - does not validate the chain this host sees"; fi
    if [ "$score" -gt "$best_score" ]; then best="$f.pem"; best_score="$score"; best_hosts="$hosts"; best_nm="$nm"; fi
  done
  if [ -z "$best" ]; then
    warn "none of the $n outbound certificate(s) on the management server validates the certificate chain this host sees"
    api_logout; return 1
  fi
  add_anchor "$best"
  ok "outbound CA \"$best_nm\": $(subj "$best") (from the management server, authenticated)"
  for k in ${MISS_HP[@]+"${!MISS_HP[@]}"}; do
    case " $best_hosts " in *" ${MISS_HP[$k]%%:*} "*) ok "${MISS_HP[$k]%%:*}: inspected by \"$(subj "$best")\" (from the management server, authenticated)" ;; esac
  done
  if [ "$best_score" -le 2 ]; then
    warn "it is not a root CA (issued by \"$(iss "$best")\"): it validates only as a partial chain."
    warn "curl and Docker accept that, Python does not: the web console in the image needs the root CA too."
    warn "It goes into certs/ anyway. For Python, rerun with --ca and the root (or the full chain) from win_client."
  fi
  if [ -z "$GATEWAY" ]; then detect_gateway; fi
  api_logout
  return 0
}

# ---------------------------------------------------------------- 2. outbound CA
say "Finding the gateway's HTTPS Inspection outbound CA"
NOT_INSPECTED="" MISSING_CA_HOSTS="" MISSING_CA_NAME=""
declare -a INSP_HP=() INSP_DIR=() MISS_HP=() MISS_DIR=()   # probe hosts with / without a CA found, and their chains
if [ -n "$CA_OPT" ]; then
  for a in "${ANCHORS[@]}"; do ok "using $CA_OPT: $(subj "$a")"; done
else
  for existing in certs/*.crt; do if [ -f "$existing" ]; then add_anchor "$existing"; fi; done
  i=0
  for hp in ${PROBE_LIST[@]+"${PROBE_LIST[@]}"}; do
    i=$((i+1)); host="${hp%%:*}"; port="${hp#*:}"; [ "$port" != "$hp" ] || port=443
    d="$WORK/probe$i"; mkdir -p "$d"
    timeout 15 openssl s_client -connect "$host:$port" -servername "$host" -showcerts </dev/null >"$d/raw" 2>/dev/null || true
    if ! grep -q "BEGIN CERTIFICATE" "$d/raw"; then warn "$host: no TLS connection (DNS, route or firewall)"; continue; fi
    split_chain "$d/raw" "$d"
    [ -f "$d/c1.pem" ] || { warn "$host: no certificate received"; continue; }
    cat "$d"/c*.pem >"$d/presented.pem"
    leaf_iss="$(iss "$d/c1.pem")"
    if public_issuer "$leaf_iss"; then NOT_INSPECTED="$NOT_INSPECTED $host"; ok "$host: public CA ($leaf_iss) - not inspected"; continue; fi
    # walk up the presented chain to the top-most certificate we can find
    cur="$d/c1.pem"; top=""
    for _ in 1 2 3 4 5; do
      want="$(iss "$cur")"; next=""
      for c in "$d"/c*.pem; do
        if [ "$c" != "$cur" ] && [ "$(subj "$c")" = "$want" ]; then next="$c"; break; fi
      done
      [ -n "$next" ] || break
      top="$next"; cur="$next"
      if is_ca_selfsigned "$cur"; then break; fi
    done
    anchor="" src=""
    if [ -n "$top" ] && is_ca_selfsigned "$top" && verifies "$top" "$d/c1.pem" "$d/presented.pem"; then
      anchor="$top"; src="presented by the gateway"
    else
      tip="${top:-$d/c1.pem}"; need="$(iss "$tip")"
      if store="$(find_in_store "$need" "$d/c1.pem" "$d/presented.pem")"; then anchor="$store"; src="already trusted on this host"; fi
      if [ -z "$anchor" ]; then
        aia="$(openssl x509 -in "$tip" -noout -ext authorityInfoAccess 2>/dev/null | sed -n 's/.*CA Issuers - URI:\(http[^ ,]*\).*/\1/p' | awk 'NR == 1' || true)"
        if [ -n "$aia" ] && curl -fsS --max-time 15 -o "$d/aia.der" "$aia" 2>/dev/null; then
          openssl x509 -inform DER -in "$d/aia.der" -out "$d/aia.pem" 2>/dev/null || cp "$d/aia.der" "$d/aia.pem"
          if is_ca_selfsigned "$d/aia.pem" && verifies "$d/aia.pem" "$d/c1.pem" "$d/presented.pem"; then anchor="$d/aia.pem"; src="downloaded from $aia"; fi
        fi
      fi
    fi
    if [ -z "$anchor" ]; then
      warn "$host: inspected by \"$leaf_iss\" but its root CA was not sent and is not on this host"
      MISSING_CA_HOSTS="$MISSING_CA_HOSTS $host"; MISSING_CA_NAME="${MISSING_CA_NAME:-$need}"
      MISS_HP+=("$hp"); MISS_DIR+=("$d")
      continue
    fi
    add_anchor "$anchor"
    INSP_HP+=("$hp"); INSP_DIR+=("$d")
    ok "$host: inspected by \"$(subj "$anchor")\" ($src)"
  done
fi

if [ "${#ANCHORS[@]}" -eq 0 ]; then
  if [ -n "$NOT_INSPECTED" ] && [ -z "$MISSING_CA_HOSTS" ]; then
    warn "No inspection CA found: traffic from this host to${NOT_INSPECTED} is not inspected."
    warn "The kit will install, but the demo needs HTTPS Inspection for the AI provider hosts (preflight will say so)."
  else
    # not on the wire and not on this host: ask the management server (Management API)
    if [ -n "$MGMT" ]; then ca_from_mgmt || true; fi
    if [ "${#ANCHORS[@]}" -eq 0 ]; then
      # last resort: copy it from win_client. The Windows certificate store name to look
      # for: the CA the gateway signs with, as seen here. Short lines (MobaXterm wraps).
      ps_cn="$(cn_of "$MISSING_CA_NAME" | tr -cd 'A-Za-z0-9 ._-')"; ps_cn="${ps_cn:-server-22}"
      hint=("Copy it from win_client with the clipboard instead:")
      if [ -z "$MGMT" ]; then hint=("Easiest: rerun with --mgmt <management server address> and type the" "Management API key when asked: the installer then reads the CA from it." "Or copy the CA from win_client with the clipboard:"); fi
      # shellcheck disable=SC2016  # PowerShell code: $ and backticks are for PowerShell
      die "Could not find the gateway's outbound CA automatically." \
          ${hint[@]+"${hint[@]}"} \
          "1. On win_client, in PowerShell, run these lines one at a time:" \
          "     \$s = 'CN=${ps_cn}*'" \
          '     $all = Get-ChildItem Cert:\LocalMachine\Root' \
          '     $c = $all | ? Subject -like $s | select -First 1' \
          '     $c.Subject' \
          "     \$b = [Convert]::ToBase64String(\$c.RawData,'InsertLineBreaks')" \
          '     $p = "-----BEGIN CERTIFICATE-----`n$b`n-----END CERTIFICATE-----"' \
          '     $p | Set-Clipboard' \
          '   ($c.Subject must show the CA; if it shows nothing, check the name after CN=)' \
          "2. On this host, run:" \
          "     cat > ~/outbound-ca.crt" \
          "   paste (right-click in MobaXterm), press Enter, then Ctrl+D." \
          "3. Run the installer again with --ca:" \
          "     $(rerun_cmd '--ca ~/outbound-ca.crt')" \
          "Without the clipboard (if scp to this host is allowed), after step 1:" \
          '     $p | Set-Content -Encoding ascii outbound-ca.crt' \
          "     scp outbound-ca.crt $(id -un)@${HOST_IP:-this-host}:~/"
    fi
  fi
elif [ -n "$MISSING_CA_HOSTS" ]; then
  warn "no CA found for:${MISSING_CA_HOSTS} (another CA signs them?): the check below shows whether they verify"
fi
if [ "$SETUP" = 0 ]; then API_KEY=""; fi   # kept only for the guided setup (step 9)

# Which of these CAs did this host trust before this run (in the system store, or curl already
# verified a host it signs)? Only a CA that is new here can also be new to Docker.
pem_lines() {  # pem_lines FILE...: each certificate on one line (its base64)
  awk '/-----BEGIN CERTIFICATE-----/ { b = ""; inb = 1; next }
       /-----END CERTIFICATE-----/ { if (inb) print b; inb = 0; next }
       inb { gsub(/[ \t\r]/, ""); b = b $0 }' "$@" 2>/dev/null || true
}
curl_verifies() { local c; c="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "https://$1/" 2>/dev/null || true)"; [ -n "$c" ] && [ "$c" != 000 ]; }
trusted_before() {  # trusted_before ANCHOR
  local l k
  l="$(pem_lines "$1" | awk 'NR == 1')"
  if [ -n "$l" ] && grep -qxF -- "$l" "$WORK/store.lines"; then return 0; fi
  for k in ${INSP_HP[@]+"${!INSP_HP[@]}"}; do
    if verifies "$1" "${INSP_DIR[$k]}/c1.pem" "${INSP_DIR[$k]}/presented.pem" && curl_verifies "${INSP_HP[$k]}"; then return 0; fi
  done
  return 1
}
pem_lines /etc/ssl/certs/ca-certificates.crt >"$WORK/store.lines"

CA_CHANGED=0 CA_NEW=0
n=0
for a in ${ANCHORS[@]+"${ANCHORS[@]}"}; do
  n=$((n+1))
  if trusted_before "$a"; then state="already trusted by this host"; else state="new on this host"; CA_NEW=1; fi
  if [ "$n" = 1 ]; then dest="certs/outbound-ca.crt"; else dest="certs/outbound-ca-$n.crt"; fi
  cp "$a" "$dest"; chmod 644 "$dest"
  name="aiguard-outbound-ca-$n.crt"
  if ! cmp -s "$dest" "/usr/local/share/ca-certificates/$name" 2>/dev/null; then
    $SUDO install -D -m 0644 "$dest" "/usr/local/share/ca-certificates/$name"; CA_CHANGED=1
  fi
  echo "    trusting: $(subj "$dest") ($state)"
  echo "      SHA-256 $(fp "$dest" sha256)"
  echo "      SHA-1   $(fp "$dest" sha1)   (compare: win_client certificate viewer, Details > Thumbprint)"
done
if [ "$CA_CHANGED" = 1 ] || [ "$CA_NEW" = 1 ]; then
  UCA="$(command -v update-ca-certificates || echo /usr/sbin/update-ca-certificates)"
  $SUDO "$UCA" >"$WORK/uca.log" 2>&1 || die "update-ca-certificates failed." "$(tail -n 5 "$WORK/uca.log")"
  if [ "$CA_NEW" = 1 ]; then ok "added to this host's trust store"
  else ok "also saved as /usr/local/share/ca-certificates/aiguard-outbound-ca-*.crt (this host already trusted it)"; fi
fi
for hp in ${PROBE_LIST[@]+"${PROBE_LIST[@]}"}; do
  host="${hp%%:*}"
  case "$hp" in *:*) url="https://$hp/" ;; *) url="https://$host/" ;; esac
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$url" 2>"$WORK/curl.err" || true)"
  if [ "$code" != "000" ]; then ok "$host: TLS verified by this host (HTTP $code)"; else warn "$host: $(tr '\n' ' ' < "$WORK/curl.err" | cut -c1-160)"; fi
done

# ---------------------------------------------------------------- 3. docker
# Docker reads the system trust store only when it starts, and restarting Docker restarts every
# container on this host. So a Docker that this installer did not just install is never restarted
# unless --restart-docker is given: a new CA goes to /etc/docker/certs.d/<registry>/, which Docker
# reads on every pull, and a pull of the base image shows whether Docker trusts what it sees.
say "Docker"
DOCKER_CERTS_D="" RESTARTED=0 N_RUNNING="?" PULL="" PULL_LOG="$WORK/pull.log"
X509_RE='x509|certificate signed by unknown authority|failed to verify certificate|certificate verify failed|certificate is not trusted'
BASE_IMAGE="$(awk 'toupper($1) == "FROM" { for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; exit } }' Dockerfile 2>/dev/null || true)"
BASE_IMAGE="${BASE_IMAGE:-python:3.11-slim}"
running_text() { case "$N_RUNNING" in 0) echo "no running containers" ;; "?") echo "all running containers" ;; *) echo "all $N_RUNNING running containers" ;; esac; }
docker_certs_d() {  # the CA(s) for Docker's registries: read on every pull, no restart needed
  local h f="$WORK/docker-ca.crt"
  [ "${#ANCHORS[@]}" -gt 0 ] || return 0
  cat "${ANCHORS[@]}" >"$f"
  for h in $DOCKER_REGISTRIES; do
    if ! cmp -s "$f" "/etc/docker/certs.d/$h/aiguard-outbound-ca.crt" 2>/dev/null; then
      $SUDO install -D -m 0644 "$f" "/etc/docker/certs.d/$h/aiguard-outbound-ca.crt" \
        || die "Could not write /etc/docker/certs.d/$h/aiguard-outbound-ca.crt."
    fi
  done
  DOCKER_CERTS_D=1
  ok "CA added for Docker's registries (read on every pull, no restart): /etc/docker/certs.d/<registry>/aiguard-outbound-ca.crt"
  echo "      registries: $DOCKER_REGISTRIES"
}
base_image_check() {  # sets PULL: present | pulled | x509 | failed (docker output in $PULL_LOG)
  PULL_LOG="$WORK/pull.log"
  if $SUDO docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then PULL=present; return 0; fi
  echo "    docker pull $BASE_IMAGE ..."
  if timeout 900 $SUDO docker pull "$BASE_IMAGE" >"$PULL_LOG" 2>&1; then PULL=pulled
  elif grep -qiE "$X509_RE" "$PULL_LOG"; then PULL=x509
  else PULL=failed; fi
}
builder_check() {  # after an x509 pull: the builder (BuildKit) reads certs.d on every build, docker pull may not
  echo "    docker pull does not trust it yet; trying docker build, which reads /etc/docker/certs.d ..."
  if printf 'FROM %s\n' "$BASE_IMAGE" | timeout 900 $SUDO docker build -q -t aiguard-ca-probe:tmp - >"$WORK/build-probe.log" 2>&1; then
    PULL=built
    $SUDO docker rmi aiguard-ca-probe:tmp >/dev/null 2>&1 || true
  fi
}
restart_docker() {  # restart the daemon and wait until it answers
  RESTARTED=1
  if ! $SUDO systemctl restart docker >"$WORK/restart.log" 2>&1; then
    warn "could not restart Docker: $(tail -n 1 "$WORK/restart.log")"; return 0
  fi
  for _ in $(seq 1 30); do if $SUDO docker info >/dev/null 2>&1; then break; fi; sleep 1; done
  ok "Docker restarted"
}
docker_x509_stop() {  # Docker does not trust the TLS it sees for the registry, and may not be restarted
  local err why
  err="$(grep -m1 -iE "$X509_RE" "$PULL_LOG" | cut -c1-220 || true)"
  if [ "${#ANCHORS[@]}" -eq 0 ]; then
    die "Docker cannot verify the registry's certificate, and no outbound CA was found for this host." \
        "docker pull $BASE_IMAGE: $err" "Get the gateway's outbound CA and rerun with --ca FILE (see --help)."
  fi
  if [ "$RESTARTED" = 1 ]; then
    die "Docker still does not trust the registry's certificate, even after a restart." "docker pull $BASE_IMAGE: $err" \
        "The gateway may sign the registry hosts with another CA than the one trusted above (see the TLS checks above)."
  fi
  case "$N_RUNNING" in
    0) why="No containers are running, but the installer restarts a Docker it did not install only with --restart-docker." ;;
    "?") why="The installer could not count the running containers, so it does not restart Docker by itself." ;;
    *) why="Restarting Docker restarts all $N_RUNNING running containers on this host, so the installer does not do it by itself." ;;
  esac
  die "Docker on this host does not trust the gateway's outbound CA yet." \
      "docker pull $BASE_IMAGE: $err" \
      "The CA is in this host's trust store and in /etc/docker/certs.d, but this Docker reads the trust store only when it starts." \
      "$why" \
      "At a convenient time, run:" \
      "  sudo systemctl restart docker" \
      "then run the installer again:" \
      "  $(rerun_cmd)" \
      "Or let the installer restart Docker now ($(running_text) restart too):" \
      "  $(rerun_cmd --restart-docker)"
}
if [ "$SKIP_DOCKER" = 1 ]; then
  warn "skipped (--skip-docker)"
  if [ "$RESTART_DOCKER" = 1 ]; then warn "--restart-docker has no effect with --skip-docker"; fi
else
  DOCKER_NEW=0
  if ! command -v docker >/dev/null; then
    echo "    installing docker.io (apt)..."
    { $SUDO apt-get update -qq && $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io; } >"$WORK/apt-docker.log" 2>&1 \
      || die "Could not install Docker (apt-get install docker.io)." "$(tail -n 3 "$WORK/apt-docker.log")"
    DOCKER_NEW=1
  fi
  $SUDO systemctl enable --now docker >/dev/null 2>&1 || true
  $SUDO docker info >/dev/null 2>&1 || die "Docker is not running." "Check: sudo systemctl status docker"
  ok "$($SUDO docker --version)"
  if ids="$($SUDO docker ps -q 2>/dev/null)"; then N_RUNNING="$(grep -c . <<<"$ids" || true)"; fi
  if [ "$DOCKER_NEW" = 1 ] && [ "$N_RUNNING" = 0 ]; then
    restart_docker   # just installed, nothing runs on it yet: it now reads the trust store with the CA
  else
    case "$N_RUNNING" in
      0) ok "no containers running" ;;
      "?") warn "could not list the running containers" ;;
      *) if [ "$RESTART_DOCKER" = 1 ]; then ok "$N_RUNNING containers running: Docker is restarted only if it has to be (--restart-docker)"
         else ok "$N_RUNNING containers running: the installer does not restart Docker"; fi ;;
    esac
    if [ "$CA_NEW" = 1 ]; then docker_certs_d; fi
  fi
  base_image_check
  if [ "$PULL" = x509 ] && [ "$RESTARTED" = 0 ] && [ -z "$DOCKER_CERTS_D" ] && [ "${#ANCHORS[@]}" -gt 0 ]; then
    docker_certs_d; base_image_check
  fi
  if [ "$PULL" = x509 ] && [ -n "$DOCKER_CERTS_D" ]; then builder_check; fi
  if [ "$PULL" = x509 ] && [ "$RESTART_DOCKER" = 1 ] && [ "$RESTARTED" = 0 ] && [ "${#ANCHORS[@]}" -gt 0 ]; then
    warn "--restart-docker: restarting Docker so it reads the CA; this restarts $(running_text)"
    if [ "$N_RUNNING" != 0 ]; then echo "    (Ctrl+C within 5 seconds to cancel)"; sleep 5; fi
    restart_docker; base_image_check
  fi
  case "$PULL" in
    present) ok "base image $BASE_IMAGE is already on this host" ;;
    pulled) ok "Docker pulled $BASE_IMAGE: it trusts the TLS it sees" ;;
    built) ok "docker build fetched $BASE_IMAGE through /etc/docker/certs.d: no restart needed"
           warn "docker pull itself trusts the CA only after Docker's next restart (this kit does not need it)" ;;
    x509) docker_x509_stop ;;
    *) die "docker pull $BASE_IMAGE failed (not a certificate problem)." "$(tail -n 5 "$PULL_LOG")" \
           "Fix Docker's access to the registry (DNS, proxy, rate limit), then rerun." ;;
  esac
fi

# ---------------------------------------------------------------- 4. .env
say "Settings (.env)"
# set_env / unset_env / get_env use bash builtins only, so a password or key never
# appears on a command line (ps); the new file is written in $WORK (mode 0700)
# and copied over .env, which keeps its mode.
set_env() {  # set_env KEY VALUE: replace (or append) KEY=VALUE, keep the rest of the file
  local k="$1" v="$2" line found=0
  case "$v" in *$'\n'*|*$'\r'*) die "Refusing to write $k to .env: the value contains a line break." ;; esac
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in "$k="*) printf '%s=%s\n' "$k" "$v"; found=1 ;; *) printf '%s\n' "$line" ;; esac
  done <.env >"$WORK/env.new"
  if [ "$found" = 0 ]; then printf '%s=%s\n' "$k" "$v" >>"$WORK/env.new"; fi
  cat "$WORK/env.new" >.env; rm -f "$WORK/env.new"
}
unset_env() {  # unset_env KEY: drop KEY= lines
  local line
  [ -f .env ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in "$1="*) ;; *) printf '%s\n' "$line" ;; esac
  done <.env >"$WORK/env.new"
  cat "$WORK/env.new" >.env; rm -f "$WORK/env.new"
}
get_env() {  # get_env KEY: last value, without CR and one pair of surrounding quotes
  local line v=""
  [ -f .env ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in "$1="*) v="${line#*=}" ;; esac
  done <.env
  v="${v%$'\r'}"
  case "$v" in \'*\'|\"*\") if [ "${#v}" -ge 2 ]; then v="${v:1:${#v}-2}"; fi ;; esac
  printf '%s' "$v"
}
new_password() {  # sets NEW_PW: 22 random letters and digits
  NEW_PW="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9')"; NEW_PW="${NEW_PW:0:22}"
  [ "${#NEW_PW}" = 22 ] || die "Could not generate a password (openssl rand)."
}
NEW_PW=""
if [ ! -f .env ]; then
  [ -f .env.example ] || die ".env.example is missing from $DIR." "Unpack the kit again (rerun the installer file)."
  (umask 077; cp .env.example .env)
  new_password
  set_env DEFAULT_ADMIN_EMAIL "$ADMIN_EMAIL"
  set_env DEFAULT_ADMIN_PASSWORD "$NEW_PW"
  set_env FLASK_SECRET_KEY "$(openssl rand -hex 32)"
  set_env SETTINGS_ENCRYPTION_KEY "$(openssl rand -base64 32)"
  ok "created .env with a new admin password and app keys"
else
  ok "kept the existing .env"
  if [ -z "$(get_env DEFAULT_ADMIN_PASSWORD)$(get_env DEFAULT_ADMIN_PASSWORD_HASH)" ]; then
    new_password
    set_env DEFAULT_ADMIN_PASSWORD "$NEW_PW"
    if [ -z "$(get_env DEFAULT_ADMIN_EMAIL)" ]; then set_env DEFAULT_ADMIN_EMAIL "$ADMIN_EMAIL"; fi
    ok "set a missing admin password"
  fi
fi
chmod 600 .env
if [ -n "$APP_PORT_OPT" ]; then set_env APP_PORT "$APP_PORT_OPT"; fi
PORT="$(get_env APP_PORT)"; PORT="${PORT:-9000}"
if [ -n "$HOST_IP" ]; then set_env AIGUARD_LOCAL_IP "$HOST_IP"; fi
if [ -n "$GATEWAY" ]; then set_env AIGUARD_GATEWAY "$GATEWAY"; fi
if [ -n "$MGMT_TYPE" ]; then set_env AIGUARD_MGMT_TYPE "$MGMT_TYPE"; fi
if [ -n "$DOMAIN" ]; then set_env AIGUARD_MGMT_DOMAIN "$DOMAIN"; fi
ok "web console port $PORT"

# ---------------------------------------------------------------- 5. management server
if [ -n "$MGMT" ]; then
  say "Management server $MGMT:$MGMT_PORT"
  if [ "$MGMT_PROBED" = 1 ]; then ok "checked above"; else mgmt_probe; fi
  mgmt_record
fi

# ---------------------------------------------------------------- 6. firewall on this host
if command -v ufw >/dev/null && [[ "$($SUDO ufw status 2>/dev/null || true)" == *"Status: active"* ]]; then
  if $SUDO ufw allow "$PORT/tcp" >/dev/null; then ok "ufw: allowed TCP $PORT"; else warn "ufw: could not allow TCP $PORT"; fi
fi

# ---------------------------------------------------------------- 7. build and start
if [ "$SKIP_BUILD" = 1 ]; then
  say "Skipping build (--skip-build)"
else
  say "Building and starting the web console (first build 10-20 minutes)"
  if [ "$UPDATED" = 1 ] || [ "$CA_CHANGED" = 1 ]; then bash ./scripts/lab_run_web.sh --rebuild; else bash ./scripts/lab_run_web.sh; fi
  say "Checking TLS from inside the container"
  for h in api.openai.com api.anthropic.com; do
    r="$($SUDO docker exec aiguard-web python -c "from aiguard import probe; r=probe.tls_probe('$h'); print(r.get('status'), '|', r.get('issuer') or r.get('verify_error') or '')" 2>/dev/null || echo "error")"
    case "$r" in inspected*) ok "$h: $r";; *) warn "$h: $r";; esac
  done
fi

# ---------------------------------------------------------------- 8. summary
say "Done"
URL="http://${HOST_IP:-$(hostname)}:${PORT}"
echo "    Web console:  $URL   (then: Gateway Mode)"
echo "    Sign in:      $(get_env DEFAULT_ADMIN_EMAIL)"
if [ -n "$NEW_PW" ]; then
  # printed to the terminal only, never into the install log
  sleep 0.3   # let tee print the lines above first
  if { printf '    Password:     %s   (also in %s/.env)\n' "$NEW_PW" "$DIR"; } 2>/dev/null >/dev/tty; then :
  else echo "    Password:     see DEFAULT_ADMIN_PASSWORD in $DIR/.env"; fi
  echo "    (password not written to this log; it is in $DIR/.env, mode 0600)"
else
  echo "    Password:     unchanged (DEFAULT_ADMIN_PASSWORD in $DIR/.env)"
fi
if [ -n "$MGMT" ]; then echo "    Management:   $MGMT:$MGMT_PORT pre-filled on the Connect page${GATEWAY:+, gateway $GATEWAY pre-selected}"; fi
if [ -n "$DOCKER_CERTS_D" ]; then
  echo "    Docker CA:    /etc/docker/certs.d/<registry>/aiguard-outbound-ca.crt (Docker reads it on every pull; not restarted)"
  echo "                  registries: $DOCKER_REGISTRIES"
fi
echo "    You type:     the Management API key, then the Guard API key + project ID (kept in memory only)"
echo "    CLI:          ${SUDO:+$SUDO }docker exec -it aiguard-web python -m aiguard setup"
echo "    Update:       copy a new aiguard-lab-install.sh and run it again (settings and data are kept)"
echo "    Remove:       bash aiguard-lab-install.sh --uninstall"
echo "    Install log:  $LOG"
echo
echo "    If win_client cannot open $URL: allow TCP $PORT from win_client to ${HOST_IP:-this host} in the gateway's Access Control policy."
if [ "$SETUP" = 0 ]; then
  if [ "$NO_SETUP" = 0 ] && [ "$SKIP_BUILD" = 0 ]; then echo "    Next:         not a terminal, so no guided setup here: run the CLI line above, or use the web console."; fi
  exit 0
fi

# ---------------------------------------------------------------- 9. guided setup and demo, in this terminal
# The Management API key reaches the CLI in the container as the environment variable
# AIGUARD_MGMT_KEY, which docker reads from its own environment (docker exec -e NAME, without
# =value): it is never on a command line, and not in docker inspect (the settings of an exec are
# not part of the container's configuration). How it gets to the docker command:
#   - root, or a user who may use docker without sudo: docker inherits the exported variable;
#   - sudo: sudo --preserve-env=AIGUARD_MGMT_KEY, when sudoers allows it (checked first);
#   - else: docker exec --env-file with a 0600 file in the 0700 work folder (read by the docker
#     command; removed when the demo ends, and with the work folder at exit).
# Not used: the key on docker exec's stdin (setup needs stdin as its terminal for -it, the hidden
# prompts and the typed APPROVE), or a key file in a mounted folder (an exec cannot add a mount,
# and the kit's mounted folders stay on disk).
say "Guided setup and demo in this terminal"
echo "    The web console at $URL does the same: stop here with Ctrl+C and continue there at any time."
if [ -z "$API_KEY" ] && ! read_api_key; then warn "no Management API key ($KEY_WHY): setup asks for the sign-in itself"; fi
DX=(docker exec -it) KEY_ENV=() KEY_ARG=()
if [ -n "$API_KEY" ]; then
  mkdir -p "$API"; chmod 700 "$API"
  if [ -z "$SUDO" ] || docker info >/dev/null 2>&1; then
    KEY_ENV=(-e AIGUARD_MGMT_KEY)
  elif AIGUARD_MGMT_KEY=aiguard-env-check sudo --preserve-env=AIGUARD_MGMT_KEY env 2>/dev/null | grep -qx 'AIGUARD_MGMT_KEY=aiguard-env-check'; then
    DX=(sudo --preserve-env=AIGUARD_MGMT_KEY docker exec -it) KEY_ENV=(-e AIGUARD_MGMT_KEY)
  else
    ( umask 077; printf 'AIGUARD_MGMT_KEY=%s\n' "$API_KEY" >"$API/setup.env" )
    DX=(sudo docker exec -it) KEY_ENV=(--env-file "$API/setup.env")
  fi
  if [ "${KEY_ENV[0]}" = -e ]; then export AIGUARD_MGMT_KEY="$API_KEY"; fi
  KEY_ARG=(--api-key-env AIGUARD_MGMT_KEY)
elif [ -n "$SUDO" ] && ! docker info >/dev/null 2>&1; then
  DX=(sudo docker exec -it)
fi
API_KEY=""
CONN=()   # what setup would otherwise ask (all known here), so it only asks for the Guard key and project ID
if [ -n "$MGMT" ]; then
  CONN=(--server "$MGMT" --port "$MGMT_PORT" --server-type "$(printf '%s' "${MGMT_TYPE:-SMS}" | tr '[:upper:]' '[:lower:]')")
fi
if [ -n "$DOMAIN" ]; then CONN+=(--domain "$DOMAIN"); fi
if [ -n "$GATEWAY" ]; then CONN+=(--gateway "$GATEWAY"); fi
SETUP_ARGS=(--moderation); if [ -n "$PROJECT_ID" ]; then SETUP_ARGS+=(--project-id "$PROJECT_ID"); fi
end_setup() {  # the key is not needed any more
  unset AIGUARD_MGMT_KEY
  rm -f "$API/setup.env"
}
sleep 0.3   # let tee print the lines above first; the CLI talks to the terminal directly (it keeps its own log)
rc=0
"${DX[@]}" ${KEY_ENV[@]+"${KEY_ENV[@]}"} aiguard-web python -m aiguard setup ${KEY_ARG[@]+"${KEY_ARG[@]}"} \
  ${CONN[@]+"${CONN[@]}"} "${SETUP_ARGS[@]}" >&3 2>&4 || rc=$?
if [ "$rc" != 0 ]; then
  end_setup
  say "Setup stopped (exit code $rc)"
  echo "    CLI log:      $DIR/logs/aiguard   (in the container: /app/logs/aiguard)"
  echo "    The web console at $URL continues from where it stopped (Gateway Mode)."
  exit "$rc"
fi
"${DX[@]}" ${KEY_ENV[@]+"${KEY_ENV[@]}"} aiguard-web python -m aiguard demo --guided ${KEY_ARG[@]+"${KEY_ARG[@]}"} \
  ${CONN[@]+"${CONN[@]}"} >&3 2>&4 || rc=$?
end_setup
if [ "$rc" = 0 ]; then say "Guided demo ended"; else say "Guided demo ended (exit code $rc)"; fi
echo "    Web console:  $URL   (the same demo in a browser)"
echo "    CLI log:      $DIR/logs/aiguard"
exit "$rc"
