#!/usr/bin/env bash
# AI Guard Demo Kit: one-shot lab installer for a Linux host behind a Check Point gateway.
#
#   bash aiguard-lab-install.sh --mgmt 10.1.1.100 --gateway GW
#
# Everything is automatic by default:
#   1. unpacks the kit (from this self-extracting file, or uses the repo it sits in)
#   2. finds the gateway's HTTPS Inspection outbound CA and trusts it on this host
#      (already trusted: copied from the system store; otherwise taken from the
#      certificate chain the gateway presents, with its fingerprint printed)
#   3. installs Docker if missing and restarts it so it trusts the CA
#   4. writes .env (admin sign-in, app keys, management defaults) if missing
#   5. checks the management server: certificate, name/IP match, API access
#   6. builds the image (the CA goes into the image trust store) and starts it
#   7. checks the container sees inspected TLS to the AI providers
#   8. prints the URL, the admin sign-in, and what is left to do
# Secrets you still type yourself (never stored by this script): the Management
# API key and the Guard API key, in the web console or the CLI.
#
# Options (all optional):
#   --mgmt HOST            management server (SMS/MDS) address, e.g. 10.1.1.100
#   --mgmt-port N          management web API port (default 443)
#   --mgmt-name NAME       name to verify the management certificate against
#   --mgmt-type SMS|MDS    server type (default SMS)
#   --domain NAME          MDS domain
#   --gateway NAME         gateway object to pre-select (e.g. GW)
#   --ca FILE              outbound CA (PEM or DER) to trust instead of auto-detecting
#   --dir DIR              install folder (default ~/ai-guardrails-demo)
#   --port N               web console port (default 9000)
#   --admin-email EMAIL    sign-in e-mail (default admin@aiguard.lab)
#   --skip-build           prepare everything but do not build/start the container
#   --skip-docker          do not install or touch Docker (implies --skip-build)
#   --uninstall            stop and remove the container and image (keeps data)
#   -h, --help             this help
# Environment (tests and special labs): AIGUARD_PROBE_HOSTS="host[:port] ..."
# overrides the hosts used to detect the outbound CA.
case "$(head -c 4096 -- "$0" 2>/dev/null || true)" in *$'\r'*) printf '%s\n' "This file has Windows (CRLF) line endings, so bash cannot run it." "Fix: sed -i 's/\r\$//' \"$0\"   then run it again (next time copy it in binary mode: scp/SFTP)." >&2; exit 2 ;; esac # CRLF guard: this line ends in a comment so it still parses with CRLF
set -Eeuo pipefail

PAYLOAD_MARKER="__AIGUARD_PAYLOAD_BELOW__"
ORIG_PWD="$PWD"
DIR="${HOME}/ai-guardrails-demo" DIR_OPT=""
APP_PORT_OPT=""
ADMIN_EMAIL="admin@aiguard.lab"
MGMT="" MGMT_PORT="443" MGMT_NAME="" MGMT_TYPE="" DOMAIN="" GATEWAY="" CA_OPT=""
SKIP_BUILD=0 SKIP_DOCKER=0 UNINSTALL=0
PROBE_HOSTS="${AIGUARD_PROBE_HOSTS:-api.openai.com api.anthropic.com pypi.org download.pytorch.org registry-1.docker.io}"
PUBLIC_CA_RE='(google trust services|digicert|let.s encrypt|isrg|sectigo|comodo|usertrust|globalsign|amazon|microsoft|entrust|godaddy|starfield|baltimore|identrust|cloudflare|certainly|buypass|actalis|ssl\.com|harica|certum|quovadis|swisssign|telia|wisekey|trustwave|secom|t-systems|d-trust|geotrust|thawte|rapidssl|zerossl|apple|cisco)'

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
exec 3>&1 4>&2
exec > >(tee -a "$LOG") 2>&1
TEE_PID=$!
finish() {  # remove the scratch folder; let tee write the last lines before the shell exits
  local rc=$?
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

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
  say "Removing the container and image (data in $DIR is kept)"
  if ! command -v docker >/dev/null 2>&1; then
    warn "Docker is not installed: no container or image to remove"
  else
    if $SUDO docker rm -f aiguard-web >/dev/null 2>&1; then ok "container removed"; else warn "no container"; fi
    if $SUDO docker rmi aiguard-web:lab >/dev/null 2>&1; then ok "image removed"; else warn "no image"; fi
  fi
  echo "    The outbound CA stays trusted on this host (/usr/local/share/ca-certificates/aiguard-outbound-ca-*.crt)."
  echo "    To remove it too: sudo rm /usr/local/share/ca-certificates/aiguard-outbound-ca-*.crt && sudo update-ca-certificates --fresh"
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
split_chain() { awk -v d="$2" '/-----BEGIN CERTIFICATE-----/{n++; inb=1} inb{print > (d "/c" n ".pem")} /-----END CERTIFICATE-----/{inb=0}' "$1"; }
verifies() {  # verifies ANCHOR LEAF [MORE_CERTS]: ANCHOR (and only ANCHOR) validates the presented chain
  local extra=()
  if [ -n "${3:-}" ] && [ -s "$3" ]; then extra=(-untrusted "$3"); fi
  openssl verify -no_check_time -trusted "$1" ${extra[@]+"${extra[@]}"} "$2" >/dev/null 2>&1
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

# ---------------------------------------------------------------- 2. outbound CA
say "Finding the gateway's HTTPS Inspection outbound CA"
NOT_INSPECTED="" MISSING_CA_HOSTS="" MISSING_CA_NAME=""
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
      continue
    fi
    add_anchor "$anchor"
    ok "$host: inspected by \"$(subj "$anchor")\" ($src)"
  done
fi

if [ "${#ANCHORS[@]}" -eq 0 ]; then
  if [ -n "$NOT_INSPECTED" ] && [ -z "$MISSING_CA_HOSTS" ]; then
    warn "No inspection CA found: traffic from this host to${NOT_INSPECTED} is not inspected."
    warn "The kit will install, but the demo needs HTTPS Inspection for the AI provider hosts (preflight will say so)."
  else
    # the Windows certificate store name to look for: the CA the gateway signs with, as seen here
    ps_cn="$(cn_of "$MISSING_CA_NAME" | tr -cd 'A-Za-z0-9 ._-')"; ps_cn="${ps_cn:-server-22}"
    die "Could not find the gateway's outbound CA automatically." \
        "On win_client (PowerShell), export it and copy it here, then rerun with --ca ~/outbound-ca.crt:" \
        "  \$c = Get-ChildItem Cert:\\LocalMachine\\Root | ? Subject -like 'CN=${ps_cn}*' | select -First 1" \
        "  '-----BEGIN CERTIFICATE-----' + [char]10 + [Convert]::ToBase64String(\$c.RawData,'InsertLineBreaks') + [char]10 + '-----END CERTIFICATE-----' | Set-Content -Encoding ascii outbound-ca.crt" \
        "  scp outbound-ca.crt $(id -un)@${HOST_IP:-this-host}:~/"
  fi
elif [ -n "$MISSING_CA_HOSTS" ]; then
  warn "no CA found for:${MISSING_CA_HOSTS} (another CA signs them?): the check below shows whether they verify"
fi

CA_CHANGED=0
n=0
for a in ${ANCHORS[@]+"${ANCHORS[@]}"}; do
  n=$((n+1))
  if [ "$n" = 1 ]; then dest="certs/outbound-ca.crt"; else dest="certs/outbound-ca-$n.crt"; fi
  cp "$a" "$dest"; chmod 644 "$dest"
  name="aiguard-outbound-ca-$n.crt"
  if ! cmp -s "$dest" "/usr/local/share/ca-certificates/$name" 2>/dev/null; then
    $SUDO install -D -m 0644 "$dest" "/usr/local/share/ca-certificates/$name"; CA_CHANGED=1
  fi
  echo "    trusting: $(subj "$dest")"
  echo "      SHA-256 $(fp "$dest" sha256)"
  echo "      SHA-1   $(fp "$dest" sha1)   (compare: win_client certificate viewer, Details > Thumbprint)"
done
if [ "$CA_CHANGED" = 1 ]; then
  UCA="$(command -v update-ca-certificates || echo /usr/sbin/update-ca-certificates)"
  $SUDO "$UCA" >"$WORK/uca.log" 2>&1 || die "update-ca-certificates failed." "$(tail -n 5 "$WORK/uca.log")"
  ok "added to this host's trust store"
fi
for hp in ${PROBE_LIST[@]+"${PROBE_LIST[@]}"}; do
  host="${hp%%:*}"
  case "$hp" in *:*) url="https://$hp/" ;; *) url="https://$host/" ;; esac
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$url" 2>"$WORK/curl.err" || true)"
  if [ "$code" != "000" ]; then ok "$host: TLS verified by this host (HTTP $code)"; else warn "$host: $(tr '\n' ' ' < "$WORK/curl.err" | cut -c1-160)"; fi
done

# ---------------------------------------------------------------- 3. docker
say "Docker"
if [ "$SKIP_DOCKER" = 1 ]; then
  warn "skipped (--skip-docker)"
else
  if ! command -v docker >/dev/null; then
    echo "    installing docker.io (apt)..."
    { $SUDO apt-get update -qq && $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io; } >"$WORK/apt-docker.log" 2>&1 \
      || die "Could not install Docker (apt-get install docker.io)." "$(tail -n 3 "$WORK/apt-docker.log")"
    CA_CHANGED=1
  fi
  $SUDO systemctl enable --now docker >/dev/null 2>&1 || true
  if [ "$CA_CHANGED" = 1 ]; then
    if $SUDO systemctl restart docker >/dev/null 2>&1; then ok "restarted so it trusts the CA"; else warn "could not restart Docker: restart it yourself so it trusts the CA"; fi
  fi
  $SUDO docker info >/dev/null 2>&1 || die "Docker is not running." "Check: sudo systemctl status docker"
  ok "$($SUDO docker --version)"
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
  set_env AIGUARD_MGMT_SERVER "$MGMT"; set_env AIGUARD_MGMT_PORT "$MGMT_PORT"
  m="$WORK/mgmt"; mkdir -p "$m"
  sni=(); if [ -n "$MGMT_NAME" ]; then sni=(-servername "$MGMT_NAME"); fi
  timeout 15 openssl s_client -connect "$MGMT:$MGMT_PORT" ${sni[@]+"${sni[@]}"} -showcerts </dev/null >"$m/raw" 2>/dev/null || true
  if grep -q "BEGIN CERTIFICATE" "$m/raw"; then split_chain "$m/raw" "$m"; fi
  if [ ! -f "$m/c1.pem" ]; then
    warn "no TLS answer from $MGMT:$MGMT_PORT (route, firewall, or the Gaia portal is on another port)"
  else
    leaf="$m/c1.pem"; cat "$m"/c*.pem >"$m/presented.pem"
    msubj="$(subj "$leaf")"; mcn="$(cn_of "$msubj")"
    msan="$(openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ' || true)"
    echo "    certificate: $msubj"
    echo "    SAN:         ${msan:-none}"
    echo "    SHA-1:       $(fp "$leaf" sha1)   (compare on the SMS: api fingerprint)"
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
    set_env AIGUARD_MGMT_CA_FILE /app/instance/aiguard/mgmt-ca.pem
    set_env AIGUARD_MGMT_FINGERPRINT_SHA1 "$(fp "$leaf" sha1)"
    # which name will verify?
    is_ip=0; if grep -Eq '^[0-9]+(\.[0-9]+){3}$' <<<"$MGMT"; then is_ip=1; fi
    name_ok=""
    if [ -n "$MGMT_NAME" ]; then name_ok="$MGMT_NAME"
    elif [ "$is_ip" = 1 ] && grep -qxF "IPAddress:$MGMT" <<<"${msan//,/$'\n'}"; then name_ok="(IP in SAN)"
    elif [ "$is_ip" = 0 ] && grep -qiF "$MGMT" <<<"$msan$mcn"; then name_ok="(name in certificate)"
    else
      dns="$(sed -n 's/^DNS://p' <<<"${msan//,/$'\n'}" | awk 'NR == 1')"
      if [ -z "$dns" ] && [ -n "$mcn" ] && ! grep -Eq '^[0-9.]+$' <<<"$mcn"; then dns="$mcn"; fi
      name_ok="$dns"
    fi
    MGMT_CERT_PROBLEM=0
    case "$name_ok" in
      "") if [ -n "$msan" ]; then warn "the certificate does not name $MGMT (SAN: $msan): it cannot be verified when connecting by IP."
          else warn "the certificate names only \"$mcn\" with no SAN: it cannot be verified when connecting by IP."; fi
          warn "Fix on the management server: ICA-signed Gaia portal certificate with SAN IP $MGMT (sk164382), then rerun this installer."
          unset_env AIGUARD_MGMT_SERVER_NAME
          MGMT_CERT_PROBLEM=1 ;;
      "("*) unset_env AIGUARD_MGMT_SERVER_NAME; ok "certificate matches $MGMT $name_ok" ;;
      *) set_env AIGUARD_MGMT_SERVER_NAME "$name_ok"; ok "will verify the certificate as \"$name_ok\" while connecting to $MGMT" ;;
    esac
    if [ "$MGMT_CERT_PROBLEM" = 0 ]; then
      vname="$MGMT"; case "$name_ok" in "("*|"") ;; *) vname="$name_ok" ;; esac
      body="$(curl -sS --max-time 15 --cacert instance/aiguard/mgmt-ca.pem --connect-to "$vname:$MGMT_PORT:$MGMT:$MGMT_PORT" \
              -H 'Content-Type: application/json' -d '{}' -w '\n%{http_code}' "https://$vname:$MGMT_PORT/web_api/login" 2>"$WORK/m.err" || true)"
      code="${body##*$'\n'}"
      case "$code" in
        400|401) ok "Management API answers and accepts calls from this host (HTTP $code to an empty login)";;
        403) if grep -qiE "permission to access|forbidden" <<<"$body"; then
               warn "Management API refuses this host (HTTP 403)."
               warn "SmartConsole > Manage & Settings > Blades > Management API > Advanced Settings > Accept API calls from: All IP addresses that can be used for GUI clients; publish; on the SMS: api restart"
             else ok "Management API answers (HTTP 403 to an empty login)"; fi ;;
        000|"") warn "could not verify/reach the API: $(tr '\n' ' ' < "$WORK/m.err" | cut -c1-200)";;
        *) warn "Management API answered HTTP $code";;
      esac
    fi
  fi
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
echo "    You type:     the Management API key, then the Guard API key + project ID (kept in memory only)"
echo "    CLI:          ${SUDO:+$SUDO }docker exec -it aiguard-web python -m aiguard setup"
echo "    Update:       copy a new aiguard-lab-install.sh and run it again (settings and data are kept)"
echo "    Remove:       bash aiguard-lab-install.sh --uninstall"
echo "    Install log:  $LOG"
echo
echo "    If win_client cannot open $URL: allow TCP $PORT from win_client to ${HOST_IP:-this host} in the gateway's Access Control policy."
exit 0
