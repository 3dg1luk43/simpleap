#!/usr/bin/env bash
# simple_ap.sh — 2.4GHz WPA2 AP for pentesting; hostapd+dnsmasq; iptables NAT/filters; logs; Ctrl+C cleanup
# Positional: WIFI_IF UPLINK_IF SSID WPA2_PSK
# Utility mode:
#   --install                Interactive setup assistant (step-by-step, with pauses)
#   --cleanup                Comprehensive cleanup (rules/processes/interfaces)
# Named:
#   --channel N               (default: 1)
#   --subnet CIDR             (default: 10.10.10.0/24)
#   --gateway IP              (default: 10.10.10.1)
#   --dhcp-start IP           (default: 10.10.10.50)
#   --dhcp-end IP             (default: 10.10.10.150)
#   --mode normal|compat      (default: compat)  # compat = 11n off, WMM off, PMF off
#   --country CC              (default: CZ)
#   --forward SPEC            (repeatable)       # tcp|udp:INPORT=DSTPORT  or  tcp|udp:INPORT=DSTIP:DSTPORT
#   --lease MAC=IP            (repeatable)       # static DHCP lease
#   --debug                   (optional)
set -euo pipefail

usage() { sed -n '1,70p' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,60p'; }
die(){ echo "ERROR: $*" >&2; exit 1; }
debug(){ [[ ${DEBUG:-0} -eq 1 ]] && echo "[DEBUG] $*" >&2 || true; }

pause_step(){
  local msg="$1"
  echo
  echo "[STEP] $msg"
  read -r -p "[INPUT] Press Enter to continue, or type q to quit: " _ans
  if [[ "${_ans:-}" == "q" || "${_ans:-}" == "Q" ]]; then
    echo "[INFO] Install aborted by user"
    exit 0
  fi
  return 0
}

ask_approval(){
  local prompt="$1"
  local ans
  while true; do
    read -r -p "[INPUT] ${prompt} [y/N/q]: " ans
    case "${ans:-}" in
      y|Y) return 0 ;;
      n|N|"") return 1 ;;
      q|Q) echo "[INFO] Install aborted by user"; exit 0 ;;
      *) echo "[WARN] Please answer y, n, or q." ;;
    esac
  done
}

run_cmd(){
  local cmd="$1"
  echo "[CMD] $cmd"
  eval "$cmd"
}

print_cmd(){
  printf '[CMD] '
  printf '%q ' "$@"
  printf '\n'
}

delete_rule_all(){
  local table="$1"
  local chain="$2"
  shift 2

  while true; do
    if [[ -n "$table" ]]; then
      iptables -t "$table" -C "$chain" "$@" 2>/dev/null || break
      print_cmd iptables -t "$table" -D "$chain" "$@"
      iptables -t "$table" -D "$chain" "$@" 2>/dev/null || break
    else
      iptables -C "$chain" "$@" 2>/dev/null || break
      print_cmd iptables -D "$chain" "$@"
      iptables -D "$chain" "$@" 2>/dev/null || break
    fi
  done
}

delete_prerouting_for_iface(){
  local wifi_if="$1"
  local line spec

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    spec="${line/-A /-D }"
    echo "[CMD] iptables -t nat $spec"
    iptables -t nat $spec 2>/dev/null || true
  done < <(iptables -t nat -S PREROUTING 2>/dev/null \
    | grep " -i ${wifi_if} " \
    | grep -E ' -j (REDIRECT|DNAT)')
}

run_cleanup(){
  [[ $(id -u) -eq 0 ]] || die "run cleanup as root (sudo ./simpleap.sh --cleanup)"
  command -v iptables >/dev/null || die "iptables not found"
  command -v ip >/dev/null || die "ip not found"

  local wifi_if="wlan0"
  local up_if="eth0"
  local subnet="10.10.10.0/24"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --wifi-if)   wifi_if="${2?}"; shift 2 ;;
      --uplink-if) up_if="${2?}"; shift 2 ;;
      --subnet)    subnet="${2?}"; shift 2 ;;
      -h|--help)
        echo "Usage: sudo ./simpleap.sh --cleanup [--wifi-if wlan0] [--uplink-if eth0] [--subnet 10.10.10.0/24]"
        exit 0
        ;;
      *) die "unknown cleanup option: $1" ;;
    esac
  done

  echo "[INFO] Comprehensive cleanup started"
  echo "[INFO] Target wifi-if=${wifi_if} uplink-if=${up_if} subnet=${subnet}"

  echo "[STEP] Stop AP/DHCP processes"
  echo "[CMD] pkill -9 hostapd dnsmasq"
  pkill -9 hostapd dnsmasq 2>/dev/null || true

  echo "[STEP] Remove NAT PREROUTING redirects/dnat for target wifi interface"
  delete_prerouting_for_iface "$wifi_if"

  echo "[STEP] Remove known filter/NAT rules"
  delete_rule_all "" INPUT -i "$wifi_if" -s "$subnet" -j ACCEPT
  delete_rule_all "" INPUT -i "$wifi_if" -p udp --dport 67 -j ACCEPT
  delete_rule_all "" INPUT -i "$wifi_if" -p udp --dport 68 -j ACCEPT
  delete_rule_all "" INPUT -i "$wifi_if" -p udp --dport 53 -j ACCEPT
  delete_rule_all "" INPUT -i "$wifi_if" -p tcp --dport 53 -j ACCEPT
  delete_rule_all "" INPUT -i "$wifi_if" -p icmp -j ACCEPT
  delete_rule_all "" OUTPUT -o "$wifi_if" -j ACCEPT
  delete_rule_all "" FORWARD -i "$wifi_if" -o "$up_if" -j ACCEPT
  delete_rule_all "" FORWARD -i "$up_if" -o "$wifi_if" -j ACCEPT
  delete_rule_all "" FORWARD -i "$wifi_if" -o "$wifi_if" -j ACCEPT
  delete_rule_all "" FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  delete_rule_all "nat" POSTROUTING -o "$up_if" -j MASQUERADE

  echo "[STEP] Restore interface/network state"
  if ip link show "$wifi_if" >/dev/null 2>&1; then
    print_cmd ip addr flush dev "$wifi_if"
    ip addr flush dev "$wifi_if" 2>/dev/null || true
    print_cmd iw dev "$wifi_if" set type managed
    iw dev "$wifi_if" set type managed 2>/dev/null || true
    print_cmd ip link set "$wifi_if" down
    ip link set "$wifi_if" down 2>/dev/null || true
    if command -v nmcli >/dev/null 2>&1; then
      print_cmd nmcli dev set "$wifi_if" managed yes
      nmcli dev set "$wifi_if" managed yes >/dev/null 2>&1 || true
    fi
  else
    echo "[INFO] Interface $wifi_if not found; skipped interface state restore"
  fi

  echo "[STEP] Disable IPv4 forwarding"
  print_cmd sysctl -q net.ipv4.ip_forward=0
  sysctl -q net.ipv4.ip_forward=0 2>/dev/null || true

  echo "[DONE] Cleanup completed"
  exit 0
}

run_install(){
  local _c

  [[ -t 0 && -t 1 ]] || die "--install requires an interactive TTY (run directly in a terminal)"
  [[ $(id -u) -eq 0 ]] || die "run installer as root (sudo ./simpleap.sh --install)"
  command -v apt >/dev/null || die "apt not found (installer currently supports Debian/Kali/Ubuntu apt-based systems)"

  echo "[INFO] Interactive setup assistant"
  echo "[INFO] Commands are shown before execution"
  echo "[INFO] You manually approve each step"

  pause_step "Step 1/6: refresh package metadata (apt update)"
  run_cmd "apt update"

  pause_step "Step 2/6: install runtime deps required for simpleap.sh"
  run_cmd "apt install -y hostapd dnsmasq iptables iproute2 iw"

  pause_step "Step 3/6: verify tools required by script are present"
  for cmd in ip iw hostapd dnsmasq iptables ss; do
    command -v "$cmd" >/dev/null || die "missing after install: $cmd"
    echo "[OK] Found: $cmd"
  done

  if ask_approval "Optional: install tcpdump for troubleshooting captures?"; then
    run_cmd "apt install -y tcpdump"
  else
    echo "[INFO] Skipped optional tcpdump"
  fi

  if ask_approval "Optional: install pipx (preferred over pip for standalone Python CLI tools)?"; then
    run_cmd "apt install -y pipx python3-venv"
    run_cmd "pipx ensurepath || true"
    echo "[INFO] pipx installed. Open a new shell session if PATH did not refresh."
  else
    echo "[INFO] Skipped optional pipx"
  fi

  if ask_approval "Optional: run Realtek AU driver helper steps (for AWUS/rtl8812au scenarios)?"; then
    pause_step "Driver helper: install build dependencies"
    run_cmd "apt install -y linux-headers-\"$(uname -r)\" dkms git build-essential"

    pause_step "Driver helper: show dkms status"
    run_cmd "dkms status || true"

    if ask_approval "Driver helper: remove currently installed 8812au DKMS entries (if any)?"; then
      while IFS= read -r modver; do
        [[ -z "$modver" ]] && continue
        echo "[INFO] Removing DKMS entry: $modver"
        run_cmd "dkms remove \"$modver\" --all || true"
      done < <(dkms status | awk -F, '/8812au/ {gsub(/ /, "", $1); print $1}')
    else
      echo "[INFO] Skipped automatic DKMS removal"
    fi

    pause_step "Driver helper: clone/pin aircrack-ng rtl8812au to commit 63cf0b4"
    run_cmd "rm -rf /tmp/rtl8812au.install"
    run_cmd "git clone -b v5.6.4.2 https://github.com/aircrack-ng/rtl8812au.git /tmp/rtl8812au.install"
    run_cmd "git -C /tmp/rtl8812au.install checkout 63cf0b4"

    if ask_approval "Driver helper: run 'make dkms_install' now?"; then
      run_cmd "make -C /tmp/rtl8812au.install dkms_install"
      echo "[INFO] Driver install finished. Reboot is recommended before AP use."
    else
      echo "[INFO] Skipped make dkms_install. You can run it manually in /tmp/rtl8812au.install"
    fi
  else
    echo "[INFO] Skipped optional Realtek driver helper"
  fi

  pause_step "Step 6/6: final quick capability check (iw list)"
  run_cmd "iw list | sed -n '/Supported interface modes:/,/Band 1/p' || true"

  echo
  echo "[DONE] Setup assistant completed"
  echo "[NEXT] Run AP mode, for example:"
  echo "       sudo ./simpleap.sh wlan0 eth0 PentestAP StrongPass123 --mode compat --channel 1"
  exit 0
}

if [[ "${1:-}" == "--install" ]]; then
  run_install
fi

if [[ "${1:-}" == "--cleanup" ]]; then
  shift
  run_cleanup "$@"
fi

validate_ip(){
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.'
  local -a octets
  read -r -a octets <<< "$ip"
  (( ${#octets[@]} == 4 )) || return 1
  local o
  for o in "${octets[@]}"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
}

[[ $# -ge 1 && ( "${1:-}" == "-h" || "${1:-}" == "--help" ) ]] && { usage; exit 0; }
[[ $# -lt 4 ]] && { usage; exit 1; }

WIFI_IF="$1"; shift
UP_IF="$1";   shift
SSID="$1";    shift
PSK="$1";     shift

CHANNEL=1
SUBNET="10.10.10.0/24"
GATEWAY="10.10.10.1"
DHCP_START="10.10.10.50"
DHCP_END="10.10.10.150"
MODE="compat"
COUNTRY="CZ"
DEBUG=0

FORWARDS=()
LEASES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --channel|-c)              CHANNEL="${2?}"; shift 2 ;;
    --subnet)                  SUBNET="${2?}"; shift 2 ;;
    --gateway)                 GATEWAY="${2?}"; shift 2 ;;
    --dhcp-start|--dhcpstart)  DHCP_START="${2?}"; shift 2 ;;
    --dhcp-end|--dhcpend)      DHCP_END="${2?}"; shift 2 ;;
    --mode)                    MODE="${2?}"; shift 2 ;;
    --country)                 COUNTRY="${2?}"; shift 2 ;;
    --forward)                 FORWARDS+=("${2?}"); shift 2 ;;
    --lease)                   LEASES+=("${2?}"); shift 2 ;;
    --debug)                   DEBUG=1; shift ;;
    -h|--help)                 usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $(id -u) -eq 0 ]] || die "run as root"
for cmd in ip iw hostapd dnsmasq iptables ss; do command -v "$cmd" >/dev/null || die "missing: $cmd"; done
ip link show "$WIFI_IF" >/dev/null 2>&1 || die "wifi IF '$WIFI_IF' not found"
ip link show "$UP_IF"   >/dev/null 2>&1 || die "uplink IF '$UP_IF' not found"
(( ${#PSK} >= 8 && ${#PSK} <= 63 )) || die "WPA2 pass must be 8..63 chars"
[[ "$MODE" == "normal" || "$MODE" == "compat" ]] || die "mode must be normal|compat"
(( CHANNEL >= 1 && CHANNEL <= 13 )) || die "channel must be 1..13"
validate_ip "$GATEWAY" || die "invalid gateway IP: $GATEWAY"
validate_ip "$DHCP_START" || die "invalid DHCP start IP: $DHCP_START"
validate_ip "$DHCP_END" || die "invalid DHCP end IP: $DHCP_END"

if [[ "$SUBNET" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3})/([0-9]+)$ ]]; then
  PREFIX="${BASH_REMATCH[3]}"
else
  die "SUBNET must be CIDR like 10.10.10.0/24"
fi
(( PREFIX >= 1 && PREFIX <= 30 )) || die "bad prefix $PREFIX"

prefix_to_mask(){ local p=$1 m=0 i; for ((i=0;i<32;i++)); do (( i<p )) && m=$((m | (1<<(31-i)))); done;
  printf "%d.%d.%d.%d" $(( (m>>24)&255 )) $(( (m>>16)&255 )) $(( (m>>8)&255 )) $(( m&255 )); }
NETMASK="$(prefix_to_mask "$PREFIX")"

RUNID="$(date +%Y%m%d_%H%M%S)_$$"
RUNDIR="$(mktemp -d "/tmp/simple_ap.${WIFI_IF}.${RUNID}.XXXX")"
HCONF="${RUNDIR}/hostapd.conf"; DCONF="${RUNDIR}/dnsmasq.conf"
HLOG="${RUNDIR}/hostapd.log";   DLOG="${RUNDIR}/dnsmasq.log"
LEASEFILE="${RUNDIR}/dnsmasq.leases"; CTRL_DIR="${RUNDIR}/hostapd_ctrl"

NM_UNMANAGE_REVERT=0
ORIG_FORWARD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
HOSTAPD_PID=; DNSMASQ_PID=; TAIL1_PID=; TAIL2_PID=
MONITOR_PID=
SHUTDOWN_REQUESTED=0

cleanup(){
  set +e
  echo -e "\n[*] cleanup"
  SHUTDOWN_REQUESTED=1
  [[ -n "${MONITOR_PID}" ]] && kill "${MONITOR_PID}" 2>/dev/null || true
  [[ -n "${TAIL1_PID}" ]] && kill "${TAIL1_PID}" 2>/dev/null || true
  [[ -n "${TAIL2_PID}" ]] && kill "${TAIL2_PID}" 2>/dev/null || true
  [[ -n "${HOSTAPD_PID}" ]] && kill "${HOSTAPD_PID}" 2>/dev/null || true
  [[ -n "${DNSMASQ_PID}" ]] && kill "${DNSMASQ_PID}" 2>/dev/null || true
  sleep 0.2
  [[ -n "${HOSTAPD_PID}" ]] && kill -9 "${HOSTAPD_PID}" 2>/dev/null || true
  [[ -n "${DNSMASQ_PID}" ]] && kill -9 "${DNSMASQ_PID}" 2>/dev/null || true

  iptables -D INPUT -i "$WIFI_IF" -s "$SUBNET" -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p udp --dport 67 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p udp --dport 68 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p icmp -j ACCEPT 2>/dev/null || true
  iptables -D OUTPUT -o "$WIFI_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WIFI_IF" -o "$UP_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$UP_IF"  -o "$WIFI_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WIFI_IF" -o "$WIFI_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -t nat -D POSTROUTING -o "$UP_IF" -j MASQUERADE 2>/dev/null || true
  if [[ -s "${RUNDIR}/fw.rules" ]]; then
    while read -r line; do
      iptables $line 2>/dev/null || true
    done < <(tac "${RUNDIR}/fw.rules")
  fi

  sysctl -q net.ipv4.ip_forward="$ORIG_FORWARD" || true
  ip addr flush dev "$WIFI_IF" 2>/dev/null || true
  iw dev "$WIFI_IF" set type managed 2>/dev/null || true
  ip link set "$WIFI_IF" down 2>/dev/null || true
  if command -v nmcli >/dev/null 2>&1 && [[ $NM_UNMANAGE_REVERT -eq 1 ]]; then
    nmcli dev set "$WIFI_IF" managed yes >/dev/null 2>&1 || true
  fi
  echo "[*] logs in ${RUNDIR}"
}
trap cleanup INT TERM EXIT

echo "[*] run dir: ${RUNDIR}"
iw reg set "$COUNTRY" 2>/dev/null || true
if command -v nmcli >/dev/null 2>&1; then
  nmcli dev set "$WIFI_IF" managed no >/dev/null 2>&1 && NM_UNMANAGE_REVERT=1 || true
fi
pgrep -af "wpa_supplicant.*${WIFI_IF}" | awk '{print $1}' | xargs -r kill || true

echo "[*] configuring ${WIFI_IF} (ch ${CHANNEL}, mode ${MODE}, country ${COUNTRY})"
ip link set "$WIFI_IF" down
iw dev "$WIFI_IF" set type __ap || true
ip addr flush dev "$WIFI_IF"
ip addr add "${GATEWAY}/${PREFIX}" dev "$WIFI_IF"
ip link set "$WIFI_IF" up
iw dev "$WIFI_IF" set power_save off 2>/dev/null || true

sysctl -q net.ipv4.ip_forward=1

iptables -C INPUT -i "$WIFI_IF" -s "$SUBNET" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i "$WIFI_IF" -s "$SUBNET" -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p udp --dport 67 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i "$WIFI_IF" -p udp --dport 67 -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p udp --dport 68 -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -i "$WIFI_IF" -p udp --dport 68 -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -i "$WIFI_IF" -p udp --dport 53 -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -i "$WIFI_IF" -p tcp --dport 53 -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p icmp -j ACCEPT 2>/dev/null || iptables -I INPUT 5 -i "$WIFI_IF" -p icmp -j ACCEPT
iptables -C OUTPUT -o "$WIFI_IF" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o "$WIFI_IF" -j ACCEPT
iptables -C FORWARD -i "$WIFI_IF" -o "$UP_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WIFI_IF" -o "$UP_IF" -j ACCEPT
iptables -C FORWARD -i "$UP_IF"  -o "$WIFI_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$UP_IF"  -o "$WIFI_IF" -j ACCEPT
iptables -C FORWARD -i "$WIFI_IF" -o "$WIFI_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WIFI_IF" -o "$WIFI_IF" -j ACCEPT
iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -C POSTROUTING -o "$UP_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$UP_IF" -j MASQUERADE

mkdir -p "$CTRL_DIR"
cat > "$HCONF" <<EOF
interface=${WIFI_IF}
driver=nl80211
ssid=${SSID}
country_code=${COUNTRY}
ieee80211d=1
hw_mode=g
channel=${CHANNEL}
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=${PSK}
wpa_pairwise=CCMP
rsn_pairwise=CCMP
ap_isolate=0
obss_interval=0
dtim_period=1
ap_max_inactivity=900
disassoc_low_ack=0
ctrl_interface=${CTRL_DIR}
logger_stdout=-1
logger_stdout_level=2
logger_syslog=-1
logger_syslog_level=2
EOF
if [[ "$MODE" == "compat" ]]; then
  {
    echo "ieee80211n=0"
    echo "wmm_enabled=0"
    echo "ieee80211w=0"
  } >> "$HCONF"
else
  {
    echo "wmm_enabled=1"
    echo "ieee80211n=1"
    echo "ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]"
    echo "ieee80211w=0"
  } >> "$HCONF"
fi

{
  echo "interface=${WIFI_IF}"
  echo "bind-interfaces"
  echo "listen-address=${GATEWAY}"
  echo "dhcp-authoritative"
  echo "log-dhcp"
  echo "dhcp-broadcast"
  echo "dhcp-range=${DHCP_START},${DHCP_END},${NETMASK},12h"
  echo "dhcp-option=option:router,${GATEWAY}"
  echo "dhcp-option=option:dns-server,${GATEWAY}"
  for entry in "${LEASES[@]}"; do
    if [[ "$entry" =~ ^([0-9a-fA-F:]{17})=([0-9]{1,3}(\.[0-9]{1,3}){3})$ ]]; then
      echo "dhcp-host=${BASH_REMATCH[1]},${BASH_REMATCH[2]}"
    else
      echo "WARN: ignoring bad --lease '$entry'" >&2
    fi
  done
  echo "dhcp-leasefile=${LEASEFILE}"
  echo "log-facility=${DLOG}"
} > "$DCONF"

: > "$HLOG"; : > "$DLOG"; : > "$LEASEFILE"; chmod 600 "$HLOG" "$DLOG" "$LEASEFILE" || true

stale_pids=$(ss -Hulpn | awk -v gw="$GATEWAY" '$5 ~ ("^"gw":(53|67|68)$") {print $7}' | sed 's/,.*//' | cut -d= -f2 | sort -u)
[[ -n "$stale_pids" ]] && { echo "[*] reaping stale listeners on ${GATEWAY}:{53,67,68}: $stale_pids"; kill $stale_pids 2>/dev/null || true; sleep 0.2; }

echo "[*] starting dnsmasq -> ${DLOG}"
dnsmasq --conf-file="${DCONF}" --no-daemon >> "${DLOG}" 2>&1 & DNSMASQ_PID=$!
sleep 0.3; kill -0 "$DNSMASQ_PID" 2>/dev/null || die "dnsmasq failed (see ${DLOG})"

echo "[*] starting hostapd -> ${HLOG}"
hostapd "${HCONF}" >> "${HLOG}" 2>&1 & HOSTAPD_PID=$!
sleep 0.6; kill -0 "$HOSTAPD_PID" 2>/dev/null || die "hostapd failed (see ${HLOG})"

touch "${RUNDIR}/fw.rules"
for spec in "${FORWARDS[@]}"; do
  if [[ ! "$spec" =~ ^(tcp|udp):([0-9]{1,5})=(.+)$ ]]; then
    echo "WARN: bad --forward '$spec' (format: tcp|udp:PORT=DSTPORT or tcp|udp:PORT=DSTIP:DSTPORT)" >&2; continue
  fi
  proto="${BASH_REMATCH[1]}"; inport="${BASH_REMATCH[2]}"; right="${BASH_REMATCH[3]}"
  [[ $inport -ge 1 && $inport -le 65535 ]] || { echo "WARN: --forward $spec (bad inport)"; continue; }

  dstip=""; dstport=""
  if [[ "$right" =~ ^([0-9]{1,5})$ ]]; then
    dstport="${BASH_REMATCH[1]}"
  elif [[ "$right" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})$ ]]; then
    dstip="${BASH_REMATCH[1]}"; dstport="${BASH_REMATCH[3]}"
  else
    echo "WARN: --forward '$spec' requires DSTPORT or DSTIP:DSTPORT"; continue
  fi
  [[ $dstport -ge 1 && $dstport -le 65535 ]] || { echo "WARN: --forward $spec (bad dstport)"; continue; }

  if [[ -z "$dstip" || "$dstip" == "127.0.0.1" || "$dstip" == "$GATEWAY" ]]; then
    if ! iptables -t nat -C PREROUTING -i "$WIFI_IF" -p "$proto" --dport "$inport" -j REDIRECT --to-ports "$dstport" 2>/dev/null; then
      iptables -t nat -A PREROUTING -i "$WIFI_IF" -p "$proto" --dport "$inport" -j REDIRECT --to-ports "$dstport"
      echo "-t nat -D PREROUTING -i $WIFI_IF -p $proto --dport $inport -j REDIRECT --to-ports $dstport" >> "${RUNDIR}/fw.rules"
    fi
    echo "[*] forward: $proto:$inport -> REDIRECT local:$dstport"
  else
    if ! iptables -t nat -C PREROUTING -i "$WIFI_IF" -p "$proto" --dport "$inport" -j DNAT --to-destination "$dstip:$dstport" 2>/dev/null; then
      iptables -t nat -A PREROUTING -i "$WIFI_IF" -p "$proto" --dport "$inport" -j DNAT --to-destination "$dstip:$dstport"
      echo "-t nat -D PREROUTING -i $WIFI_IF -p $proto --dport $inport -j DNAT --to-destination $dstip:$dstport" >> "${RUNDIR}/fw.rules"
    fi
    echo "[*] forward: $proto:$inport -> DNAT ${dstip}:${dstport}"
  fi
done

echo
echo "[*] AP '${SSID}' up on ${WIFI_IF} (2.4 GHz ch ${CHANNEL}, mode ${MODE}, country ${COUNTRY})"
echo "[*] logs: ${HLOG}, ${DLOG} ; leases: ${LEASEFILE}"
[[ ${#FORWARDS[@]} -gt 0 ]] && echo "[*] forwards: ${FORWARDS[*]}"
echo "[*] monitoring enabled - services auto-restart on failure"
echo "[*] Live logs below (Ctrl+C to stop & cleanup)…"
echo "----- hostapd -----"
tail -n 80 -F "${HLOG}" & TAIL1_PID=$!
echo "----- dnsmasq -----"
tail -n 80 -F "${DLOG}" & TAIL2_PID=$!

monitor_services(){
  while [[ $SHUTDOWN_REQUESTED -eq 0 ]]; do
    sleep 2

    if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
      echo -e "\n[!] hostapd crashed, restarting…" >&2
      sleep 0.5
      hostapd "${HCONF}" >> "${HLOG}" 2>&1 & HOSTAPD_PID=$!
      sleep 1
      if kill -0 "$HOSTAPD_PID" 2>/dev/null; then
        echo "[+] hostapd restarted (PID: $HOSTAPD_PID)" >&2
      else
        echo "[ERROR] hostapd restart failed" >&2
      fi
    fi

    if ! kill -0 "$DNSMASQ_PID" 2>/dev/null; then
      echo -e "\n[!] dnsmasq crashed, restarting…" >&2
      sleep 0.5
      stale_pids=$(ss -Hulpn 2>/dev/null | awk -v gw="$GATEWAY" '$5 ~ ("^"gw":(53|67|68)$") {print $7}' | sed 's/,.*//' | cut -d= -f2 | sort -u)
      [[ -n "$stale_pids" ]] && kill $stale_pids 2>/dev/null || true
      sleep 0.2
      dnsmasq --conf-file="${DCONF}" --no-daemon >> "${DLOG}" 2>&1 & DNSMASQ_PID=$!
      sleep 0.5
      if kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        echo "[+] dnsmasq restarted (PID: $DNSMASQ_PID)" >&2
      else
        echo "[ERROR] dnsmasq restart failed" >&2
      fi
    fi
  done
}

monitor_services & MONITOR_PID=$!
wait
