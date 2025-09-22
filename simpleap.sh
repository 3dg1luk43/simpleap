#!/usr/bin/env bash
# simple_ap.sh — 2.4GHz WPA2 AP for pentesting; hostapd+dnsmasq; iptables NAT/filters; logs; Ctrl+C cleanup
# Positional: WIFI_IF UPLINK_IF SSID WPA2_PSK
# Named:
#   --channel N               (default: 1)
#   --subnet CIDR             (default: 10.10.10.0/24)
#   --gateway IP              (default: 10.10.10.1)
#   --dhcp-start IP           (default: 10.10.10.50)
#   --dhcp-end IP             (default: 10.10.10.150)
#   --mode normal|compat      (default: compat)  # compat = 11n off, WMM off, PMF off
#   --country CC              (default: CZ)
#   --forward SPEC            (repeatable)       # tcp|udp:INPORT->DSTPORT  or  tcp|udp:INPORT->DSTIP:DSTPORT
#   --lease MAC=IP            (repeatable)       # static DHCP lease
#
# Notes:
#   - All inbound from WLAN to router is ACCEPTed (host services on 10.10.10.1:*).
#   - Clients can talk to each other (no AP isolation).
#   - Forward rules apply to traffic *from WLAN clients* (PREROUTING -i WIFI_IF).
#   - Transparent HTTP/HTTPS interception to local Burp: --forward tcp:80->8080 --forward tcp:443->8080
set -euo pipefail

usage() { sed -n '1,70p' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,60p'; }

die(){ echo "ERROR: $*" >&2; exit 1; }

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

FORWARDS=()     # strings like tcp:80->8080 or tcp:80->10.10.10.60:8080
LEASES=()       # strings like aa:bb:cc:dd:ee:ff=10.10.10.60

# parse named options
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
    -h|--help)                 usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

# sanity
[[ $(id -u) -eq 0 ]] || die "run as root"
for cmd in ip iw hostapd dnsmasq iptables ss; do command -v "$cmd" >/dev/null || die "missing: $cmd"; done
ip link show "$WIFI_IF" >/dev/null 2>&1 || die "wifi IF '$WIFI_IF' not found"
ip link show "$UP_IF"   >/dev/null 2>&1 || die "uplink IF '$UP_IF' not found"
(( ${#PSK} >= 8 && ${#PSK} <= 63 )) || die "WPA2 pass must be 8..63 chars"
[[ "$MODE" == "normal" || "$MODE" == "compat" ]] || die "mode must be normal|compat"

# parse CIDR
if [[ "$SUBNET" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3})/([0-9]+)$ ]]; then
  NETBASE="${BASH_REMATCH[1]}"
  PREFIX="${BASH_REMATCH[3]}"
else die "SUBNET must be CIDR like 10.10.10.0/24"; fi
(( PREFIX >= 1 && PREFIX <= 30 )) || die "bad prefix $PREFIX"

prefix_to_mask(){ local p=$1 m=0 i; for ((i=0;i<32;i++)); do (( i<p )) && m=$((m | (1<<(31-i)))); done;
  printf "%d.%d.%d.%d" $(( (m>>24)&255 )) $(( (m>>16)&255 )) $(( (m>>8)&255 )) $(( m&255 )); }
NETMASK="$(prefix_to_mask "$PREFIX")"

# run dir
RUNID="$(date +%Y%m%d_%H%M%S)_$$"
RUNDIR="$(mktemp -d "/tmp/simple_ap.${WIFI_IF}.${RUNID}.XXXX")"
HCONF="${RUNDIR}/hostapd.conf"; DCONF="${RUNDIR}/dnsmasq.conf"
HLOG="${RUNDIR}/hostapd.log";   DLOG="${RUNDIR}/dnsmasq.log"
LEASEFILE="${RUNDIR}/dnsmasq.leases"; CTRL_DIR="${RUNDIR}/hostapd_ctrl"

NM_UNMANAGE_REVERT=0
ORIG_FORWARD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
HOSTAPD_PID=; DNSMASQ_PID=; TAIL1_PID=; TAIL2_PID=

cleanup(){
  set +e
  echo -e "\n[*] cleanup"
  [[ -n "${TAIL1_PID}" ]] && kill "${TAIL1_PID}" 2>/dev/null || true
  [[ -n "${TAIL2_PID}" ]] && kill "${TAIL2_PID}" 2>/dev/null || true
  [[ -n "${HOSTAPD_PID}" ]] && kill "${HOSTAPD_PID}" 2>/dev/null || true
  [[ -n "${DNSMASQ_PID}" ]] && kill "${DNSMASQ_PID}" 2>/dev/null || true
  sleep 0.2
  [[ -n "${HOSTAPD_PID}" ]] && kill -9 "${HOSTAPD_PID}" 2>/dev/null || true
  [[ -n "${DNSMASQ_PID}" ]] && kill -9 "${DNSMASQ_PID}" 2>/dev/null || true

  # remove iptables rules we added
  # INPUT accepts (broad accept + DHCP/DNS/ICMP)
  iptables -D INPUT -i "$WIFI_IF" -s "$SUBNET" -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p udp --dport 67 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p udp --dport 68 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
  iptables -D INPUT -i "$WIFI_IF" -p icmp -j ACCEPT 2>/dev/null || true
  # OUTPUT accept on wlan0
  iptables -D OUTPUT -o "$WIFI_IF" -j ACCEPT 2>/dev/null || true
  # FORWARD accepts
  iptables -D FORWARD -i "$WIFI_IF" -o "$UP_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$UP_IF"  -o "$WIFI_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WIFI_IF" -o "$WIFI_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  # NAT (MASQUERADE)
  iptables -t nat -D POSTROUTING -o "$UP_IF" -j MASQUERADE 2>/dev/null || true
  # DNAT/REDIRECT forwards
  if [[ -s "${RUNDIR}/fw.rules" ]]; then
    while read -r line; do
      # shellcheck disable=SC2086
      iptables $line 2>/dev/null || true
    done < <(tac "${RUNDIR}/fw.rules")   # delete in reverse order
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
trap cleanup INT TERM

echo "[*] run dir: ${RUNDIR}"
# region + iface
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

# routing + firewall
sysctl -q net.ipv4.ip_forward=1

# INPUT: accept everything from WLAN to router (services on 10.10.10.1)
iptables -C INPUT -i "$WIFI_IF" -s "$SUBNET" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i "$WIFI_IF" -s "$SUBNET" -j ACCEPT
# Always permit DHCP/DNS/ICMP explicitly
iptables -C INPUT -i "$WIFI_IF" -p udp --dport 67 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i "$WIFI_IF" -p udp --dport 67 -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p udp --dport 68 -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -i "$WIFI_IF" -p udp --dport 68 -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -i "$WIFI_IF" -p udp --dport 53 -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -i "$WIFI_IF" -p tcp --dport 53 -j ACCEPT
iptables -C INPUT -i "$WIFI_IF" -p icmp -j ACCEPT 2>/dev/null || iptables -I INPUT 5 -i "$WIFI_IF" -p icmp -j ACCEPT
# OUTPUT: allow router-initiated to clients
iptables -C OUTPUT -o "$WIFI_IF" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o "$WIFI_IF" -j ACCEPT
# FORWARD: both ways (and hairpin on wlan0→wlan0 for DNAT to clients)
iptables -C FORWARD -i "$WIFI_IF" -o "$UP_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WIFI_IF" -o "$UP_IF" -j ACCEPT
iptables -C FORWARD -i "$UP_IF"  -o "$WIFI_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$UP_IF"  -o "$WIFI_IF" -j ACCEPT
iptables -C FORWARD -i "$WIFI_IF" -o "$WIFI_IF" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WIFI_IF" -o "$WIFI_IF" -j ACCEPT
iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
# NAT
iptables -t nat -C POSTROUTING -o "$UP_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$UP_IF" -j MASQUERADE

# hostapd
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

# dnsmasq
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
    # format MAC=IP
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

# kill stale listeners on 10.10.10.1:{53,67,68}
stale_pids=$(ss -Hulpn | awk -v gw="$GATEWAY" '$5 ~ ("^"gw":(53|67|68)$") {print $7}' | sed 's/,.*//' | cut -d= -f2 | sort -u)
[[ -n "$stale_pids" ]] && { echo "[*] reaping stale listeners on ${GATEWAY}:{53,67,68}: $stale_pids"; kill $stale_pids 2>/dev/null || true; sleep 0.2; }

echo "[*] starting dnsmasq -> ${DLOG}"
dnsmasq --conf-file="${DCONF}" --no-daemon >> "${DLOG}" 2>&1 & DNSMASQ_PID=$!
sleep 0.3; kill -0 "$DNSMASQ_PID" 2>/dev/null || die "dnsmasq failed (see ${DLOG})"

echo "[*] starting hostapd -> ${HLOG}"
hostapd "${HCONF}" >> "${HLOG}" 2>&1 & HOSTAPD_PID=$!
sleep 0.6; kill -0 "$HOSTAPD_PID" 2>/dev/null || die "hostapd failed (see ${HLOG})"

# parse and install forwards
touch "${RUNDIR}/fw.rules"  # store deletions
for spec in "${FORWARDS[@]}"; do
  # forms: proto:inport->dstport   OR   proto:inport->dstip:dstport
  if [[ ! "$spec" =~ ^(tcp|udp):([0-9]{1,5})->(.+)$ ]]; then
    echo "WARN: bad --forward '$spec' (ignored)" >&2; continue
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
    # REDIRECT to local port
    if iptables -t nat -C PREROUTING -i "$WIFI_IF" -p "$proto" --dport "$inport" -j REDIRECT --to-ports "$dstport" 2>/dev/null; then
      :
    else
      iptables -t nat -A PREROUTING -i "$WIFI_IF" -p "$proto" --dport "$inport" -j REDIRECT --to-ports "$dstport"
      echo "-t nat -D PREROUTING -i $WIFI_IF -p $proto --dport $inport -j REDIRECT --to-ports $dstport" >> "${RUNDIR}/fw.rules"
    fi
    echo "[*] forward: $proto:$inport -> REDIRECT local:$dstport"
  else
    # DNAT to dstip:dstport
    if iptables -t nat -C PREROUTING -i "$WIFI_IF" -p "$proto" --dport "$inport" -j DNAT --to-destination "$dstip:$dstport" 2>/dev/null; then
      :
    else
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
echo "[*] Live logs below (Ctrl+C to stop & cleanup)…"
echo "----- hostapd -----"
tail -n 80 -F "${HLOG}" & TAIL1_PID=$!
echo "----- dnsmasq -----"
tail -n 80 -F "${DLOG}" & TAIL2_PID=$!
wait