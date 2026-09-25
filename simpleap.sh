#!/usr/bin/env bash
# simple_ap.sh — 2.4GHz WPA2 AP for pentesting; hostapd+dnsmasq; iptables NAT/filters; logs; Ctrl+C cleanup
# Positional: WIFI_IF UPLINK_IF SSID WPA2_PSK
# Utility mode:
#   --install                Automatic setup: deps + kernel-appropriate Wi-Fi driver (no prompts)
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
#   --proxy-port N           (default: 8080)    # transparent-proxy target (Burp), toggled live with 'p'
#   --proxy-ports "P.."      (default: "80 443")# client TCP dports redirected when proxy is ON
#   --proxy-on                                  # start with the proxy redirect enabled (default off)
#   --debug                   (optional)
# Live hotkeys (when run in a terminal): p = toggle proxy on/off,  q = quit
#   proxy ON  -> client tcp {proxy-ports} REDIRECT to local :proxy-port (Burp)
#   proxy OFF -> client traffic goes straight to the Internet (NAT only)
set -euo pipefail

usage() { sed -n '1,70p' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,60p'; }
die(){ echo "ERROR: $*" >&2; exit 1; }
debug(){ [[ ${DEBUG:-0} -eq 1 ]] && echo "[DEBUG] $*" >&2 || true; }

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

# --- native nftables firewall support ---------------------------------------
# Some hosts (Kali/Debian with nftables.service, etc.) run a *native* nftables
# firewall in `table inet filter` with a base chain on the input/forward hook and
# policy drop. That base chain co-exists with the iptables (ip filter) chain this
# script edits, and BOTH run on each packet - so an iptables ACCEPT is overridden
# by the inet-filter drop policy (symptom: client associates but never gets DHCP,
# and no forwarding). These helpers add matching accepts into that table and track
# them by handle for clean removal.
NFT_ADDED_RULES=()

# True if a native `inet filter` firewall base chain on the given hook drops by default.
nft_native_drop(){
  local chain="$1"
  command -v nft >/dev/null 2>&1 || return 1
  nft list chain inet filter "$chain" 2>/dev/null | grep -q 'hook '"$chain"'.*policy drop'
}

# Add a rule to inet filter and remember its handle for cleanup. Args: chain expr...
nft_add(){
  local chain="$1"; shift
  local out h
  out="$(nft --echo --handle add rule inet filter "$chain" "$@" 2>/dev/null)" || return 1
  h="$(printf '%s\n' "$out" | sed -n 's/.*# handle \([0-9][0-9]*\).*/\1/p' | tail -1)"
  [[ -n "$h" ]] && NFT_ADDED_RULES+=("$chain $h")
  print_cmd nft add rule inet filter "$chain" "$@"
}

# Remove every inet-filter input/forward rule referencing the given interface name
# (used by --cleanup, which does not have the tracked handles from a live run).
nft_purge_wifi(){
  local wifi="$1" chain h
  command -v nft >/dev/null 2>&1 || return 0
  for chain in input forward; do
    while read -r h; do
      [[ -z "$h" ]] && continue
      echo "[CMD] nft delete rule inet filter $chain handle $h"
      nft delete rule inet filter "$chain" handle "$h" 2>/dev/null || true
    done < <(nft -a list chain inet filter "$chain" 2>/dev/null | grep "\"$wifi\"" | grep -oE 'handle [0-9]+' | awk '{print $2}')
  done
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

  echo "[STEP] Remove native nftables (inet filter) accepts for wifi interface"
  nft_purge_wifi "$wifi_if"

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

# True if the given kernel ships an in-tree rtw88 driver for RTL88xxAU USB chips
# (RTL8811AU/8812AU/8814AU as used by Alfa AWUS036AC/ACS). Works on modern kernels
# (Kali >= 2025 / kernel >= ~6.x, incl. the 7.x series).
intree_au_supported(){
  local krel="$1"
  local d="/lib/modules/${krel}/kernel/drivers/net/wireless/realtek/rtw88"
  ls "$d"/rtw88_8812au.ko* "$d"/rtw88_8821au.ko* "$d"/rtw88_8814au.ko* 2>/dev/null | grep -q .
}

# Neutralize any modprobe blacklist that would stop the in-tree driver from binding
# (left behind by older out-of-tree DKMS installs).
unblacklist_intree(){
  local f matched=0
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    sed -i -E 's/^([[:space:]]*blacklist[[:space:]]+(rtw88[[:alnum:]_]*|rtl8xxxu).*)$/# disabled by simpleap: \1/' "$f"
    echo "[INFO] neutralized in-tree-driver blacklist in $f"
    matched=1
  done < <(grep -rslE '^[[:space:]]*blacklist[[:space:]]+(rtw88|rtl8xxxu)' /etc/modprobe.d/ 2>/dev/null || true)
  [[ $matched -eq 1 ]] && { run_cmd "depmod -a"; } || echo "[OK] no in-tree-driver blacklist present"
}

# Load the in-tree rtw88 USB stack (covers AWUS036AC = 8812AU, AWUS036ACS = 8811AU).
# Also persist AP-friendly tuning: deep power-save makes the adapter sleep and drop
# client data frames (symptom: associates + 4-way handshake OK, but no DHCP/data);
# USB-3 mode self-interferes on 2.4 GHz. Both are common causes of "connects but no IP".
load_rtw88(){
  local m conf=/etc/modprobe.d/rtw88-ap.conf
  if [[ ! -f "$conf" ]] || ! grep -q 'disable_lps_deep=Y' "$conf" 2>/dev/null; then
    cat > "$conf" <<'EOF'
# simpleap: AP-friendly tuning for rtw88 USB Realtek AU adapters
options rtw88_core disable_lps_deep=Y
options rtw88_usb switch_usb_mode=N
EOF
    echo "[OK] wrote $conf (disable_lps_deep=Y, switch_usb_mode=N)"
    # reload so the options take effect if the stack is already loaded
    if lsmod | grep -q '^rtw88_core'; then
      modprobe -r rtw88_8812au rtw88_8821au rtw88_8814au 2>/dev/null || true
      modprobe -r rtw88_8821a rtw88_8812a rtw88_8814a rtw88_88xxa rtw88_usb rtw88_core 2>/dev/null || true
    fi
  fi
  for m in rtw88_8812au rtw88_8821au rtw88_8814au; do
    if modprobe "$m" 2>/dev/null; then echo "[OK] loaded $m"; fi
  done
}

# Best-effort patches so the out-of-tree aircrack driver builds on modern kernels.
# Harmless on old kernels (ccflags-y has always worked; timer shims are version-guarded).
patch_outoftree_driver(){
  local src="$1"
  [[ -f "$src/Makefile" ]] || return 0
  # 1) kernel 7.x removed deprecated EXTRA_CFLAGS/EXTRA_LDFLAGS -> use supported names
  sed -i -E 's/\bEXTRA_CFLAGS\b/ccflags-y/g; s/\bEXTRA_LDFLAGS\b/ldflags-y/g' "$src/Makefile"
  # 2) drop the proprietary bridge/NAT extension (unneeded here; breaks on new kernels)
  sed -i -E 's/^CONFIG_BR_EXT[[:space:]]*=[[:space:]]*y/CONFIG_BR_EXT = n/' "$src/Makefile"
  # 3) legacy timer API removed in 6.15/6.16 -> shim onto the current API
  local hdr="$src/include/osdep_service_linux.h"
  if [[ -f "$hdr" ]] && ! grep -q 'simpleap timer compat' "$hdr"; then
    awk '
      /#include <linux\/version.h>/ && !done {
        print
        print "/* simpleap timer compat: 6.15 removed del_timer*, 6.16 removed from_timer */"
        print "#include <linux/timer.h>"
        print "#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0))"
        print "  #ifndef from_timer"
        print "    #define from_timer(a, b, c) timer_container_of(a, b, c)"
        print "  #endif"
        print "#endif"
        print "#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0))"
        print "  #ifndef del_timer_sync"
        print "    #define del_timer_sync(t) timer_delete_sync(t)"
        print "  #endif"
        print "  #ifndef del_timer"
        print "    #define del_timer(t) timer_delete(t)"
        print "  #endif"
        print "#endif"
        done=1; next
      }
      { print }
    ' "$hdr" > "$hdr.simpleap" && mv "$hdr.simpleap" "$hdr"
  fi
  echo "[INFO] applied modern-kernel compat patches to out-of-tree source"
}

# Build+install the out-of-tree aircrack-ng rtl8812au driver via DKMS (legacy fallback).
build_outoftree_driver(){
  local krel="$1"
  local src="/usr/src/rtl8812au.simpleap"
  run_cmd "apt-get install -y linux-headers-${krel} dkms git build-essential"
  run_cmd "rm -rf ${src}"
  run_cmd "git clone --depth 1 https://github.com/aircrack-ng/rtl8812au.git ${src}"
  patch_outoftree_driver "${src}"
  if make -C "${src}" dkms_install; then
    echo "[OK] out-of-tree driver installed via DKMS (reboot may be required)"
  else
    echo "[ERROR] out-of-tree driver build failed on kernel ${krel}."
    echo "[ERROR] Prefer a kernel with in-tree rtw88 (Kali >= 2025 / kernel >= ~6.x)."
    return 1
  fi
}

# Autodetect the running kernel and install the appropriate driver:
#   in-tree rtw88 if the kernel provides it (no build), else out-of-tree DKMS.
install_driver_auto(){
  local krel="$1"
  if intree_au_supported "$krel"; then
    echo "[INFO] kernel ${krel}: in-tree rtw88 supports RTL88xxAU (AWUS036AC/ACS) -> using it"
    unblacklist_intree
    load_rtw88
  else
    echo "[INFO] kernel ${krel}: no in-tree rtw88 AU support -> building out-of-tree DKMS driver"
    build_outoftree_driver "$krel"
  fi
}

# Fully automatic, non-interactive setup: deps + kernel-appropriate driver.
run_install(){
  [[ $(id -u) -eq 0 ]] || die "run installer as root (sudo ./simpleap.sh --install)"
  command -v apt-get >/dev/null || die "apt-get not found (installer supports Debian/Kali/Ubuntu)"

  local KREL; KREL="$(uname -r)"
  export DEBIAN_FRONTEND=noninteractive

  echo "[INFO] simpleap automated setup (non-interactive)"
  echo "[INFO] kernel: ${KREL}"

  echo "[STEP] 1/4 refresh package metadata"
  run_cmd "apt-get update -y -q"

  echo "[STEP] 2/4 install runtime + support packages"
  run_cmd "apt-get install -y hostapd dnsmasq iptables iproute2 iw tcpdump"

  echo "[STEP] 3/4 verify required tools"
  for cmd in ip iw hostapd dnsmasq iptables ss; do
    command -v "$cmd" >/dev/null || die "missing after install: $cmd"
    echo "[OK] $cmd"
  done

  echo "[STEP] 4/4 autodetect + install Wi-Fi driver"
  install_driver_auto "$KREL" || echo "[WARN] driver step did not complete cleanly (see messages above)"

  echo
  echo "[INFO] Wi-Fi interfaces detected:"
  iw dev 2>/dev/null | awk '/Interface/{print "       - "$2}' || true
  echo "[INFO] AP-mode capability (must list '* AP'):"
  iw list 2>/dev/null | sed -n '/Supported interface modes:/,/Band 1/p' | sed 's/^/       /' || true

  echo
  echo "[DONE] Setup complete"
  echo "[NEXT] Plug in the Wi-Fi adapter (if not already), then start the AP, e.g.:"
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
PROXY_PORT=8080          # transparent-proxy target (Burp), toggled live with 'p'
PROXY_PORTS="80 443"     # client TCP dports transparently redirected when proxy is ON
PROXY_ON=0               # runtime state of the transparent proxy toggle

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
    --proxy-port)              PROXY_PORT="${2?}"; shift 2 ;;
    --proxy-ports)             PROXY_PORTS="${2?}"; shift 2 ;;  # e.g. "80 443 8443"
    --proxy-on)                PROXY_ON=1; shift ;;             # start with redirect enabled
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
  for _nftrule in "${NFT_ADDED_RULES[@]:-}"; do
    [[ -z "$_nftrule" ]] && continue
    set -- $_nftrule   # chain handle
    nft delete rule inet filter "$1" handle "$2" 2>/dev/null || true
  done
  for _pp in ${PROXY_PORTS:-}; do
    while iptables -t nat -C PREROUTING -i "$WIFI_IF" -p tcp --dport "$_pp" -j REDIRECT --to-ports "${PROXY_PORT:-8080}" 2>/dev/null; do
      iptables -t nat -D PREROUTING -i "$WIFI_IF" -p tcp --dport "$_pp" -j REDIRECT --to-ports "${PROXY_PORT:-8080}" 2>/dev/null || break
    done
  done
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

# If a native nftables firewall (inet filter) with a drop policy is active, the
# iptables rules above are silently overridden by it. Add matching accepts there.
if command -v nft >/dev/null 2>&1 && nft list table inet filter >/dev/null 2>&1; then
  if nft_native_drop input; then
    echo "[*] native nftables firewall detected (inet filter/input drop) - adding AP accepts"
    nft_add input iifname "$WIFI_IF" udp dport 67 accept
    nft_add input iifname "$WIFI_IF" udp dport 68 accept
    nft_add input iifname "$WIFI_IF" udp dport 53 accept
    nft_add input iifname "$WIFI_IF" tcp dport 53 accept
    nft_add input iifname "$WIFI_IF" ip protocol icmp accept
    nft_add input iifname "$WIFI_IF" ip saddr "$SUBNET" accept
  fi
  if nft_native_drop forward; then
    echo "[*] native nftables firewall (inet filter/forward drop) - adding forwarding accepts"
    nft_add forward iifname "$WIFI_IF" oifname "$UP_IF" accept
    nft_add forward iifname "$UP_IF" oifname "$WIFI_IF" ct state established,related accept
    nft_add forward iifname "$WIFI_IF" oifname "$WIFI_IF" accept
  fi
fi

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

# --- transparent proxy toggle (live hotkey 'p') -----------------------------
# ON  = client tcp {$PROXY_PORTS} REDIRECT to local :$PROXY_PORT (Burp/mitmproxy).
# OFF = client traffic goes straight out via NAT. Toggled on the fly with 'p'.
proxy_apply(){   # $1 = on|off
  local p
  for p in $PROXY_PORTS; do
    if [[ "$1" == "on" ]]; then
      iptables -t nat -C PREROUTING -i "$WIFI_IF" -p tcp --dport "$p" -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null \
        || iptables -t nat -A PREROUTING -i "$WIFI_IF" -p tcp --dport "$p" -j REDIRECT --to-ports "$PROXY_PORT"
    else
      while iptables -t nat -C PREROUTING -i "$WIFI_IF" -p tcp --dport "$p" -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null; do
        iptables -t nat -D PREROUTING -i "$WIFI_IF" -p tcp --dport "$p" -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null || break
      done
    fi
  done
  # drop existing client conntrack so the new routing applies to live flows immediately
  command -v conntrack >/dev/null 2>&1 && conntrack -D -s "$SUBNET" >/dev/null 2>&1 || true
}

proxy_toggle(){
  if [[ $PROXY_ON -eq 1 ]]; then
    proxy_apply off; PROXY_ON=0
    echo "[PROXY] OFF -> ${WIFI_IF} clients go straight to Internet (NAT only)"
  else
    proxy_apply on;  PROXY_ON=1
    echo "[PROXY] ON  -> ${WIFI_IF} clients tcp {${PROXY_PORTS}} REDIRECT to :${PROXY_PORT}"
  fi
}

# apply the requested initial state (default OFF, or ON via --proxy-on)
if [[ $PROXY_ON -eq 1 ]]; then
  proxy_apply on
  echo "[*] transparent proxy START state: ON (tcp {${PROXY_PORTS}} -> :${PROXY_PORT})"
fi

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

# Interactive hotkeys when attached to a TTY; otherwise just wait (background/CI safe).
if [[ -t 0 ]]; then
  echo "[*] hotkeys:  p = toggle proxy redirect (tcp {${PROXY_PORTS}} -> :${PROXY_PORT})   q = quit"
  while [[ $SHUTDOWN_REQUESTED -eq 0 ]]; do
    if IFS= read -rsn1 -t 1 _key 2>/dev/null; then
      case "$_key" in
        p|P) proxy_toggle ;;
        q|Q) echo "[*] quit via hotkey"; break ;;
      esac
    fi
  done
else
  wait
fi
