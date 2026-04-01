# simple-ap (Kali-friendly Wi-Fi AP for mobile pentests)

`simpleap.sh` spins up a **2.4 GHz WPA2 AP** on Linux for mobile app/network testing. It’s built to be reliable on **Kali in a VM** with **Realtek AU** USB adapters (e.g. **AWUS036ACS**).

* **Open WLAN → router by default** (host services on `10.10.10.1:*` and reach clients from the router).
* **DHCP/DNS** via `dnsmasq`, **AP** via `hostapd`.
* **NAT + port forwards** via **iptables (iptables-nft)**; explicit `INPUT` rules so DHCP works even when the distro’s `INPUT` policy is `DROP`.
* **Transparent REDIRECT/DNAT** helpers for Burp or other tooling.
* **Non-destructive**: unique `/tmp` run dir, live logs, **Ctrl-C reverts** everything.
* **Compat mode** for flaky AP drivers (disables 11n/WMM/PMF).

---

## Driver setup (Realtek AU / Alfa AWUS on Kali 2024)

**Follow this guide exactly (credit to Sapsan & Janek):**
**[https://sapsan-sklep.pl/en/blogs/articles/alfa-awus-kali-linux-2024-fix-en](https://sapsan-sklep.pl/en/blogs/articles/alfa-awus-kali-linux-2024-fix-en)**

Kali 2024.x broke the “latest” 8812au driver for AWUS cards; the adapter associates but doesn’t see networks or won’t beacon. Fix = install **older** aircrack-ng 8812au driver at **commit `63cf0b4`**.

> **Do the steps in this order on the VM host OS:**

```bash
# 0) Update OS and reboot
sudo apt update
sudo apt upgrade -y
sudo reboot now
```

```bash
# 1) Prereqs
sudo apt install -y linux-headers-$(uname -r) dkms
dkms status    # note any 8812au versions present
```

```bash
# 2) Remove any existing 8812au DKMS modules (adjust version string if different)
sudo dkms uninstall 8812au/5.6.4.2_35491.20191025
sudo dkms remove    8812au/5.6.4.2_35491.20191025 --all
```

```bash
# 3) Get the aircrack-ng driver and pin to commit 63cf0b4 (on tag v5.6.4.2)
git clone -b v5.6.4.2 https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
git checkout 63cf0b4
```

```bash
# 4) Build & install via DKMS
sudo make dkms_install
sudo reboot now
```

After reboot, plug the AWUS and verify it enumerates, can scan, and supports **AP** mode:

```bash
ip link show
iw list | sed -n '/Supported interface modes:/,/Band 1/p'   # should include "AP"
```

> **Notes**
>
> * If you previously installed `realtek-rtl88xxau-dkms`, remove it before installing the pinned aircrack driver (to avoid module conflicts).
> * If you swap kernels, re-run `sudo make dkms_install`.

---

## Quick start

```bash
chmod +x simpleap.sh

# optional: run interactive installer first (pauses between steps)
sudo ./simpleap.sh --install

# Realtek/VM-friendly baseline: channel 1, compat mode, Burp on local :8080
sudo ./simpleap.sh wlan0 eth0 PentestAP StrongPass123 \
  --channel 1 --mode compat \
  --forward tcp:80=8080 \
  --forward tcp:443=8080
```

* SSID `PentestAP` on **2.4 GHz** ch 1.
* Clients get `10.10.10.0/24`; router is `10.10.10.1`.
* **HTTP/HTTPS from clients transparently redirected** to local `:8080` (Burp).
  Install Burp CA on devices if you intercept TLS.

Stop with **Ctrl-C** — rules and processes are removed.

---

## Interactive installer (`--install`)

You can run a guided setup assistant:

```bash
sudo ./simpleap.sh --install
```

What it does:

1. Installs runtime packages required by `simpleap.sh`.
2. Pauses before each logic step so output can be reviewed/intercepted.
3. Prints the exact command before it runs (`[CMD] ...`).
3. Asks approval before installing optional extras (not required for AP runtime), including:
  - `tcpdump` (troubleshooting)
  - `pipx` + `python3-venv` (preferred over direct `pip` for standalone Python CLI tools)
  - optional Realtek AU driver helper flow

Installer output is structured and explicit (`[STEP]`, `[INPUT]`, `[CMD]`, `[OK]`, `[INFO]`, `[DONE]`, `[NEXT]`).

> `pipx` is preferred for Python CLI tooling because system `pip` installs are increasingly restricted without virtual environments.

---

## Cleanup utility (`--cleanup`)

If a run crashes or leaves partial state, use the built-in comprehensive cleanup:

```bash
sudo ./simpleap.sh --cleanup
```

You can target non-default interfaces/subnet:

```bash
sudo ./simpleap.sh --cleanup --wifi-if wlan1 --uplink-if eth1 --subnet 10.20.30.0/24
```

What `--cleanup` does:

- Stops `hostapd` and `dnsmasq`
- Removes NAT PREROUTING REDIRECT/DNAT rules for the Wi-Fi interface
- Removes known INPUT/OUTPUT/FORWARD/MASQUERADE rules added by the script
- Flushes IP addresses on Wi-Fi interface, sets interface back to managed mode, sets it down
- Re-enables NetworkManager management for the Wi-Fi interface (if `nmcli` is available)
- Sets `net.ipv4.ip_forward=0`

Output is structured and shows exact commands before execution.

---

## Usage

```bash
sudo ./simpleap.sh WIFI_IF UPLINK_IF SSID WPA2_PSK \
  [--channel 1] [--subnet 10.10.10.0/24] [--gateway 10.10.10.1] \
  [--dhcp-start 10.10.10.50] [--dhcp-end 10.10.10.150] \
  [--mode normal|compat] [--country CZ] \
  [--debug] \
  [--forward SPEC]... \
  [--lease MAC=IP]...
```

**Required positionals**

* `WIFI_IF` – wireless NIC (e.g. `wlan0`)
* `UPLINK_IF` – internet uplink (e.g. `eth0`)
* `SSID` – network name
* `WPA2_PSK` – 8..63 chars

**Named options**

* `--channel N` – 2.4 GHz channel (default `1`)
* `--subnet CIDR` – default `10.10.10.0/24`
* `--gateway IP` – default `10.10.10.1`
* `--dhcp-start IP` / `--dhcp-end IP` – default `10.10.10.50`–`150`
* `--mode normal|compat` – **use `compat` for Realtek AU**
* `--country CC` – regdomain (default `CZ`)
* `--debug` – print debug messages to stderr
* `--forward SPEC` – port forward rule (below)
* `--lease MAC=IP` – pin client leases

**Logs** (tailed live & saved):
`/tmp/simpleap.<if>.<timestamp>.../{hostapd.log,dnsmasq.log,dnsmasq.leases}`

---

## Forwarding rules

`--forward` supports:

* `tcp|udp:INPORT=DSTPORT` → **REDIRECT** to local router (`10.10.10.1:DSTPORT`)
  e.g. `--forward tcp:80=8080`
* `tcp|udp:INPORT=DSTIP:DSTPORT` → **DNAT** to `DSTIP:DSTPORT`
  e.g. `--forward tcp:22=10.10.10.60:2222`

Applied to **client traffic arriving on `WIFI_IF`** (PREROUTING).
Hairpin `wlan0→wlan0` is allowed so DNAT to clients works.

---

## Static DHCP leases

```bash
--lease aa:bb:cc:dd:ee:ff=10.10.10.60
--lease 00:11:22:33:44:55=10.10.10.61
```

---

## What the script does

1. Sets regdomain, kills `wpa_supplicant` for `WIFI_IF`, unmanages it in NetworkManager.
2. Configures `WIFI_IF` to `__ap`, assigns `GATEWAY/PREFIX`, brings it up.
3. Enables `net.ipv4.ip_forward=1`.
4. **iptables (iptables-nft)**:

   * **INPUT:** accept **all** from `WIFI_IF` (router services reachable), plus explicit DHCP/DNS/ICMP accepts.
   * **OUTPUT:** accept to `WIFI_IF` (router→clients).
   * **FORWARD:** accept both directions and `wlan0→wlan0` (hairpin).
   * **NAT:** MASQUERADE on `UPLINK_IF`.
   * **PREROUTING NAT:** installs `--forward` REDIRECT/DNAT rules.
5. **dnsmasq:** binds to `GATEWAY` on `WIFI_IF`, authoritative DHCP/DNS, verbose logs.
6. **hostapd:** WPA2-PSK/CCMP on 2.4 GHz; **compat** disables 11n/WMM/PMF (most stable for AU).
7. Live tails both logs; **Ctrl-C** tears everything down.

---

## Requirements

* Root.
* `hostapd`, `dnsmasq`, `iptables`, `iw`, `ip`, `ss`, `tcpdump` (optional).
* Wi-Fi adapter supporting **AP** (`nl80211`).
  Targeted: **Realtek AWUS036ACS (8811/8812AU)** on **Kali VM** + VMware/VirtualBox.

Install on Kali:

```bash
sudo apt update
sudo apt install -y hostapd dnsmasq iptables tcpdump
# optional Python CLI tooling manager (preferred over plain pip):
sudo apt install -y pipx python3-venv
pipx ensurepath
# Driver: follow the Sapsan guide to install aircrack-ng rtl8812au @ commit 63cf0b4
```

---

## Troubleshooting

**Phone stuck on “Obtaining IP address”**
Use a second terminal:

```bash
ss -lupn 'sport = :67 or :68 or :53'     # dnsmasq bound to 10.10.10.1?
tcpdump -ni wlan0 -vvv port 67 or 68    # DHCPDISCOVER / OFFER / REQUEST / ACK visible?
```

If DISCOVERs appear but no OFFERs: iptables `INPUT` policy was dropping; the script inserts accepts—ensure you ran it as root and nothing else overwrote your rules.

**SSID not visible**
Use `--mode compat` and channel **1** or **6**. Fresh SSID. If still dead, reload the module and retry:

```bash
sudo ip link set wlan0 down
sudo modprobe -r 8812au 2>/dev/null || sudo modprobe -r rtl88xxau 2>/dev/null
sudo rfkill unblock all
sudo modprobe 8812au 2>/dev/null || sudo modprobe rtl88xxau 2>/dev/null
```

Minimal hostapd check:

```bash
cat >/tmp/hapd-min.conf <<'EOF'
interface=wlan0
driver=nl80211
ssid=MINTEST
hw_mode=g
channel=6
wmm_enabled=0
ieee80211n=0
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=12345678
wpa_pairwise=CCMP
EOF
sudo ip link set wlan0 up
sudo hostapd -dd /tmp/hapd-min.conf
```

**TLS interception**
`--forward tcp:443=8080` breaks HTTPS unless the device trusts your CA. Install the Burp CA (or only redirect 80).

**Crash cleanup (manual)**

```bash
# defaults: wlan0 / eth0 / 10.10.10.0/24
sudo ./simpleap.sh --cleanup

# custom targets
sudo ./simpleap.sh --cleanup --wifi-if <WIFI_IF> --uplink-if <UPLINK_IF> --subnet <SUBNET>
```

---

## Security notes

* This is a **test harness**, not a home AP: WLAN → router is **wide open** by design.
* Clients can talk to each other (AP isolation **off**).
* Use a legal **country code** and channels.

---

### Attribution

Driver workaround and procedure summarized from Sapsan’s article (thanks to **Janek**):
**[https://sapsan-sklep.pl/en/blogs/articles/alfa-awus-kali-linux-2024-fix-en](https://sapsan-sklep.pl/en/blogs/articles/alfa-awus-kali-linux-2024-fix-en)**
