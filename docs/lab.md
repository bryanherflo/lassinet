# Lab guide — testing LassiNet against a real (isolated) network

LassiNet ships with a simulator so nothing here is *required*, but building
this lab is a worthwhile extension exercise.

## Option A — two-VM lab (VirtualBox / VMware / Proxmox)

1. **OPNsense VM** — WAN: NAT/dummy · LAN: 192.168.56.0/24, enable the API and create an API key/secret.
2. **Kali/attacker VM** — e.g. `nmap` port scan, `hydra`/ssh brute force, `hping3` flood.
3. **Victim VM** — a simple web server (`python -m http.server`).
4. Run LassiNet on the host or inside one VM with `LASSI_MODE=live`.

Reproduce attack signatures the model was trained for:

```bash
# port scan  (high dst_port_count, high syn_ratio)
nmap -T5 -p- 192.168.56.10

# SSH brute force  (many pkts, single port)
hydra -l root -P rock-sm.txt ssh://192.168.56.10   # demo: use a tiny wordlist

# DoS  (high pkt_rate, tiny packets)
hping3 --flood -S -p 80 192.168.56.10
```

## Option B — containerised attack lab

```bash
# terminal 1: victim
docker run --rm -it --network lab -p 80:80 nicolaka/netshoot python -m http.server
# terminal 2: attacker
docker run --rm -it --network lab b3ardino/attacker nmap -T5 -Pn -p- 172.17.0.2
```

> ⚠️ Run all of this only on networks you own. Isolate the lab from your home/
> office network (host-only/NAT interfaces, or a dedicated VLAN).

## Option C — sensor on your own LAN (Windows)

LassiNet can run as a passive sensor on the network you are sitting on. It
only *listens* (one ARP sweep per interval) and never scans ports.

```powershell
pip install scapy            # + Npcap driver installed (https://npcap.com)
$env:LASSI_MODE = "live"
$env:LASSI_FW   = "windows"   # real blocking; needs an Administrator shell
python app.py
```

* The capture interface is the one of the **default route**, so a laptop with
  Wi-Fi, Ethernet and virtual adapters still listens on the right NIC. Pin it
  explicitly with `LASSI_IFACE="Ethernet"` if you want to be sure.
* The real default gateway becomes the router hub of the map, and the machine
  running LassiNet appears as a workstation. Both are protected and can never
  be blocked.
* `LASSI_AUTO_BLOCK` stays `0` in live mode: nothing is blocked until you
  click *Block source* (or *Block IP* on a device).
* Expect to see the traffic of the machine itself: the flows are real.

## Wiring real firewall enforcement

* **OPNsense** — create an alias named `lassinet_blocked` (Host, Network or
  External type) and a block rule that uses it as the source. Then generate an
  API key/secret in the web UI and set:
  ```bash
  LASSI_FW=opnsense \
  OPNSENSE_URL=https://192.168.56.1 \
  OPNSENSE_KEY=... OPNSENSE_SECRET=... \
  OPNSENSE_ALIAS=lassinet_blocked \
  python app.py
  ```
  LassiNet calls `/api/firewall/alias_util/add|delete/<alias>` and only reports
  the block after OPNsense returns `status: done`. It does not create the alias
  or the firewall rule. For a lab with a self-signed certificate, set
  `OPNSENSE_VERIFY_TLS=0`; never disable verification on a production firewall.
  `pfsense` is still a placeholder because its REST API is different.
* **Linux nftables** — `LASSI_FW=nftables`; create the table and a base chain
  named `drop` with the hook for your deployment. LassiNet adds/removes rules
  but does not create firewall infrastructure:
  ```bash
  sudo nft add table inet lassinet
  # protect this host (input); use hook forward instead if this host is a gateway
  sudo nft add chain inet lassinet drop '{ type filter hook input priority 0; policy accept; }'
  ```
  A base chain has one hook, so choose `input` (local host) or `forward`
  (traffic routed through the machine) according to what you want to protect.
  On restart, LassiNet reads the existing `ip saddr ... drop` rules back into
  the dashboard so active blocks are not hidden or duplicated.
* **Windows Firewall** — `LASSI_FW=windows`; the process must run **elevated**
  (Administrator PowerShell), otherwise `netsh` is rejected and the API reports
  the error instead of marking the source as blocked:
  ```powershell
  # capture needs Npcap (https://npcap.com); blocking needs Administrator
  pip install scapy
  $env:LASSI_MODE = "live"
  $env:LASSI_FW   = "windows"
  python app.py
  ```
  Each blocked source becomes a persistent inbound rule named
  `LassiNet-Block-<ip>` (`dir=in action=block remoteip=<ip> profile=any`),
  removed again on unblock. Surviving rules are read back on startup.
  Note the semantics: the rule blocks **inbound** traffic from that source on
  this host. Outbound connections the machine initiates are not affected, and
  a host behind NAT only sees the traffic that actually reaches it.
