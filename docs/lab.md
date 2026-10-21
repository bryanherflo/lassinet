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
  On restart, LassiNet reads the existing `drop ... saddr` rules back into the
  dashboard so active blocks are not hidden or duplicated.
