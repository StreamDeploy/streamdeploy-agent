# SSH into Orin from Anywhere (via GCP Bastion + Reverse SSH)

This guide explains how to connect to an NVIDIA Orin (and future edge devices) from anywhere using a **GCP VM as a bastion** and an **SSH reverse tunnel**. No router or Wi‑Fi NAT changes on the device side are required.

```
Laptop ── ssh -p <PORT> ──▶ GCP VM (bastion) ── reverse tunnel ──▶ Device :22
```

---

## TL;DR (Tony’s current environment)

* **Bastion VM IP:** `34.170.221.16`
* **Bastion user:** `tonyloehr`
* **Orin user:** `tony`
* **Orin’s tunnel port:** `2222`

From anywhere:

```bash
ssh -p 2222 tony@34.170.221.16
```

> The tunnel is **device → VM** (outbound). You connect to the VM’s port to reach the device.

---

## Onboarding Checklist (for new developers)

1. ✅ Confirm you can run `gcloud` on your **laptop** (or use Cloud Shell) with project access.
2. ✅ Tag the bastion VM and open firewall ports **from your laptop**, not from inside the VM.
3. ✅ On each device (Orin, etc.), generate a device‑specific SSH key and add its **public key** to the bastion user’s `~/.ssh/authorized_keys`.
4. ✅ Start a reverse tunnel from the device to the bastion (`-R 0.0.0.0:<PORT>:localhost:22`).
5. ✅ (Recommended) Install a systemd service on the device using `autossh` for auto‑reconnect.
6. ✅ Test: `ssh -p <PORT> tony@<BASTION_IP>` from your laptop.

---

## 1) One‑time GCP network setup (run on your **laptop / Cloud Shell**)

Set project/region/zone:

```bash
gcloud auth login
gcloud config set project stream-deploy-888888
gcloud config set compute/region us-central1
gcloud config set compute/zone us-central1-c
```

Tag the VM so firewall rules can target it:

```bash
gcloud compute instances add-tags instance-20250824-020619 \
  --zone us-central1-c --tags bastion
```

Open a port range for device tunnels (covers many devices):

```bash
gcloud compute firewall-rules create reverse-ssh-range \
  --allow tcp:2222-2299 --direction=INGRESS \
  --target-tags=bastion --network=default
```

> If you see a permissions error, your Google user likely needs IAM like **Compute Network Admin** (or **Security Admin**) to manage firewall rules, and **Compute Instance Admin** to set tags.

(Optional) Reserve/attach a static IP to the VM so the bastion IP doesn’t change.

---

## 2) Bastion VM SSH config (run **on** the VM once)

Make sure sshd allows remote‑bound tunnels and listens publicly for them:

```bash
# Show effective config
sudo sshd -T | egrep 'gatewayports|allowtcpforwarding|permitlisten'

# Enforce & restart (safe to repeat)
echo -e '\nGatewayPorts yes\nAllowTcpForwarding yes' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart ssh
```

---

## 3) Prepare a device (Orin example)

Install `autossh` and create a **device‑specific** keypair on the device:

```bash
sudo apt-get update && sudo apt-get install -y autossh
ssh-keygen -t ed25519 -C "orin01" -f ~/.ssh/orin01 -N ""
cat ~/.ssh/orin01.pub   # copy this line
```

Add the device’s **public key** to the bastion user’s `~/.ssh/authorized_keys`:

```bash
# From your laptop
gcloud compute ssh instance-20250824-020619 --zone us-central1-c

# On the VM shell (as user: tonyloehr)
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA... orin01' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

> **Gotcha:** Log in to the bastion as the correct user (here `tonyloehr`). If you add the key under `tonyloehr`, the device must connect as `tonyloehr@<VM_IP>`.

---

## 4) Bring up a test tunnel (device → VM)

On the device (Orin), create a reverse tunnel on **port 2222**:

```bash
ssh -f -N -T \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -i ~/.ssh/orin01 -o IdentitiesOnly=yes \
  -R 0.0.0.0:2222:localhost:22 \
  tonyloehr@34.170.221.16
```

Validate it:

**On the VM:**

```bash
sudo ss -lntp | grep :2222     # should show sshd listening on 0.0.0.0:2222
ssh -p 2222 tony@localhost     # should land on the device
```

**From your laptop (anywhere):**

```bash
ssh -p 2222 tony@34.170.221.16
```

If it says **connection refused**, re‑check that the firewall rule exists and the VM is tagged `bastion` (Step 1).

---

## 5) Make the tunnel persistent (systemd on the device)

Install a unit so the tunnel is always up and auto‑recovers:

```bash
sudo tee /etc/systemd/system/reverse-ssh.service >/dev/null <<'EOF'
[Unit]
Description=Reverse SSH Tunnel to GCP VM
After=network-online.target
Wants=network-online.target

[Service]
User=tony
ExecStart=/usr/bin/autossh -M 0 -N -T \
  -o "ExitOnForwardFailure=yes" \
  -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" \
  -i /home/tony/.ssh/orin01 -o "IdentitiesOnly=yes" \
  -R 0.0.0.0:2222:localhost:22 tonyloehr@34.170.221.16
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable reverse-ssh
sudo systemctl start reverse-ssh
systemctl status reverse-ssh --no-pager
```

Check logs on the device:

```bash
journalctl -u reverse-ssh -e
```

---

## 6) Add more devices (multi‑device pattern)

Use a **unique port per device**. The firewall already allows `2222–2299`.

Example port plan:

|  Device | Key name | Remote port | Connect from laptop              |
| ------: | :------- | ----------: | :------------------------------- |
| Orin 01 | `orin01` |      `2222` | `ssh -p 2222 tony@34.170.221.16` |
| Orin 02 | `orin02` |      `2223` | `ssh -p 2223 tony@34.170.221.16` |
| Orin 03 | `orin03` |      `2224` | `ssh -p 2224 tony@34.170.221.16` |

Device setup steps (repeat per device):

1. On the device: create a new keypair (`orin02`, etc.).
2. On the VM: append the device’s `*.pub` to `~/.ssh/authorized_keys` (user `tonyloehr`).
3. On the device: set the service to `-R 0.0.0.0:<UNIQUE_PORT>:localhost:22`.
4. From your laptop: connect using that port.

> Tip: Keep a spreadsheet mapping Device ID ⇄ Key name ⇄ Port.

---

## 7) Optional: DNS convenience

Point a DNS A record (e.g., Cloudflare) to the bastion IP `34.170.221.16`:

```
A  orin   → 34.170.221.16
```

Then connect with:

```bash
ssh -p 2222 tony@orin.example.com
```

---

## Troubleshooting

**“Connection refused” from laptop**

* The reverse tunnel isn’t up (device not connected or service failed).
* Firewall rule/VM tag missing. Re‑run Step 1 and verify:

  ```bash
  gcloud compute instances describe instance-20250824-020619 --zone us-central1-c \
    --format="get(tags.items)"
  # expect: [bastion]
  ```

**`Permission denied (publickey)` when device connects to VM**

* Wrong bastion username — should be `tonyloehr@<VM_IP>` in this repo.
* Device isn’t using its key — include `-i ~/.ssh/<device_key>` and `-o IdentitiesOnly=yes`.
* Device’s pubkey not in VM’s `~/.ssh/authorized_keys` or wrong file perms.

**`remote port forwarding failed for listen port <PORT>`**

* Port already in use on the VM. Free it then retry:

  ```bash
  # on VM
  sudo ss -lntp | grep :<PORT> || true
  sudo fuser -k <PORT>/tcp || true
  ```
* SSHD not permitting remote binds. Ensure on VM:

  ```bash
  echo -e '\nGatewayPorts yes\nAllowTcpForwarding yes' | sudo tee -a /etc/ssh/sshd_config
  sudo systemctl restart ssh
  ```

**The command “hangs”**

* `ssh -N` runs in foreground. Use `-f` for background or the systemd service.

**Inspect logs**

* Device: `journalctl -u reverse-ssh -e`
* VM listeners: `sudo ss -lntp | grep :<PORT>`

---

## Security Notes

* Use **SSH keys only**; disable password SSH on devices where possible.
* Rotate device keys periodically and remove stale keys from the VM.
* Limit firewall sources to trusted IP ranges if you can.
* Keep VM and devices updated (`apt-get upgrade`). Treat the bastion as a minimal, audited entry point.

---

## Quickstart (copy/paste for Tony’s current values)

**Laptop / Cloud Shell (one‑time):**

```bash
gcloud auth login
gcloud config set project stream-deploy-888888
gcloud config set compute/region us-central1
gcloud config set compute/zone us-central1-c
gcloud compute instances add-tags instance-20250824-020619 --zone us-central1-c --tags bastion
gcloud compute firewall-rules create reverse-ssh-range --allow tcp:2222-2299 --direction=INGRESS --target-tags=bastion --network=default
```

**Device (Orin) one‑time key + test:**

```bash
ssh-keygen -t ed25519 -C "orin01" -f ~/.ssh/orin01 -N ""
# paste ~/.ssh/orin01.pub into VM: ~/.ssh/authorized_keys (user: tonyloehr)

ssh -f -N -T \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -i ~/.ssh/orin01 -o IdentitiesOnly=yes \
  -R 0.0.0.0:2222:localhost:22 \
  tonyloehr@34.170.221.16
```

**Persist (device):** install `reverse-ssh.service` as shown above.

**Connect from anywhere:**

```bash
ssh -p 2222 tony@34.170.221.16
```

---

## Appendix: Template service for additional devices

Replace placeholders and pick a unique port per device.

```ini
# /etc/systemd/system/reverse-ssh.service
[Unit]
Description=Reverse SSH Tunnel to GCP VM
After=network-online.target
Wants=network-online.target

[Service]
User=<device_user>
ExecStart=/usr/bin/autossh -M 0 -N -T \
  -o "ExitOnForwardFailure=yes" \
  -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" \
  -i /home/<device_user>/.ssh/<device_key> -o "IdentitiesOnly=yes" \
  -R 0.0.0.0:<UNIQUE_PORT>:localhost:22 <bastion_user>@<BASTION_IP>
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

That’s it — you can now attach new devices in minutes and reach any of them from anywhere via the GCP bastion.
