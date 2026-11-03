#!/usr/bin/env bash
# =============================================================================
# Care Access Navigator - IR1 Tasks 1-6 (shared lab): build the "golden" parrot-vm disk
# -----------------------------------------------------------------------------
# One-time. Boots the official Debian 12 genericcloud image (checksum-verified) under
# QEMU with a cloud-init seed that installs the Parrot OS forensic/IR toolset (incl. Wireshark/tshark)
# and the Wazuh agent 4.9.2 (enrolled later, at provisioning), then powers off. The result, parrot-vm-golden.qcow2, is the known-good baseline:
#   - every lab run boots a throw-away overlay on top of it (Task 1 builds the lab from it)
#   - Task 6 verifies it as the rebuild source of last resort
# VM files live OUTSIDE the git repo (they are GBs): ~/ir1-vm-lab/
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
VMLAB="$HOME/ir1-vm-lab"; IMG="$VMLAB/images"; G="$VMLAB/golden"
KEYS="$(pwd)/.keys"; KEY="$KEYS/ir_analyst_ed25519"
mkdir -p "$G" "$KEYS"
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C 'ir-analyst@ir-forensics' -f "$KEY"

# 0. verify the base image against Debian's published SHA512SUMS
( cd "$IMG" && grep ' debian-12-genericcloud-amd64.qcow2$' SHA512SUMS | shasum -a 512 -c )

cat > "$G/user-data" <<EOF
#cloud-config
hostname: parrot-vm
manage_etc_hosts: true
timezone: UTC
users:
  - name: ir-analyst
    gecos: Incident Response analyst (forensic access)
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat "$KEY.pub")"]
package_update: true
packages: [rsyslog, cron, tcpdump, gdb, lsof, psmisc, netcat-openbsd, dc3dd, sleuthkit,
           qemu-guest-agent, curl, acl, auditd, gnupg, apt-transport-https]
write_files:
  - path: /etc/motd
    content: |
      parrot-vm (Debian 12 bookworm, Parrot OS stand-in) - Care Access Navigator IR lab
runcmd:
  - systemctl enable --now rsyslog cron qemu-guest-agent auditd
  - [sh, -c, "echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections && DEBIAN_FRONTEND=noninteractive apt-get install -y -q tshark"]
  - [sh, -c, "curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list && apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q wazuh-agent=4.9.2-1 && systemctl disable wazuh-agent"]
  - echo "golden built $(date -u +%FT%TZ)" > /etc/ir-golden-release
  - [sh, -c, "dpkg -l rsyslog tcpdump tshark gdb lsof dc3dd sleuthkit qemu-guest-agent auditd wazuh-agent | awk '/^ii/{print \$2, \$3}' > /etc/ir-golden-packages"]
  - poweroff
EOF
printf 'instance-id: parrot-vm-golden\nlocal-hostname: parrot-vm\n' > "$G/meta-data"

docker run --rm -v "$G":/g -v "$IMG":/img:ro -w /g ir-hypervisor:1.0 sh -c '
  cloud-localds seed.iso user-data meta-data
  rm -f parrot-vm-golden.qcow2
  qemu-img create -q -f qcow2 -F qcow2 -b /img/debian-12-genericcloud-amd64.qcow2 build.qcow2 8G
  timeout 1500 qemu-system-x86_64 -machine q35 -accel tcg,thread=multi -cpu max -smp 2 -m 1024 \
    -drive file=build.qcow2,if=virtio -drive file=seed.iso,if=virtio,format=raw,media=cdrom \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -serial file:/g/golden-console.log -display none -monitor none
  # flatten to a standalone golden disk (no backing file) so restores never depend on the download
  qemu-img convert -O qcow2 build.qcow2 parrot-vm-golden.qcow2 && rm -f build.qcow2
  qemu-img info parrot-vm-golden.qcow2 | head -4'
grep -E 'Cloud-init .* finished|reboot: Power down' "$G/golden-console.log" | tail -2
shasum -a 256 "$G/parrot-vm-golden.qcow2" | tee "$G/parrot-vm-golden.sha256"
