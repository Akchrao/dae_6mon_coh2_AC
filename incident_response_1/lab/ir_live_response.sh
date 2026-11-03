#!/bin/sh
# ir_live_response.sh - live data collection on a Parrot OS / Debian host (Care Access Navigator IR toolkit)
# Runs as root, fed over SSH from the forensic workstation:  ssh ir-analyst@host 'sudo sh -s' < ir_live_response.sh
# Writes ONLY to RAM (/dev/shm/lr), never to the suspect disk. The workstation then pulls /dev/shm/lr as a tar.
# Order follows RFC 3227 (most volatile first). Every command is logged with UTC start time, exit code and the
# SHA-256 of its output, so each output file can be tied back to the exact command that produced it.
CASE=${CASE:-IR1-2026-005}
OUT=/dev/shm/lr; rm -rf "$OUT"; mkdir -p "$OUT"; chmod 700 "$OUT"
LOG="$OUT/00_collection_log.tsv"
printf 'seq\tutc_start\texit\tsha256\toutput\tcommand\n' > "$LOG"
N=0
c() {  # c <name> <command...>
  N=$((N + 1)); f=$(printf '%02d_%s.txt' "$N" "$1"); shift
  t=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
  sh -c "$*" > "$OUT/$f" 2>&1; rc=$?
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$N" "$t" "$rc" "$(sha256sum "$OUT/$f" | cut -d' ' -f1)" "$f" "$*" >> "$LOG"
}
# --- 1. system state and clock (needed to interpret every other timestamp)
c clock          'date -u; date; cat /etc/timezone; timedatectl 2>/dev/null | head -6; cat /proc/uptime'
c system         'hostname; uname -a; head -2 /etc/os-release; cat /proc/cmdline; cat /etc/ir-golden-release'
# --- 2. running processes (volatile)
c processes      'ps -eo pid,ppid,user,uid,lstart,etime,stat,args --forest'
c process_exe_sha256 'for p in /proc/[0-9]*; do e=$(readlink $p/exe 2>/dev/null) && printf "%s\t%s\t%s\n" "${p#/proc/}" "$e" "$(sha256sum $p/exe 2>/dev/null | cut -d" " -f1)"; done | sort -n'
c open_files     'lsof -nP 2>/dev/null | grep -vE " (mem|DEL) " | head -400'
c logged_in      'who -a; echo; w'
# --- 3. network connections and configuration (volatile)
c sockets        'ss -tunap'
c listening      'ss -ltunp'
c interfaces     'ip -d -br link; echo; ip -br addr; echo; ip route; echo; ip neigh'
c firewall       'iptables-save; echo; iptables -vnL'
c dns_hosts      'cat /etc/resolv.conf /etc/hosts'
# --- 4. kernel and services
c kernel_modules 'lsmod'
c kernel_log     'dmesg -T | tail -60'
c services       'systemctl list-units --type=service --all --no-pager --no-legend'
c timers_cron    'systemctl list-timers --all --no-pager; echo; ls -la /var/spool/cron/crontabs; for f in /var/spool/cron/crontabs/*; do echo "== $f"; cat "$f"; done; echo; cat /etc/crontab; ls -la /etc/cron.d'
c mounts_disks   'findmnt -l; echo; df -h; echo; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID'
# --- 5. accounts and access
c accounts       'getent passwd | awk -F: "\$3>=1000 || \$3==0"; echo; getent group | grep -E "clinical|billing|sudo|disabled-users"; echo; for u in $(getent passwd | awk -F: "\$3>=1000{print \$1}"); do passwd -S $u; done'
c sudoers        'cat /etc/sudoers.d/* 2>/dev/null; grep -vE "^#|^$" /etc/sudoers'
c ssh_keys       'for h in /root /home/*; do for k in $h/.ssh/authorized_keys; do [ -f $k ] && { echo "== $k"; ssh-keygen -lf $k; }; done; done; ls -la /root/ir-quarantine 2>/dev/null'
c lastlog        'last -F -n 30; echo; lastb -F -n 20 2>/dev/null'
# --- 6. file system: recent changes, hidden files, SUID (non-volatile, collected last)
c recent_files   'find /home /tmp /var/tmp /dev/shm /etc /var/spool /usr/local -xdev -newermt "-3 hours" -type f ! -path "/dev/shm/lr/*" -printf "%TY-%Tm-%Td %TH:%TM:%TS\t%u\t%m\t%s\t%p\n" 2>/dev/null | sort'
c hidden_dirs    'find /home /tmp /var/tmp /root -xdev -name ".*" -type d -printf "%u\t%p\n" 2>/dev/null'
c suid_sgid      'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m\t%u\t%p\n" 2>/dev/null | sort -k3'
c shell_history  'for h in /root /home/*; do for f in $h/.bash_history $h/.sh_history; do [ -f $f ] && { echo "== $f"; cat $f; }; done; done; echo "(end)"'
echo "collected $N items into $OUT at $(date -u +%FT%TZ)"
