"""Build the CloudSec1 'Cloud Infrastructure Security & Container Protection' evidence PDF.

Matches the style of the Criterion 4 IAM evidence package (Letter, Helvetica,
navy #1B2A4A headings, amber step badges, cream note boxes).
Optional screenshots (see optional_shot calls) are embedded when saved into
cloud_security_1/ under the expected filename; otherwise the section relies on
the captured command output alone. The helpers above the '# ---- Cover' marker
are reused by build_c4_addendum.py.
"""
import os
import textwrap
from html import escape

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (CondPageBreak, Image, KeepTogether, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

SCRATCH = os.path.dirname(os.path.abspath(__file__))          # cloud_security_1/pdf-build
DATA = os.path.join(SCRATCH, "data")
IMG = os.path.join(SCRATCH, ".cache")                        # downscaled screenshots (regenerated)
SHOTS = os.path.dirname(SCRATCH)                             # cloud_security_1
REPO = SHOTS                                                 # project folders live in cloud_security_1/
os.makedirs(IMG, exist_ok=True)
OUT = os.path.join(SHOTS, "Care_Access_Navigator_CloudSec1_Criterion_3_Infrastructure_Container_Security.pdf")

NAVY = colors.HexColor("#1B2A4A")
AMBER = colors.HexColor("#E8A33D")
CREAM = colors.HexColor("#FFF4DE")
BROWN = colors.HexColor("#5C4200")
GREY_BG = colors.HexColor("#F3F4F6")
GREY_LINE = colors.HexColor("#CCCCCC")
TEXT = colors.HexColor("#444444")
MUTED = colors.HexColor("#555555")
GREEN = colors.HexColor("#1E7B45")
RED = colors.HexColor("#A3271F")

ss = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=22, leading=27, textColor=NAVY),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=NAVY),
    "subsub": ParagraphStyle("subsub", fontName="Helvetica-Oblique", fontSize=10.5, leading=14, textColor=MUTED),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=NAVY,
                         spaceBefore=6, spaceAfter=6),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=NAVY,
                         spaceBefore=2, spaceAfter=4),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=14, textColor=TEXT,
                           spaceAfter=6, alignment=TA_LEFT),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=10, leading=14, textColor=TEXT,
                             leftIndent=14, bulletIndent=4, spaceAfter=2),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=9, leading=11.5, textColor=TEXT),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=NAVY),
    "cellh": ParagraphStyle("cellh", fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=colors.white),
    "caption": ParagraphStyle("caption", fontName="Helvetica-Oblique", fontSize=9, leading=12, textColor=MUTED,
                              spaceBefore=3, spaceAfter=10),
    "note": ParagraphStyle("note", fontName="Helvetica", fontSize=9.3, leading=13, textColor=BROWN),
    "badge": ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=9, leading=11, textColor=colors.white),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=7.6, leading=9.4, textColor=colors.HexColor("#1F2933")),
}

FULL_W = 6.5 * inch
fig_no = [0]


def P(text, style="body"):
    return Paragraph(text, ss[style])


def bullets(items):
    return [Paragraph(t, ss["bullet"], bulletText="•") for t in items]


def note(text, label="Note"):
    t = Table([[Paragraph(f"<b>{label}:</b> {text}", ss["note"])]], colWidths=[FULL_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CREAM),
        ("LINEBEFORE", (0, 0), (0, -1), 3, AMBER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return [t, Spacer(1, 8)]


def step(num, title):
    badge = Table([[Paragraph(f"STEP {num}", ss["badge"])]], colWidths=[0.8 * inch])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), AMBER),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    row = Table([[badge, Paragraph(title, ss["h2"])]], colWidths=[0.95 * inch, FULL_W - 0.95 * inch])
    row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                             ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    return [CondPageBreak(2.2 * inch), Spacer(1, 6), row, Spacer(1, 4)]


FIG = {}
MISSING = []


def screenshot_jpg(num):
    """Downscaled copy of cloud_security_1/'Virtual Machine <num>.png' (any capitalisation)."""
    out = os.path.join(IMG, f"{num:02d}.jpg")
    if not os.path.exists(out):
        src = next(os.path.join(SHOTS, f) for f in os.listdir(SHOTS)
                   if f.lower() == f"virtual machine {num}.png")
        im = PILImage.open(src).convert("RGB")
        if im.width > 1800:
            im = im.resize((1800, round(im.height * 1800 / im.width)), PILImage.LANCZOS)
        im.save(out, quality=85, optimize=True)
    return out


def figure(num, caption, max_h=4.1 * inch, path=None):
    path = path or screenshot_jpg(num)
    w, h = PILImage.open(path).size
    scale = min(FULL_W / w, max_h / h)
    img = Image(path, width=w * scale, height=h * scale)
    img.hAlign = "CENTER"
    frame = Table([[img]], colWidths=[w * scale + 2])
    frame.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, GREY_LINE),
                               ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
                               ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
    fig_no[0] += 1
    FIG[num] = fig_no[0]
    return [KeepTogether([frame, Paragraph(f"Figure {fig_no[0]}. {caption}", ss["caption"])])]


def optional_shot(filename, key, caption, max_h=4.6 * inch):
    """Embed cloud_security_1/<filename> if it has been saved; otherwise add nothing,
    since the same evidence is already shown as captured command output."""
    src = os.path.join(SHOTS, filename)
    if not os.path.exists(src):
        MISSING.append(filename)
        return []
    out = os.path.join(IMG, key + ".jpg")
    im = PILImage.open(src).convert("RGB")
    if im.width > 1800:
        im = im.resize((1800, round(im.height * 1800 / im.width)), PILImage.LANCZOS)
    im.save(out, quality=85, optimize=True)
    return figure(key, caption, max_h=max_h, path=out)


def figs(*keys):
    nums = [FIG[k] for k in keys if k in FIG]
    if not nums:
        return ""
    if len(nums) > 2 and nums == list(range(nums[0], nums[-1] + 1)):
        return f"Fig. {nums[0]}–{nums[-1]}"
    return "Fig. " + ", ".join(map(str, nums))


def code(text, title=None, width=98):
    lines = []
    for line in text.expandtabs(4).rstrip("\n").splitlines():
        line = "".join(ch for ch in line if ch == " " or ch.isprintable())
        if len(line) <= width:
            lines.append(line)
        else:
            lines += textwrap.wrap(line, width, subsequent_indent="    ", break_long_words=True,
                                   break_on_hyphens=False, drop_whitespace=False)
    pre = Preformatted("\n".join(lines), ss["code"])
    t = Table([[pre]], colWidths=[FULL_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), GREY_BG), ("BOX", (0, 0), (-1, -1), 0.5, GREY_LINE),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    block = [t]
    if title:
        block.insert(0, Paragraph(f"<font name='Helvetica-Bold' size=8.5 color='#1B2A4A'>{escape(title)}</font>",
                                  ss["body"]))
    # keep short blocks (and their title) on one page; long ones may split
    return [KeepTogether(block) if len(lines) < 45 else block[0]] + ([] if len(lines) < 45 else block[1:]) + [Spacer(1, 8)]


def table(rows, widths, header=True, zebra=True):
    data = []
    for r_i, row in enumerate(rows):
        style = "cellh" if header and r_i == 0 else "cell"
        data.append([c if not isinstance(c, str) else Paragraph(c, ss[style]) for c in row])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    cmds = [("GRID", (0, 0), (-1, -1), 0.5, GREY_LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    if header:
        cmds.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if (i % 2 == 0) == header:
                cmds.append(("BACKGROUND", (0, i), (-1, i), GREY_BG))
    t.setStyle(TableStyle(cmds))
    return [t, Spacer(1, 10)]


def kv(rows):
    data = [[Paragraph(k, ss["cellb"]), Paragraph(v, ss["cell"])] for k, v in rows]
    t = Table(data, colWidths=[1.55 * inch, FULL_W - 1.55 * inch])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, GREY_LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                           ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    return [t, Spacer(1, 12)]


def read(rel):
    with open(os.path.join(SHOTS, rel)) as f:
        return f.read()


def ok(t="PASS"):
    return f"<font color='#1E7B45'><b>{t}</b></font>"


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(inch, 0.55 * inch,
                      "Care Access Navigator — CloudSec1 Criterion 3: Cloud Infrastructure Security & Container Protection")
    canvas.drawRightString(letter[0] - inch, 0.55 * inch, f"Page {doc.page}")
    canvas.setStrokeColor(GREY_LINE)
    canvas.line(inch, 0.7 * inch, letter[0] - inch, 0.7 * inch)
    canvas.restoreState()


s = []

# ------------------------------------------------------------------ Cover
s += [P("Care Access Navigator", "title"), Spacer(1, 4),
      P("CloudSec1 Rubric — Criterion 3: Cloud Infrastructure Security &amp; Container Protection", "subtitle"),
      P("Evidence Package — VM Hardening, Container Security (Docker + Trivy) &amp; Serverless Function "
        "Isolation", "subsub"), Spacer(1, 14)]
s += kv([
    ("Prepared by:", "Akhila Chennamaneni"),
    ("Capstone:", "Care Access Navigator (HealthLine Regional Medical Center)"),
    ("Rubric criterion:", "Criterion 3 — Cloud Infrastructure Security &amp; Container Protection (CloudSec1)"),
    ("Environment:", "Microsoft Azure (Azure subscription 1, resource group rg-cloudsec1-can); "
                     "Docker 29.7 + Trivy 0.75 on macOS"),
    ("Evidence dates:", "October 6–8, 2026"),
])
s += [P("Objective", "h1"),
      P("This criterion requires practical skills securing three kinds of cloud compute: one virtual machine "
        "(automated patching, host firewall, secure SSH), one containerised workload (secure Dockerfile, Docker "
        "security settings, and container scanning with documented results) and one serverless function (proper "
        "IAM roles and network isolation). Each control below was implemented on real Azure resources or on the "
        "real CAN EHR simulator container, then <b>tested</b> — including negative tests showing that what "
        "should be blocked is blocked.")]
s += [P("Scope of this evidence package", "h2")]
s += bullets([
    "<b>Part A — VM hardening:</b> Ubuntu 24.04 VM with Trusted Launch, Azure-managed patching + "
    "unattended-upgrades, NSG + ufw host firewall, key-only SSH, fail2ban",
    "<b>Part B — Container security:</b> hardened multi-stage Dockerfile, hardened Docker runtime settings, "
    "Trivy image/config/secret scans before and after (172 → 0 vulnerabilities)",
    "<b>Part C — Serverless:</b> Azure Function (Flex Consumption) with a user-assigned managed identity, "
    "single least-privilege role, no keys, VNet integration, storage firewall and IP access restrictions",
    "Genuine issues encountered and how they were resolved (documented, not hidden)",
    "Compliance mapping to HIPAA Security Rule and NIST CSF 2.0",
])
s += [Spacer(1, 6)]
s += note("All resources were built under a strict cost constraint (pay-as-you-go on developer credit). "
          "The VM was created temporarily for this evidence and deallocated/deleted afterwards; the container work "
          "ran locally at no cost; the function runs on the Flex Consumption free grant.", "Cost constraint")

# ------------------------------------------------------------------ Summary
s += [PageBreak(), P("Results at a Glance", "h1")]
s += table([
    ["Requirement", "Implementation", "Verified result"],
    ["VM: automated patching", "Azure AutomaticByPlatform patching + unattended-upgrades (security origins, "
     "daily, auto-reboot 03:00)", ok() + " — security kernel update auto-installed; Azure assessment: "
     "0 security/critical outstanding"],
    ["VM: host firewall", "NSG vm-sg (SSH from admin IP only, deny-all) + ufw default-deny, rate-limited SSH",
     ok() + " — IP flow verify: admin IP allowed, other IP denied, port 80 denied"],
    ["VM: secure SSH", "Key-only (ed25519), no root, AllowUsers canadmin, MaxAuthTries 3, modern ciphers, "
     "no forwarding, fail2ban", ok() + " — password, root and unknown-user logins all rejected"],
    ["Container: secure Dockerfile", "Multi-stage, digest-pinned Chainguard base, non-root UID 65532, no "
     "shell/pip, read-only files, gunicorn", ok() + " — Trivy: 172 → <b>0</b> vulnerabilities; "
     "0 misconfigurations"],
    ["Container: Docker settings", "read_only, cap_drop ALL, no-new-privileges, pids/mem/cpu limits, "
     "localhost-only port", ok() + " — writes blocked, CapEff=0, fork bomb stopped at 96"],
    ["Container: scanning", "Trivy vuln + secret + Dockerfile config scans, CycloneDX SBOM",
     ok() + " — reports saved in can-ehr-container/reports/"],
    ["Serverless: IAM", "User-assigned managed identity, one role (Storage Blob Data Owner) on one storage "
     "account; shared keys disabled", ok() + " — function reads storage with no secrets; key auth refused"],
    ["Serverless: network isolation", "VNet integration (snet-func), storage firewall (subnet + admin IP), "
     "function IP restrictions, HTTPS/TLS 1.2", ok() + " — 401 without key, 403 from non-allowed IP "
     "even with valid key"],
], [1.45 * inch, 2.6 * inch, 2.45 * inch])

s += [P("Architecture", "h2")]
s += table([
    ["Component", "Value"],
    ["Resource group", "rg-cloudsec1-can"],
    ["VM", "can-vm-hardened — Ubuntu 24.04 LTS, Standard_F1als_v7, North Central US, Trusted Launch "
           "(Secure Boot + vTPM)"],
    ["VM network", "can-vnet-vmlab / snet-vm (10.30.1.0/24), NSG vm-sg"],
    ["Container", "can-ehr-simulator:2.0 (Chainguard/Wolfi Python 3.14, gunicorn), run via "
                  "docker-compose.secure.yml"],
    ["Function App", "func-can-ehr-9a8c96 — Python 3.12, Flex Consumption, East US"],
    ["Function identity", "id-can-func (user-assigned managed identity)"],
    ["Function network", "can-vnet-cloudsec1 / snet-func (10.20.5.0/27, delegated Microsoft.App/environments, "
                         "NSG func-sg, Microsoft.Storage service endpoint)"],
    ["Function storage", "stcanfunc9a8c964b — shared-key access disabled, TLS 1.2, no anonymous access, "
                         "default-deny firewall"],
], [1.6 * inch, 4.9 * inch])

# ------------------------------------------------------------------ Part A
s += [PageBreak(), P("Part A — Virtual Machine Hardening", "h1"),
      P("A dedicated Ubuntu 24.04 LTS VM was deployed with Azure platform protections enabled at creation, then "
        "hardened at the operating-system level with a repeatable script "
        "(<font name='Courier'>can-vm-hardening/harden.sh</font>) run over SSH.")]

s += step("A1", "Deploy the VM with platform security enabled")
s += [P("The VM was created with SSH-key authentication only (password authentication disabled at the "
        "platform level), Trusted Launch (Secure Boot and a virtual TPM to protect the boot chain), and "
        "<b>AutomaticByPlatform</b> patch orchestration so Azure applies critical and security patches "
        "automatically using safe deployment practices.")]
s += figure(1, "VM overview — can-vm-hardened running Ubuntu 24.04 (Standard F1als v7, North Central US), "
               "tagged as temporary for this evidence.")

s += step("A2", "Automated patching — Azure platform + unattended-upgrades")
s += [P("Two layers of automated patching were configured. Azure manages platform patching "
        "(<i>Azure Managed — Safe Deployment</i>), and inside the OS <b>unattended-upgrades</b> installs "
        "security updates daily from the security origins only, removes unused dependencies, and reboots at 03:00 "
        "when a kernel update requires it. To prove it works end-to-end, unattended-upgrades was run once and "
        "installed a pending security kernel update; after reboot the kernel moved from 6.17.0-1022 to 7.0.0-1014 "
        "and Azure's patch assessment reported <b>0 security/critical updates</b> outstanding.")]
s += code("""APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";

Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";""", "/etc/apt/apt.conf.d/20auto-upgrades + 52unattended-upgrades-can")
s += figure(2, "Azure Updates blade — patch orchestration 'Azure Managed — Safe Deployment'; 0 security "
               "and critical updates outstanding. The 5 'Other' updates are non-security kernel packages from "
               "noble-updates, intentionally excluded by the security-only policy.")

s += step("A3", "Host firewall — Azure NSG and ufw (defence in depth)")
s += [P("Inbound access is filtered twice. At the Azure network layer, NSG <b>vm-sg</b> allows TCP 22 only from "
        "the administrator's public IP (24.189.77.111/32) and explicitly denies everything else. On the host, "
        "<b>ufw</b> denies all inbound traffic by default and allows SSH only from the same IP, with rate limiting "
        "(LIMIT) to slow brute-force attempts; logging is on.")]
s += figure(3, "NSG vm-sg — allow-ssh-admin-ip (priority 100, 22/TCP from 24.189.77.111/32) and "
               "deny-all-inbound (priority 4000).")
s += [P("The NSG was tested with Azure Network Watcher <b>IP flow verify</b>:")]
s += code(read("can-vm-hardening/evidence/06-azure-patching-and-nsg.txt").split("== NSG IP flow verify")[1]
          .split("==", 1)[1].strip(), "Network Watcher IP flow verify")

s += step("A4", "Secure SSH access")
s += [P("SSH hardening is applied in <font name='Courier'>/etc/ssh/sshd_config.d/00-can-hardening.conf</font>, "
        "which loads before the cloud image defaults so these values take precedence. Root login, passwords and "
        "keyboard-interactive auth are disabled; only the <b>canadmin</b> account may log in, with public keys "
        "only; attempts are limited; forwarding is disabled; only modern key-exchange, cipher and MAC algorithms "
        "are offered; and a legal warning banner is shown. <b>fail2ban</b> bans an IP for 1 hour after 3 failed "
        "attempts in 10 minutes.")]
s += code("""PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers canadmin
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no / AllowAgentForwarding no / AllowTcpForwarding no
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
Banner /etc/issue.net""", "SSH hardening (key settings)")
s += figure(4, "Key-based SSH login as canadmin to can-vm-hardened.")
s += figure(5, "Verification on the VM — ufw active (default deny incoming, SSH LIMIT from admin IP only), "
               "fail2ban sshd jail active, and effective sshd settings (maxauthtries 3, permitrootlogin no, "
               "passwordauthentication no, allowusers canadmin).", max_h=4.6 * inch)

s += step("A5", "Negative tests — what should be blocked is blocked")
s += code(read("can-vm-hardening/evidence/05-ssh-negative-tests.txt"), "SSH negative tests (from the admin IP)")
s += note("Only two failed attempts were made deliberately: fail2ban bans after three, which would have locked "
          "out the administrator's own IP. The server log confirms root and unknown users are refused by "
          "AllowUsers, and fail2ban counted both failures.")

# ------------------------------------------------------------------ Part B
s += [PageBreak(), P("Part B — Container Security", "h1"),
      P("The workload is CAN's EHR simulator (Flask), previously built from "
        "<font name='Courier'>python:3.12-slim</font>. It was scanned with <b>Trivy</b>, rebuilt with a "
        "hardened Dockerfile, run with hardened Docker settings, and scanned again.")]

s += step("B1", "Baseline scan — the original image")
s += [P("Trivy found <b>172 vulnerabilities</b> in the original image: 165 in Debian OS packages (44 HIGH, "
        "58 MEDIUM, 61 LOW, 2 UNKNOWN) and 7 in Python packages (Flask 3.0.3 and pip 25.0.1). None of the 44 HIGH "
        "OS findings had a fix available — they sit in packages the app never uses (util-linux, mount, login), "
        "so patching could not remove them; only removing the packages could.")]
s += figure(6, "Trivy baseline scan — can-ehr-simulator:baseline: 165 OS vulnerabilities, Flask (1) and "
               "pip (6) findings.")
s += figure(7, "Trivy baseline detail — HIGH findings in util-linux, coreutils, acl and related base packages "
               "with no fixed version.")

s += step("B2", "Secure Dockerfile")
s += [P("The Dockerfile was rewritten as a multi-stage build. Dependencies are installed in a throwaway build "
        "stage; the runtime stage is Chainguard's minimal Python image, which contains no shell, no package "
        "manager and no pip. Both base images are <b>pinned by digest</b> so a build cannot silently change. "
        "Application files are owned by root and read-only to the non-root runtime user, Flask's development "
        "server is replaced by <b>gunicorn</b>, a <font name='Courier'>.dockerignore</font> allow-lists only "
        "the two files the build needs, and a HEALTHCHECK is defined.")]
s += code(read("can-ehr-container/Dockerfile"), "can-ehr-container/Dockerfile")

s += step("B3", "Docker security settings")
s += [P("The container is run from <font name='Courier'>docker-compose.secure.yml</font> with a read-only root "
        "filesystem (only a small noexec <font name='Courier'>/tmp</font>), every Linux capability dropped, "
        "privilege escalation blocked, process/memory/CPU limits, the port published on localhost only, an "
        "isolated bridge network and log rotation.")]
s += code(read("can-ehr-container/docker-compose.secure.yml"), "can-ehr-container/docker-compose.secure.yml")
s += optional_shot("Container - Dockerfile.png", "dockerfile",
                   "Terminal — the hardened Dockerfile on disk (cat Dockerfile).")
s += optional_shot("Container - Compose.png", "compose",
                   "Terminal — hardened Docker runtime settings (cat docker-compose.secure.yml).")

s += step("B4", "Runtime verification of the Docker settings")
s += code(read("can-ehr-container/reports/hardened/runtime-security-tests.txt"),
          "reports/hardened/runtime-security-tests.txt (tests run inside the live container)")
s += optional_shot("Container - Runtime tests.png", "runtime",
                   "Terminal — runtime security test results from the live container.")

s += step("B5", "Hardened scan — after")
s += [P("The rebuilt image scans clean: <b>0 vulnerabilities</b> in the OS layer and in every Python package, "
        "0 secrets and 0 Dockerfile misconfigurations. The image also shrank from 223 MB to 105 MB, and a "
        "CycloneDX SBOM was generated (<font name='Courier'>reports/hardened/sbom.cdx.json</font>).")]
s += figure(17, "Trivy scan of the hardened image can-ehr-simulator:2.0 (wolfi) — 0 vulnerabilities in "
                "every target.")
s += table([
    ["Metric", "Baseline (python:3.12-slim)", "Hardened (Chainguard, multi-stage)"],
    ["Total vulnerabilities", "172", "<b>0</b>"],
    ["HIGH / CRITICAL", "44 / 0", "0 / 0"],
    ["Image size", "223 MB", "105 MB"],
    ["Shell / pip / package manager", "Yes / yes / apt", "None"],
    ["Web server", "Flask development server", "gunicorn 23.0.0"],
    ["Runtime user", "appuser (non-root)", "UID 65532 (non-root), read-only files"],
], [1.9 * inch, 2.2 * inch, 2.4 * inch])
s += note("Google's distroless image was tried first, but Trivy showed it was <i>worse</i> (283 findings, "
          "including 2 CRITICAL) because it is built on older Debian 12 packages. Scanning every candidate base "
          "image before adopting it caught this; Chainguard's Wolfi-based image was chosen instead.",
          "Issue encountered")

# ------------------------------------------------------------------ Part C
s += [PageBreak(), P("Part C — Serverless Function: IAM &amp; Network Isolation", "h1"),
      P("A Python HTTP-triggered Azure Function (<font name='Courier'>ehr_status</font>) reads synthetic "
        "referral records from blob storage. The function, its identity, its storage and its network were all "
        "locked down so that it holds no secrets, has only the access it needs, and is reachable only from "
        "approved locations.")]

s += step("C1", "Function App on Flex Consumption")
s += figure(8, "Function App func-can-ehr-9a8c96 — Flex Consumption plan, Linux, 512 MB instances, "
               "ehr_status HTTP function enabled.")

s += step("C2", "IAM — managed identity with a single least-privilege role")
s += [P("The function authenticates to Azure with a dedicated <b>user-assigned managed identity</b>, "
        "<b>id-can-func</b>. Azure issues and rotates its tokens, so there are no passwords, keys or connection "
        "strings in code or configuration. The identity holds exactly <b>one role</b> — "
        "<i>Storage Blob Data Owner</i> — scoped to <b>one storage account</b> "
        "(stcanfunc9a8c964b), and nothing at subscription or resource-group level. The Functions host itself "
        "also uses this identity (<font name='Courier'>AzureWebJobsStorage__credential = managedidentity</font>).")]
s += figure(9, "User-assigned managed identity id-can-func (client ID 913070b7-…).", max_h=2.4 * inch)
s += code(open(os.path.join(DATA, "storage-iam.txt")).read(),
          "az role assignment list — id-can-func holds exactly one role, on one storage account")
s += optional_shot("Serverless - Storage IAM.png", "iam",
                   "Storage account stcanfunc9a8c964b → Access Control (IAM) → Role assignments: "
                   "id-can-func with Storage Blob Data Owner.")
s += figure(11, "Function app settings — identity-based storage settings only; no AccountKey, connection "
                "string or secret is stored.")
s += note("Azure's function-creation wizard inserted a storage <b>account key</b> into AzureWebJobsStorage by "
          "default. It was replaced with the three identity-based settings shown above and deleted, and key-based "
          "access was then disabled on the storage account, so the original key can no longer be used even if "
          "leaked.", "Issue encountered")

s += step("C3", "Network isolation")
s += [P("Outbound, the function is integrated into the private subnet <b>snet-func</b> (with NSG func-sg), so its "
        "calls to storage leave through the VNet. Inbound, access restrictions allow only the administrator's IP "
        "and deny everything else, for both the function endpoint and its deployment (SCM) endpoint. The storage "
        "account's firewall denies by default and accepts only snet-func and the administrator IP, with no "
        "trusted-service bypass.")]
s += figure(10, "Function networking — public access 'Enabled with access restrictions'; outbound VNet "
                "integration to can-vnet-cloudsec1/snet-func with NSG func-sg.")
s += figure(12, "Function configuration — HTTPS only, minimum inbound TLS 1.2 (site and SCM), SCM basic-auth "
                "publishing credentials disabled.")
s += figure(14, "Storage networking — public network access 'Enabled from selected networks': 1 virtual "
                "network rule (snet-func) and 1 IPv4 rule (admin IP); no exceptions.")
s += figure(15, "Storage configuration — secure transfer required, anonymous blob access disabled, "
                "storage account key access disabled.")
s += figure(13, "Storage overview — key access Disabled, minimum TLS 1.2, anonymous access Disabled.")

s += step("C4", "Security tests")
tests = read("can-ehr-serverless/evidence/security-tests.txt")
tests = tests.split("<h1")[0] + "<h1 id=\"unavailable\">Error 403 - Forbidden</h1> ...  [403]"
s += code(tests, "can-ehr-serverless/evidence/security-tests.txt")
s += [P("For the negative test, the allow rule was temporarily changed to a different IP (203.0.113.10). A call "
        "from the administrator's real IP with a <b>valid function key</b> was then refused with 403 — "
        "proving the network restriction is enforced independently of the key. The rule was restored "
        "afterwards.")]

# ------------------------------------------------------------------ Issues + compliance
s += [PageBreak(), P("Issues Encountered &amp; Resolutions", "h1")]
s += table([
    ["Issue", "Resolution"],
    ["Bastion host (Basic) and Standard container registry were costing ~$5/day against limited credit",
     "Bastion and its public IP deleted; ACR downgraded Standard → Basic. VM SSH instead restricted by "
     "NSG + ufw to the admin IP."],
    ["Standard_B1s (and other B-series) unavailable in East US due to capacity/quota limits on the subscription",
     "Queried unrestricted SKUs per region; deployed Standard_F1als_v7 in North Central US on its own VNet."],
    ["Distroless base image scanned worse than the original (283 findings, 2 CRITICAL)",
     "Rejected after scanning; switched to Chainguard Wolfi image (0 findings)."],
    ["Chainguard build stage runs as non-root, so pip could not write /deps",
     "USER root in the throwaway build stage only; runtime stage remains UID 65532."],
    ["Function created with a storage account key in its settings",
     "Replaced with managed-identity settings; key access disabled on the storage account."],
    ["Function creation silently granted the identity a second role (Storage Blob Data Contributor) "
     "alongside Owner", "Found by auditing role assignments; redundant role removed and the function "
     "re-tested (200 OK), leaving exactly one role."],
    ["An IPv6 'other IP' test was invalid (host has no IPv6, so it still used the allowed IPv4)",
     "Discarded; replaced with a controlled test that temporarily allowed only a different IP (403)."],
], [3.0 * inch, 3.5 * inch])

s += [P("Compliance &amp; Control Mapping", "h1")]
s += table([
    ["Control area", "HIPAA Security Rule", "NIST CSF 2.0", "CAN evidence"],
    ["Automated patching", "§164.308(a)(5)(ii)(B) Protection from malicious software",
     "PR.PS-02 (software maintained)", f"Steps A1–A2, {figs(2)}"],
    ["Host &amp; network firewall", "§164.312(e)(1) Transmission security",
     "PR.IR-01 (networks protected)", f"Step A3, {figs(3)}, IP flow verify"],
    ["Secure SSH / authentication", "§164.312(d) Person or entity authentication; "
     "§164.312(a)(1) Access control", "PR.AA-03 (users authenticated)", f"Steps A4–A5, {figs(4, 5)}"],
    ["Logging &amp; brute-force detection", "§164.312(b) Audit controls",
     "DE.CM-09 / PR.PS-04 (logs generated)", "fail2ban, ufw logging, sshd VERBOSE"],
    ["Container vulnerability scanning", "§164.308(a)(1)(ii)(A) Risk analysis",
     "ID.RA-01 (vulnerabilities identified)", f"Steps B1, B5, {figs(6, 7, 17)}"],
    ["Secure container configuration", "§164.308(a)(1)(ii)(B) Risk management",
     "PR.PS-01 (configuration management)", f"Steps B2–B4 {figs('dockerfile', 'compose', 'runtime')}".strip()],
    ["Least-privilege workload identity", "§164.308(a)(4) Information access management",
     "PR.AA-05 (access permissions managed)", f"Step C2, {figs(9, 'iam', 11)}"],
    ["Serverless network isolation", "§164.312(e)(1) Transmission security",
     "PR.IR-01 (networks protected)", f"Steps C3–C4, {figs(10, 12, 14, 15, 13)}"],
], [1.45 * inch, 1.85 * inch, 1.55 * inch, 1.65 * inch])

s += [P("Implementation Status", "h2"),
      P("<b>Implemented &amp; verified:</b> VM hardening (two-layer automated patching, NSG + ufw firewall, "
        "key-only SSH with fail2ban, Trusted Launch); container hardening (multi-stage digest-pinned Chainguard "
        "image, hardened runtime settings, Trivy 172 → 0); serverless isolation (managed identity with a "
        "single scoped role, no keys, VNet integration, storage firewall, IP restrictions, HTTPS/TLS 1.2).")]
s += [P("Known gaps &amp; next steps", "h2")]
s += bullets([
    "The container registry's admin user is still enabled because the existing container instance "
    "(aci-app-test) pulls with it. Next step: recreate the instance with a managed identity holding AcrPull, "
    "then disable the admin user.",
    "Storage and function are reached over public endpoints restricted by firewall/IP rules. Private endpoints "
    "would remove public exposure entirely but add ~$7/month each; deferred under the cost constraint.",
    "The VM uses a public IP restricted to one admin address. In production, access would be through Azure "
    "Bastion or a VPN with no public IP (Bastion was removed here for cost).",
    "Trivy should run automatically in CI on every build so a new vulnerability fails the build.",
])

doc = SimpleDocTemplate(OUT, pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=0.85 * inch,
                        bottomMargin=0.95 * inch,
                        title="CAN CloudSec1 - Cloud Infrastructure Security & Container Protection Evidence",
                        author="Akhila Chennamaneni")
doc.build(s, onFirstPage=footer, onLaterPages=footer)
print("wrote", OUT)
print("screenshots not yet supplied:", MISSING or "none")
