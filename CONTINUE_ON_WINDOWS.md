# Continuing This Work on Windows

This repo is worked on from two machines: a **Mac** and a **Windows laptop**.
GitHub is the bridge between them: **push** when you finish on one machine, **pull** when you start on the other.

Repo: <https://github.com/Akchrao/dae_6mon_coh2_AC>

---

## 1. One-time setup on the Windows laptop

### Install
| Tool | Why | Where |
|---|---|---|
| Git for Windows | clone / pull / push | <https://git-scm.com/download/win> (defaults are fine) |
| Docker Desktop | runs CISO Assistant and the labs | <https://www.docker.com/products/docker-desktop/> (enable **WSL 2** when asked, then reboot) |
| VS Code (optional) | editing | <https://code.visualstudio.com/> |

### Configure Git (open **PowerShell**)
```powershell
git config --global user.name  "Akchrao"
git config --global user.email "<the same email you use on the Mac>"

# Mac uses LF line endings, Windows uses CRLF - this keeps them from showing up as fake changes
git config --global core.autocrlf true

# ciso-assistant-community has very deep folder paths; without this, clone fails with "Filename too long"
git config --global core.longpaths true
```

### Clone (use a SHORT path - not deep inside OneDrive/Documents)
```powershell
cd C:\
mkdir dev
cd C:\dev
git clone https://github.com/Akchrao/dae_6mon_coh2_AC.git
cd dae_6mon_coh2_AC
```
The first push to GitHub will ask you to sign in - pick **"Sign in with your browser"**.

> Already cloned earlier? Just run `git pull` inside the folder instead.

---

## 2. Running CISO Assistant on Windows

The full source is in `ciso-assistant-community\`. It runs in Docker (Mac version is **v4.1.5**, images tagged `:latest`).

1. Start **Docker Desktop** and wait until it says "Engine running".
2. In PowerShell:
   ```powershell
   cd C:\dev\dae_6mon_coh2_AC\ciso-assistant-community
   Set-ExecutionPolicy -Scope Process Bypass     # allows the .ps1 script for this window only
   .\docker-compose.ps1
   ```
   This pulls the images, starts everything, and asks you to create an admin (superuser) account.
3. Open **<https://localhost:8443>** and accept the self-signed certificate warning.

After the first time, start/stop with:
```powershell
docker compose up -d      # start
docker compose down       # stop
```

### ⚠️ Your CISO Assistant DATA is not in Git

Everything you entered in the app (frameworks, risk assessments, assets, users...) lives in
`ciso-assistant-community\db\` - a ~170 MB SQLite database. That folder is **git-ignored on purpose**
(it's too big for GitHub and contains secret keys). So a fresh Windows setup starts with an **empty** app.

To bring your Mac data over, pick one:

**Option A - Copy the `db` folder (simplest, exact copy)**
1. On the Mac: `cd ciso-assistant-community && docker compose down` (stops cleanly so nothing is lost mid-write).
2. Copy the whole `ciso-assistant-community/db/` folder to a USB stick / Google Drive / OneDrive.
3. On Windows, put it at `C:\dev\dae_6mon_coh2_AC\ciso-assistant-community\db\`
   (replace it if one exists - stop Docker first with `docker compose down`).
4. Start with **`docker compose up -d`** - do **not** run `docker-compose.ps1` (it refuses when a DB already exists).
5. Log in with your **Mac** username and password.

**Option B - Use the app's built-in backup**
1. On the Mac app: left sidebar → **Extra → Backup & restore** → download a backup.
2. Set up Windows as in steps 1–3 above, then go to the same page and **restore** the file.
3. Both machines should be on the same app version (v4.1.5) - if the restore complains, that's the likely cause.

Do the same in reverse when you go back to the Mac. **Only work in the app on one machine at a time**, or
you'll end up with two different databases that can't be merged.

---

## 3. Daily workflow (both machines)

**When you sit down:**
```bash
git pull
```

**When you're done:**
```bash
git add .
git commit -m "short description of what you did"
git push
```

Forgot to push on the other machine? `git pull` will just say "Already up to date" - go back and push from there first.

---

## 4. Gotchas

- **GitHub rejects files over 100 MB.** `.zip` files are now ignored for this reason (the original
  `ciso-assistant-community.zip` was 400 MB). Keep big downloads/archives out of the repo.
- **Never commit `.env` files or `db/` folders** - they hold passwords and secret keys.
  Note: `care-access-navigator-iam-lab/.env` was committed in the past; treat those lab passwords as public.
- **`.ps1` vs `.sh`:** on Windows use the `.ps1` version of a script; `.sh` scripts are for Mac/Linux.
- **"Filename too long"** → you skipped `core.longpaths true` (see section 1).
- **Every file shows as modified after cloning** → you skipped `core.autocrlf true`; run it, then `git checkout .`
  (only if you have no real changes yet).
- **Port already in use (8443)** → something else is running; `docker ps` to see, `docker compose down` in the other project.
- **Docker is very slow** → keep the repo on `C:\`, not on OneDrive or a network drive.
