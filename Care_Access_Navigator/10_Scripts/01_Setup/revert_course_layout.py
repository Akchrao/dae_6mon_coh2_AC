#!/usr/bin/env python3
"""revert_course_layout.py - undo the semester grouping of reorganize_repo.py (2026-11-05, user request).

Layout after this script:
  <course>/                     every course at the repository root in lower case, with its task documents and evidence
  Status_Updates_and_Teachback/ every weekly/semester status update and every teach-back deck, original file names
  Care_Access_Navigator/        capstone workspace (unchanged, except its status updates moved out)
  Semester_2 ... Semester_5     removed (empty after the moves)

Whole directories are moved with shutil.move, so untracked/ignored files (CISO Assistant database, lab keys, venvs)
move too. Stop CISO Assistant (docker compose down) before running. Run from the repository root:
    python3 Care_Access_Navigator/10_Scripts/01_Setup/revert_course_layout.py [--dry-run]
"""
import os, shutil, sys

DRY = "--dry-run" in sys.argv
CAN = "Care_Access_Navigator"
WS = f"{CAN}/08_Reporting/01_Weekly_Status"
ST = "Status_Updates_and_Teachback"
CISO_NEW = "ciso-assistant-community"

COURSES = [  # (current, new root folder)
    ("Semester_2/Figma_1", "figma_1"), ("Semester_2/Python_1", "python_1"),
    ("Semester_2/Prompt_Engineering_1", "prompt_engineering_1"), ("Semester_2/Markdown_Activity", "markdown_activity"),
    ("Semester_2/Project_MoodBuddy", "project_moodbuddy"), ("Semester_2/Logic_1", "logic_1"),
    ("Semester_2/Design_1", "design_1"), ("Semester_2/Version_Control_1", "version_control_1"),
    ("Semester_3/Unix_1", "unix_1"), ("Semester_3/Unix_2", "unix_2"), ("Semester_3/Network_Security_1", "network_security_1"),
    ("Semester_3/Cyber_Threats_and_Vulnerabilities_1", "cyber_threats_and_vulnerabilities_1"),
    ("Semester_4/Risk_Management_1", "risk_management_1"), ("Semester_4/Cloud_Security_1", "cloud_security_1"),
    ("Semester_5/Compliance_1", "compliance_1"), ("Semester_5/Incident_Response_1", "incident_response_1"),
]
# teach-backs and status updates -> one folder, original (pre-2026-11-03) file names
DECKS = [
    ("Semester_2/Version_Control_1/Git_Weekly_Status_Update.pptx", "Weekly_Status_Update.pptx"),
    ("Semester_3/Teachbacks/Teachback_Linux_Cybersecurity.pdf", "Linux_CyberSecurity_Teachback_Session.pptx.pdf"),
    ("Semester_3/Teachbacks/Teachback_OSI_TCPIP.pptx", "OSI_TCPIP_Teach_Back.pptx"),
    ("Semester_3/Teachbacks/Teachback_Session_Token_Hijacking.pptx", "Session_Token_Hijacking_Teach_Back_Explained.pptx"),
    ("Semester_4/Teachbacks/Teachback_Workload_Identity_Federation.pptx",
     "Care_Access_Navigator_Workload_Federation_Teachback_With_Terms_Slide.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Sem2_Week2_v1.0.pptx", "Weekly_Status_Update_week2_Sem2.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Sem2_Week2_v1.0.pdf", "Weekly_Status_Update_week2_Sem2.pdf"),
    (f"{WS}/CAN_DOC_Status_Update_Sem2_Week3_v1.0.pdf", "Status_Update_Semester_2_Week_3_Akhila.docx.pdf"),
    (f"{WS}/CAN_DOC_Monthly_Update_Sem2_v1.0.pptx",
     "Second_Semester_Monthly_Update_Cybersecurity_Cohort_Clearer_Google_Compatible_Final.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Sem3_Week1_v1.0.pptx", "Semester3_Week1_Status_Update_Care_Access_Navigator_Professional.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Week3_v1.0.pptx", "HRMC_Week3_Status_Update.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Sem4_Week2_v1.0.pptx",
     "Care_Access_Navigator_HRMC_Sem4_Week2_Status_Update_Akhila_Ch_Arrows_Fixed_1.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Sem4_Week3_v1.0.pptx", "HRMC_Care_Access_Navigator_Weekly_Status_Sem4_Week3.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Sem4_Week5_v1.0.pptx", "Care_Access_Navigator_Weekly_Status_Update_Sem4_Week5.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Sem5_Week1_v1.0.pptx", "Care_Access_Navigator_Sem5_Week1_Status_Update.pptx"),
    (f"{WS}/CAN_DOC_Status_Update_Sem5_Week3_v1.0.pptx", "Care_Access_Navigator_Sem5_Week3.pptx"),
]
# root folders that only hold a "moved" pointer README (replaced by the real folder or no longer needed)
POINTERS = [new for _, new in COURSES if new not in ("logic_1", "design_1", "version_control_1", "unix_1")] + ["learning"]


GONE = set()  # dry run: paths that would have been removed


def say(msg):
    print(("[dry] " if DRY else "") + msg)


def only_pointer(d):
    """True if folder d holds nothing but README.md / .DS_Store (safe to replace)."""
    return all(f in ("README.md", ".DS_Store") for f in os.listdir(d))


def move(src, dst):
    if os.path.exists(dst) and dst not in GONE:
        sys.exit(f"STOP: destination exists: {dst}")
    say(f"move  {src}  ->  {dst}")
    if not DRY:
        if os.path.dirname(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)


def rm_tree_if_only(d, allowed=("README.md", ".DS_Store")):
    """Delete d only if every file left in it is a pointer README or .DS_Store."""
    if not os.path.isdir(d):
        return
    if DRY and d.startswith("Semester_"):
        say(f"rmdir {d} (checked for leftovers on the real run)")
        return
    left = [os.path.join(r, f) for r, _, fs in os.walk(d) for f in fs if f not in allowed]
    if left:
        sys.exit(f"STOP: {d} still holds files: {left[:5]}")
    say(f"rmdir {d}")
    GONE.add(d)
    if not DRY:
        shutil.rmtree(d)


# 0) checks
for src, _ in COURSES + DECKS:
    if not os.path.exists(src):
        sys.exit(f"STOP: missing {src}")
for d in POINTERS:
    if os.path.exists(d) and not only_pointer(d):
        sys.exit(f"STOP: {d} holds more than a pointer README: {os.listdir(d)}")
for f in os.listdir(CISO_NEW):
    if f not in ("README.md", ".DS_Store") and os.path.exists(f"Semester_5/CISO_Assistant/{CISO_NEW}/{f}"):
        sys.exit(f"STOP: {CISO_NEW}/{f} would overwrite a CISO Assistant file")

# 1) teach-backs and status updates (before the course folders move, so source paths are still valid)
st_readme = os.path.join(ST, "README.md")
if os.path.exists(st_readme):
    say(f"del   {st_readme} (pointer)")
    if not DRY:
        os.remove(st_readme)
for src, name in DECKS:
    move(src, os.path.join(ST, name))

# 2) courses: drop the root pointer folder, then move the real folder to the root
for src, dst in COURSES:
    if os.path.isdir(dst):
        rm_tree_if_only(dst)
    move(src, dst)

# 3) CISO Assistant: real folder to the root; the files already at the root (exports, GRC docx) go inside it
tmp = CISO_NEW + "__root_files"
say(f"move  {CISO_NEW}  ->  {tmp} (exports + docx kept; pointer README dropped)")
GONE.add(CISO_NEW)
if not DRY:
    os.rename(CISO_NEW, tmp)
move(f"Semester_5/CISO_Assistant/{CISO_NEW}", CISO_NEW)
for f in sorted(os.listdir(tmp) if not DRY else []):
    if f in ("README.md", ".DS_Store"):
        continue
    move(os.path.join(tmp, f), os.path.join(CISO_NEW, f))
if not DRY:
    shutil.rmtree(tmp)
move("Semester_5/CISO_Assistant/Learning_Plan", f"{CISO_NEW}/learning_plan")
rm_tree_if_only("learning")

# 4) course stubs: fix links that pointed at the old Semester_2 names; give empty unix_1 a placeholder
if not DRY:
    for d in ("logic_1", "design_1", "version_control_1"):
        p = os.path.join(d, "README.md")
        s = open(p).read().replace("../Project_MoodBuddy/", "../project_moodbuddy/").replace(
            "The Git weekly status deck is `Git_Weekly_Status_Update.pptx`.",
            "The Git weekly status deck is `../Status_Updates_and_Teachback/Weekly_Status_Update.pptx`.")
        open(p, "w").write(s)
    if not [f for f in os.listdir("unix_1") if f != ".DS_Store"]:
        open("unix_1/test.txt", "w").write("")
say("fix   course stub READMEs; unix_1/test.txt placeholder")

# 4b) capstone file pushed from Windows into the old Semester_3 pointer folder
move("Semester_3/Care_Access_Navigator/01_Docs/Care_Access_Navigator_RBAC_Model.docx.pdf",
     f"{CAN}/01_Docs/Care_Access_Navigator_RBAC_Model.docx.pdf")

# 5) remove the semester folders (only pointer READMEs / .DS_Store may be left)
for d in ("Semester_3/Care_Access_Navigator", "Semester_3/Teachbacks", "Semester_4/Teachbacks", "Semester_5/CISO_Assistant",
          "Semester_2", "Semester_3", "Semester_4", "Semester_5"):
    rm_tree_if_only(d)
print("done (dry run)" if DRY else "done")
