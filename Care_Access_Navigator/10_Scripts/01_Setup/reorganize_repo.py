#!/usr/bin/env python3
"""reorganize_repo.py - one-time reorganisation of the repository (2026-11-03).

Layout:
  Care_Access_Navigator/   capstone workspace (01_Docs ... 10_Scripts, per CAN_DOC_Workspace_Structure_v0.1),
                           files named per CAN_STD_Naming_Standards_v0.1
  Semester_2 ... Semester_5/<Course>/   course folders, moved whole (internal file names unchanged:
                           reports and evidence hash indexes refer to them)
  Career_Resources/, docs/ (website), CONTINUE_ON_WINDOWS.md stay at the root.

Moves whole directories with mv (so ignored/untracked files such as lab keys and databases move too);
git add -A afterwards records the renames. Run from the repository root:  python3 reorganize_repo.py [--dry-run]
"""
import os, shutil, subprocess, sys

DRY = "--dry-run" in sys.argv
CAN = "Care_Access_Navigator"
P = f"{CAN}/01_Docs/01_Project_Planning"
MOVES = [
    # ---- capstone workspace to the root (was under Semester_3)
    ("Semester_3/Care_Access_Navigator", CAN),
    # ---- courses by semester (whole folders)
    ("figma_1", "Semester_2/Figma_1"), ("python_1", "Semester_2/Python_1"),
    ("prompt_engineering_1", "Semester_2/Prompt_Engineering_1"), ("markdown_activity", "Semester_2/Markdown_Activity"),
    ("project_moodbuddy", "Semester_2/Project_MoodBuddy"),
    ("unix_1", "Semester_3/Unix_1"), ("unix_2", "Semester_3/Unix_2"), ("network_security_1", "Semester_3/Network_Security_1"),
    ("cyber_threats_and_vulnerabilities_1", "Semester_3/Cyber_Threats_and_Vulnerabilities_1"),
    ("risk_management_1", "Semester_4/Risk_Management_1"), ("cloud_security_1", "Semester_4/Cloud_Security_1"),
    ("compliance_1", "Semester_5/Compliance_1"), ("incident_response_1", "Semester_5/Incident_Response_1"),
    ("ciso-assistant-community", "Semester_5/CISO_Assistant/ciso-assistant-community"),
    ("learning/PLAN_CISO_Newtool.md", "Semester_5/CISO_Assistant/Learning_Plan/PLAN_CISO_Newtool.md"),
    ("learning/PLAN.md", "Semester_5/CISO_Assistant/Learning_Plan/PLAN_Template.md"),
    ("learning/NOTES.md", "Semester_5/CISO_Assistant/Learning_Plan/NOTES.md"),
    ("learning/TUTORIAL.md", "Semester_5/CISO_Assistant/Learning_Plan/TUTORIAL.md"),
    ("learning/mock_interview.md", "Career_Resources/Mock_Interview.md"),
    # ---- course decks into their semester
    ("Status_Updates_and_Teachback/Weekly_Status_Update.pptx", "Semester_2/Version_Control_1/Git_Weekly_Status_Update.pptx"),
    ("Status_Updates_and_Teachback/Linux_CyberSecurity_Teachback_Session.pptx.pdf", "Semester_3/Teachbacks/Teachback_Linux_Cybersecurity.pdf"),
    ("Status_Updates_and_Teachback/OSI_TCPIP_Teach_Back.pptx", "Semester_3/Teachbacks/Teachback_OSI_TCPIP.pptx"),
    ("Status_Updates_and_Teachback/Session_Token_Hijacking_Teach_Back_Explained.pptx", "Semester_3/Teachbacks/Teachback_Session_Token_Hijacking.pptx"),
    ("Status_Updates_and_Teachback/Care_Access_Navigator_Workload_Federation_Teachback_With_Terms_Slide.pptx", "Semester_4/Teachbacks/Teachback_Workload_Identity_Federation.pptx"),
    # ---- 01_Docs / project planning
    ("Semester_2/Care_Access_Navigator_Project_Design_Documentation_IAM_GRC.docx", f"{P}/CAN_DOC_Project_Design_Documentation_v1.0.docx"),
    ("Semester_2/EDU_DOC_Project_Design_Documentation.docx", f"{P}/CAN_DOC_Project_Design_Documentation_DAE_Template_v0.1.docx"),
    ("extra/EDU_DOC_Project_Design_Documentation_Care_Access_Navigator_DAE_Template_Completed.docx", f"{P}/CAN_DOC_Project_Design_Documentation_DAE_Template_v1.0.docx"),
    ("capstone_next_steps/Care_Access_Navigator_Project_Design_Documentation_IAM_GRC_v1.2.docx", f"{P}/CAN_DOC_Project_Design_Documentation_v1.2.docx"),
    (f"{CAN}/01_Docs/Care_Access_Navigator_Project_Design_Documentation.md", f"{P}/CAN_DOC_Project_Design_Documentation_v1.0.md"),
    ("extra/Care_Access_Navigator_IAM_GRC_12_Week_Project_Document.docx", f"{P}/CAN_DOC_12_Week_Project_Plan_v1.0.docx"),
    ("extra/Akhila_s_Project_Board_1786379037.xlsx", f"{P}/CAN_DOC_Monday_Project_Board_Export_20260810.xlsx"),
    ("capstone_next_steps/Care_Access_Navigator_Capstone_Readiness_Audit_and_Roadmap.docx", f"{P}/CAN_DOC_Capstone_Readiness_Audit_and_Roadmap_v1.0.docx"),
    ("capstone_next_steps/Care_Access_Navigator_Capstone_Readiness_Audit_and_Roadmap_v2.docx", f"{P}/CAN_DOC_Capstone_Readiness_Audit_and_Roadmap_v2.0.docx"),
    (f"{P}/HRMC_Day1_Detailed_Objective_Scope_Baseline.pdf", f"{P}/CAN_DOC_Week1_Day1_Objective_Scope_Baseline_v1.0.pdf"),
    (f"{P}/HRMC_Day2_Objectives_Scope_Requirements.pdf", f"{P}/CAN_DOC_Week1_Day2_Objectives_Scope_Requirements_v1.0.pdf"),
    (f"{P}/HRMC_Day3_Establish_Risk_Compliance_Foundation.pdf", f"{P}/CAN_DOC_Week1_Day3_Risk_Compliance_Foundation_v1.0.pdf"),
    (f"{P}/HRMC_Day4_Establish_High_Level_Architecture_Data_Flow.pdf", f"{P}/CAN_DOC_Week1_Day4_High_Level_Architecture_Data_Flow_v1.0.pdf"),
    (f"{P}/HRMC_Week2_Day1_Foundation_Structure_Plan.docx.pdf", f"{P}/CAN_DOC_Week2_Day1_Foundation_Structure_Plan_v1.0.pdf"),
    # ---- 03_IAM_Lab
    ("Claude outputs/Care_Access_Navigator_Keycloak_EntraID_Build_Log.docx", f"{CAN}/03_IAM_Lab/CAN_DOC_Keycloak_EntraID_Build_Log_v1.0.docx"),
    ("care-access-navigator-iam-lab/docker-compose.yml", f"{CAN}/03_IAM_Lab/01_Keycloak/01_Config/docker-compose.yml"),
    ("care-access-navigator-iam-lab/.env", f"{CAN}/03_IAM_Lab/01_Keycloak/01_Config/.env"),
    # ---- 06_Evidence: screenshots (EV-##_Description_YYYYMMDD) and the JML evidence package (kept intact)
    ("keycloak_EntraID/Microsoft Entra ID overview page 1.png", f"{CAN}/06_Evidence/01_Screenshots/EV-02_Entra_ID_Overview_Page1_20260921.png"),
    ("keycloak_EntraID/Microsoft Entra ID overview page 2.png", f"{CAN}/06_Evidence/01_Screenshots/EV-03_Entra_ID_Overview_Page2_20260921.png"),
    ("keycloak_EntraID/Entra ID - Keycloak connect point.png", f"{CAN}/06_Evidence/01_Screenshots/EV-04_Entra_ID_Keycloak_Connect_Point_20260921.png"),
    ("keycloak_EntraID/Federated user confirmation page.png", f"{CAN}/06_Evidence/01_Screenshots/EV-05_Federated_User_Confirmation_20260921.png"),
    ("keycloak_EntraID/Microsoft Entra ID application page.png", f"{CAN}/06_Evidence/01_Screenshots/EV-06_Entra_ID_Application_Page_20260922.png"),
    ("keycloak_EntraID/Before Authentication Page.png", f"{CAN}/06_Evidence/01_Screenshots/EV-07_Keycloak_Before_Authentication_20260922.png"),
    ("keycloak_EntraID/Keycloak password authentication policies page.png", f"{CAN}/06_Evidence/01_Screenshots/EV-08_Keycloak_Password_Policies_20260922.png"),
    ("keycloak_EntraID/Brute force detection settings page.png", f"{CAN}/06_Evidence/01_Screenshots/EV-09_Keycloak_Brute_Force_Detection_20260922.png"),
    ("keycloak_EntraID/Duplicating authentication page for mfa.png", f"{CAN}/06_Evidence/01_Screenshots/EV-10_Keycloak_MFA_Authentication_Flow_20260922.png"),
    ("keycloak_EntraID/VNet address space creation.png", f"{CAN}/06_Evidence/01_Screenshots/EV-11_Azure_VNet_Address_Space_20260923.png"),
    ("keycloak_EntraID/Network Security Groups.png", f"{CAN}/06_Evidence/01_Screenshots/EV-12_Azure_Network_Security_Groups_20260923.png"),
    ("capstone_next_steps/jml-evidence", f"{CAN}/06_Evidence/07_JML_Lifecycle"),
    # ---- 07_GRC
    ("capstone_next_steps/Care_Access_Navigator_Rubric_Traceability_Matrix.xlsx", f"{CAN}/07_GRC/03_Compliance/CAN_DOC_Rubric_Traceability_Matrix_v1.1.xlsx"),
    # ---- 08_Reporting
    ("Status_Updates_and_Teachback/Weekly_Status_Update_week2_Sem2.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem2_Week2_v1.0.pptx"),
    ("Status_Updates_and_Teachback/Weekly_Status_Update_week2_Sem2.pdf", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem2_Week2_v1.0.pdf"),
    ("Status_Updates_and_Teachback/Status_Update_Semester_2_Week_3_Akhila.docx.pdf", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem2_Week3_v1.0.pdf"),
    ("Status_Updates_and_Teachback/Second_Semester_Monthly_Update_Cybersecurity_Cohort_Clearer_Google_Compatible_Final.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Monthly_Update_Sem2_v1.0.pptx"),
    ("Status_Updates_and_Teachback/Semester3_Week1_Status_Update_Care_Access_Navigator_Professional.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem3_Week1_v1.0.pptx"),
    ("Status_Updates_and_Teachback/HRMC_Week3_Status_Update.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Week3_v1.0.pptx"),
    ("Status_Updates_and_Teachback/Care_Access_Navigator_HRMC_Sem4_Week2_Status_Update_Akhila_Ch_Arrows_Fixed_1.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem4_Week2_v1.0.pptx"),
    ("Status_Updates_and_Teachback/HRMC_Care_Access_Navigator_Weekly_Status_Sem4_Week3.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem4_Week3_v1.0.pptx"),
    ("Status_Updates_and_Teachback/Care_Access_Navigator_Weekly_Status_Update_Sem4_Week5.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem4_Week5_v1.0.pptx"),
    ("Status_Updates_and_Teachback/Care_Access_Navigator_Sem5_Week1_Status_Update.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem5_Week1_v1.0.pptx"),
    ("Status_Updates_and_Teachback/Care_Access_Navigator_Sem5_Week3.pptx", f"{CAN}/08_Reporting/01_Weekly_Status/CAN_DOC_Status_Update_Sem5_Week3_v1.0.pptx"),
    ("capstone_next_steps/tableau_dataset", f"{CAN}/08_Reporting/02_Dashboards/Tableau_Dataset"),
    # ---- 09_Portfolio
    ("capstone_next_steps/Care_Access_Navigator_MVP_Demo.pptx", f"{CAN}/09_Portfolio/04_Demo/CAN_DOC_MVP_Demo_v1.0.pptx"),
    ("capstone_next_steps/Care_Access_Navigator_MVP_Demo.pdf", f"{CAN}/09_Portfolio/04_Demo/CAN_DOC_MVP_Demo_v1.0.pdf"),
    ("capstone_next_steps/Care_Access_Navigator_MVP_Demo_IMAGES.pptx", f"{CAN}/09_Portfolio/04_Demo/CAN_DOC_MVP_Demo_Images_v1.0.pptx"),
    ("Status_Updates_and_Teachback/IAM_GRC_Healthcare_Portfolio_Pitch_Mock.pptx", f"{CAN}/09_Portfolio/04_Demo/CAN_DOC_Portfolio_Pitch_Mock_v1.0.pptx"),
    # ---- 10_Scripts
    ("capstone_next_steps/scripts", f"{CAN}/10_Scripts/02_IAM_Automation"),
    ("build.py", f"{CAN}/10_Scripts/01_Setup/build_monday_board.py"),
]
# redundant leftovers (identical to versions already in git history, or placeholders now that folders hold files)
DELETE = [
    "Claude outputs/Care_Access_Navigator_Project_Design_Documentation_IAM_GRC_v1.2.docx",   # = capstone copy @4fcf6db
    "Claude outputs/Care_Access_Navigator_Rubric_Traceability_Matrix.xlsx",                   # = capstone copy @4fcf6db
    "Claude outputs/Care_Access_Navigator_MVP_Demo.pptx",                                     # re-save of the same 13-slide deck (11 s apart)
    "Claude outputs/README.md", "learning/DS_Store", "learning/.DS_Store",
    f"{CAN}/02_Diagrams/01_Architecture/test.txt", f"{CAN}/03_IAM_Lab/01_Keycloak/01_Config/test.txt",
    f"{CAN}/07_GRC/03_Compliance/test.txt", f"{CAN}/08_Reporting/01_Weekly_Status/test.txt",
    f"{CAN}/08_Reporting/02_Dashboards/test.txt", f"{CAN}/09_Portfolio/04_Demo/test.txt", f"{CAN}/10_Scripts/01_Setup/test.txt",
]


def run(cmd):
    print("  $", " ".join(cmd)) if DRY else subprocess.run(cmd, check=True)


missing = [s for s, _ in MOVES if not os.path.exists(s) and not s.startswith(CAN + "/")]
if missing:
    sys.exit("missing sources:\n  " + "\n  ".join(missing))
# 1) the semester folders exist on disk in lower case (case-insensitive macOS); give them the case git uses
for low, proper in (("semester_2", "Semester_2"), ("semester_3", "Semester_3"), ("semester_4", "Semester_4"), ("career_resources", "Career_Resources")):
    real = [e for e in os.listdir(".") if e.lower() == low]
    if real and real[0] != proper:
        print(f"case: {real[0]} -> {proper}")
        if not DRY:
            os.rename(real[0], proper + ".tmp"); os.rename(proper + ".tmp", proper)
# 2) moves
for src, dst in MOVES:
    print(f"move  {src}  ->  {dst}")
    if not DRY and not os.path.exists(src):
        sys.exit(f"missing source at move time: {src}")
    if not DRY:
        if os.path.dirname(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)
# 2b) courses whose only file was the shared MoodBuddy deck (kept once in Project_MoodBuddy)
STUB = """# {name}

Semester 2 course. The course deliverable was the **MoodBuddy** project deck, which was submitted in several
Semester 2 courses; one copy is kept in [`../Project_MoodBuddy/MoodBuddy.pptx`](../Project_MoodBuddy/MoodBuddy.pptx)
(duplicate copies were removed on 2026-11-03). {extra}
"""
for folder, name, extra in (("Semester_2/Logic_1", "Logic 1", ""), ("Semester_2/Design_1", "Design 1", ""),
                            ("Semester_2/Version_Control_1", "Version Control 1", "The Git weekly status deck is `Git_Weekly_Status_Update.pptx`.")):
    print(f"stub  {folder}/README.md")
    if not DRY:
        os.makedirs(folder, exist_ok=True)
        open(os.path.join(folder, "README.md"), "w").write(STUB.format(name=name, extra=extra))
# 3) deletions
for f in DELETE:
    if os.path.lexists(f):
        print(f"del   {f}")
        if not DRY:
            os.remove(f)
# 4) remove folders left empty
for d in ("Claude outputs", "extra", "capstone_next_steps", "keycloak_EntraID", "care-access-navigator-iam-lab", "learning",
          "Status_Updates_and_Teachback", "Semester_3/Care_Access_Navigator"):
    if os.path.isdir(d) and not DRY:
        for root, dirs, files in os.walk(d, topdown=False):
            for f in files:
                if f == ".DS_Store":
                    os.remove(os.path.join(root, f))
            if not os.listdir(root):
                os.rmdir(root)
        print(f"rmdir {d}: {'removed' if not os.path.exists(d) else 'NOT EMPTY: ' + str(os.listdir(d))}")
print("done (dry run)" if DRY else "done")
