# DAE 6-Month Cybersecurity Cohort 2 — Akhila Chennamaneni

Coursework and the capstone project **Care Access Navigator** (IAM + GRC for HealthLine Regional Medical Center, HRMC).

## Layout

Every course has its own lower-case folder at the top level holding its task documents and evidence.

| Semester | Course folders |
|---|---|
| [Semester 2](Semester_2/) | [`logic_1/`](logic_1/), [`version_control_1/`](version_control_1/), [`design_1/`](design_1/), [`figma_1/`](figma_1/), [`python_1/`](python_1/), [`prompt_engineering_1/`](prompt_engineering_1/), [`markdown_activity/`](markdown_activity/), [`project_moodbuddy/`](project_moodbuddy/) |
| [Semester 3](Semester_3/) | [`unix_1/`](unix_1/), [`unix_2/`](unix_2/), [`network_security_1/`](network_security_1/), [`cyber_threats_and_vulnerabilities_1/`](cyber_threats_and_vulnerabilities_1/) |
| [Semester 4](Semester_4/) | [`risk_management_1/`](risk_management_1/), [`cloud_security_1/`](cloud_security_1/) |
| [Semester 5](Semester_5/) | [`compliance_1/`](compliance_1/), [`incident_response_1/`](incident_response_1/), [`ciso-assistant-community/`](ciso-assistant-community/) (CISO Assistant tool, learning plan and exports) |

`Semester_2/` … `Semester_5/` hold only a README describing what that semester covered and planned.

| Folder | Contents |
|---|---|
| [`Status_Updates_and_Teachback/`](Status_Updates_and_Teachback/) | Every weekly / semester status update and every teach-back deck |
| [`Care_Access_Navigator/`](Care_Access_Navigator/) | Capstone workspace, laid out per `CAN_DOC_Workspace_Structure_v0.1` (01_Docs … 10_Scripts); file names follow `CAN_STD_Naming_Standards_v0.1` |
| [`Career_Resources/`](Career_Resources/) | Job description activity, mock interview |
| [`docs/`](docs/) | GitHub Pages portfolio site and architecture decision records (`docs/adr/`) |
| [`CONTINUE_ON_WINDOWS.md`](CONTINUE_ON_WINDOWS.md) | How to continue this work on the Windows laptop |

## History

On 2026-11-03 the courses were grouped under `Semester_N/` folders
([`reorganize_repo.py`](Care_Access_Navigator/10_Scripts/01_Setup/reorganize_repo.py)). On 2026-11-05 they were moved back
to the top level and the status updates and teach-backs were gathered in one folder
([`revert_course_layout.py`](Care_Access_Navigator/10_Scripts/01_Setup/revert_course_layout.py)). Capstone-only folders from
before 2026-11-03 (`capstone_next_steps/`, `Claude outputs/`, `extra/`, `keycloak_EntraID/`,
`care-access-navigator-iam-lab/`) still hold a README pointing to where their files now live in `Care_Access_Navigator/`.
