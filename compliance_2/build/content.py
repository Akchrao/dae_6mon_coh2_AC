"""Single source of truth for the Compliance 2 workbook and document (HRMC expansion scenario)."""

ORG = "HealthLine Regional Medical Center (HRMC)"
AUTHOR = "Akhila Chennamaneni"

# Expansion scenario (fictional). HRMC = the capstone hospital; the EU and India entities are added for Compliance 2.
SITES = [
    ("US", "HRMC flagship hospital, Albany NY (capstone scenario)", 4_900, "Acute care, EHR, patient portal, billing", "HIPAA/HITECH, PCI DSS, NY law"),
    ("US", "2 community campuses + outpatient network, NY", 2_500, "Outpatient care, imaging", "HIPAA/HITECH, PCI DSS"),
    ("EU", "HealthLine Clinics Ireland (Dublin, Cork)", 1_150, "Outpatient + day surgery", "GDPR, Irish Data Protection Act 2018"),
    ("EU", "HealthLine Diagnostics Munich, Germany", 750, "Diagnostic imaging + lab", "GDPR, BDSG, German health-record law"),
    ("India", "HRMC Global Shared Services, Hyderabad", 1_500, "Revenue cycle (billing), IT service desk, 24x7 SOC", "DPDP Act 2023 (staff data); contracts for US/EU data"),
]

FRAMEWORKS = [
    ("HIPAA Security + Privacy Rules (HITECH breach rule)", "US law", "All US patient data; vendors under BAAs; India shared services as a business associate"),
    ("EU GDPR (+ Irish DPA 2018, German BDSG)", "EU law", "All EU patient and staff data; transfers to the US and India"),
    ("PCI DSS v4.0.1", "Card-brand contract", "Card payments at US billing and the Hyderabad revenue-cycle team"),
    ("ISO/IEC 27001:2022 (Annex A)", "Certifiable standard", "Common control backbone for the whole group; target certification 2028"),
    ("India DPDP Act 2023 + DPDP Rules 2025", "India law", "Hyderabad staff data in full; foreign patient data processed under contract: s.17(1)(d) exemption, but s.8(1) and s.8(5) security duties still apply"),
]

# conflicting requirements and how the integrated program resolves them
CONFLICTS = [
    ("Breach notification clock",
     "GDPR Art. 33: supervisory authority within 72 h of awareness; HIPAA 164.404/408: individuals and HHS without unreasonable delay, no later than 60 days (500+ people); DPDP Rules 2025: report to the Data Protection Board within 72 h; PCI DSS: notify acquirer / card brands immediately",
     "One global incident clock set to the strictest rule: preliminary regulator-ready report within 72 h for every incident involving personal data, HIPAA and card-brand notices issued in parallel well inside 60 days. Clock starts at SOC triage (SOC 1 playbook)."),
    ("Retention vs. erasure",
     "HIPAA 164.316(b)(2): keep compliance documentation 6 years; NY: adult medical records 6 years; Germany BGB 630f: patient records 10 years; GDPR Art. 5(1)(e) storage limitation and Art. 17 erasure; PCI DSS 10.5.1: audit logs 12 months; DPDP s.8(7): erase when the purpose is served",
     "Retention schedule by data class AND jurisdiction of the record, never a single global maximum. Medical records follow the local law; security logs 12 months then deleted; GDPR erasure requests are refused only under Art. 17(3)(b)/(c) with the legal obligation cited."),
    ("Cross-border transfers",
     "GDPR Chapter V: EU personal data may leave the EU only with adequacy (US: EU-US Data Privacy Framework for certified recipients) or SCCs + transfer impact assessment; India has no EU adequacy decision; DPDP s.16: transfers allowed except to countries the Government restricts; HIPAA: no localisation, but BAAs required",
     "EU patient data stays in an EU tenant. Hyderabad staff work through VDI on pseudonymised billing data; SCCs + transfer impact assessment for EU-to-India access; BAAs for US data; no Indian patient data in scope."),
    ("Legal basis for processing health data",
     "HIPAA: treatment, payment, operations without authorisation; GDPR Art. 9(2)(h): health care without consent but under professional secrecy; DPDP s.6-7: consent or a listed 'legitimate use'",
     "Purpose-and-basis register per region in CISO Assistant. No reliance on consent where GDPR/HIPAA give a care-delivery basis; consent notices only for Indian staff data and marketing."),
    ("Patients' and data subjects' access rights",
     "HIPAA 164.524: 30 days (+30 extension); GDPR Art. 15: 1 month (+2 for complex); DPDP s.11: right to information",
     "One request process with a 30-day global target (meets both); extensions only where the local law allows, logged in the tracker."),
    ("Workforce monitoring vs. employee privacy",
     "PCI DSS 10 and HIPAA 164.312(b) require activity logging and review; GDPR Art. 88 and German BetrVG s.87(1) no. 6 give the works council co-determination over monitoring technology",
     "SIEM monitoring limited to security purposes; works-council agreement in Munich before Wazuh rules go live; pseudonymised analyst views in the EU, names revealed only on escalation (SOC 1 workflow)."),
]

# unified control map: capstone controls (controls.csv) + GDPR and DPDP columns added for the expansion
GDPR_DPDP = {
    "AC-01": ("Art. 25(2), 32(1)(b)", "s.8(5)"), "AC-02": ("Art. 32(1)(b), 32(4)", "s.8(5)"),
    "AC-03": ("Art. 32(4)", "s.8(5)"), "AC-04": ("Art. 25(2)", "s.8(5)"), "AC-05": ("Art. 32(1)(b)", "s.8(5)"),
    "IA-01": ("Art. 32(1)(b)", "s.8(5)"), "IA-02": ("Art. 32(1)(b)", "s.8(5)"), "AR-01": ("Art. 32(1)(d)", "s.8(5)"),
    "VM-01": ("Art. 28", "s.8(2)"), "AU-01": ("Art. 5(2), 32(1)(d)", "s.8(5)"), "AU-02": ("Art. 33(1)", "s.8(6)"),
    "AU-03": ("Art. 5(1)(e) (conflict: storage limitation)", "s.8(7)"), "IR-01": ("Art. 33, 34", "s.8(6) + Rules"),
    "RA-01": ("Art. 32(2), 35 (DPIA)", "s.10 (SDF DPIA)"), "CA-01": ("Art. 5(2), 24(1)", "s.8(1)"),
    "SC-01": ("Art. 32(1)(a)", "s.8(5)"),
}
NEW_ENTERPRISE_CONTROLS = [  # added to reach the 48-control unified set (examples)
    ("PR-01", "Record of processing activities per region", "-", "Art. 30", "A.5.34", "-", "s.8(1)"),
    ("PR-02", "Data protection impact assessment before new high-risk processing", "164.308(a)(1)", "Art. 35", "A.5.34", "-", "s.10"),
    ("PR-03", "Cross-border transfer control (SCCs, TIA, DPF check)", "BAA 164.308(b)", "Art. 44-46", "A.5.14", "-", "s.16"),
    ("PR-04", "Data subject / patient access request process (30 days)", "164.524", "Art. 12, 15", "A.5.34", "-", "s.11"),
    ("PR-05", "Retention schedule by data class and jurisdiction", "164.316(b)(2)", "Art. 5(1)(e), 17", "A.5.33", "3.2.1, 10.5.1", "s.8(7)"),
    ("PR-06", "Global 72-hour breach clock", "164.404-410", "Art. 33, 34", "A.5.26", "12.10.1", "s.8(6)"),
]

ROADMAP = [  # phase, quarter window, milestone, owner, FTE, budget (USD)
    ("Year 1 - Foundation (2027)", "Q1 2027", "Global Compliance Committee + CCO charter; EU DPO appointed (GDPR Art. 37); unified control framework v1 (48 controls) approved", "CCO", 6, 420_000),
    ("Year 1 - Foundation (2027)", "Q2 2027", "CISO Assistant domains US/EU/India; compliance workflow + AI triage live for the US; RoPA and DPIAs for EU sites", "GRC Lead", 8, 380_000),
    ("Year 1 - Foundation (2027)", "Q3 2027", "Keycloak/Entra JML automation extended to EU + India; SCCs + transfer impact assessments signed; works-council agreement (Munich)", "IAM Lead + DPO", 10, 450_000),
    ("Year 1 - Foundation (2027)", "Q4 2027", "First multi-site audit (5 sites); PCI DSS v4.0.1 assessment; ISO 27001 gap assessment", "Internal Audit", 10, 520_000),
    ("Year 2 - Integration (2028)", "Q1-Q2 2028", "ISO 27001 stage 1 + stage 2 certification for the group ISMS; FIDO2 MFA for all ePHI roles (risk option)", "CISO", 9, 650_000),
    ("Year 2 - Integration (2028)", "Q3-Q4 2028", "Continuous control monitoring for 60% of controls; predictive KPIs in the board dashboard; Hyderabad 24x7 SOC on Wazuh", "GRC Lead + SOC Manager", 9, 600_000),
    ("Year 3 - Optimization (2029)", "Q1-Q2 2029", "80% of controls tested automatically; NIST CSF Tier 3 'Repeatable' across sites; surveillance audit", "CCO", 7, 480_000),
    ("Year 3 - Optimization (2029)", "Q3-Q4 2029", "Second PDCA cycle review; model re-validation; roadmap 2030-2032", "CCO + Board committee", 6, 400_000),
]

AUDIT_PLAN = [  # site, mode, weeks, focus, sample
    ("US - HRMC flagship (Albany)", "On-site", "Week 1-2", "IAM / JML, EHR access, PCI cardholder flows", "93 access events; 59 JML tickets"),
    ("US - community campuses", "Virtual", "Week 2", "Access reviews, workstation controls (photo evidence)", "59 accounts"),
    ("EU - Dublin + Cork", "Virtual + 1 day on-site", "Week 3", "GDPR RoPA, DPIAs, SCC transfers, DSAR log", "All transfers; 59 DSARs"),
    ("EU - Munich diagnostics", "On-site", "Week 4", "German retention (10 y), works-council monitoring scope", "59 records"),
    ("India - Hyderabad shared services", "Virtual (VDI walkthrough)", "Week 5", "PCI DSS for billing, DPDP staff data, pseudonymisation", "93 billing transactions"),
    ("Group - consolidated", "Virtual", "Week 6", "Report, findings to CISO Assistant, board summary", "-"),
]
AUDIT_TEAM = [
    ("Lead auditor (GRC)", "Akhila Chennamaneni", "Plan, sampling, analytics, report"),
    ("IT / IAM auditor", "Internal Audit", "Keycloak, Entra, Wazuh, change logs"),
    ("Operational compliance (clinical)", "Nursing quality lead", "Workflows, minimum-necessary use of records"),
    ("Financial compliance", "Revenue-cycle controller", "PCI DSS, billing reconciliations"),
    ("Privacy", "EU DPO + US Privacy Officer", "GDPR / HIPAA privacy, DSARs, transfers"),
    ("Regional SMEs", "Site IT leads (US, IE, DE, IN)", "Evidence access, interviews, walkthroughs"),
]
