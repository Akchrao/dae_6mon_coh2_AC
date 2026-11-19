# Wazuh health check 2026-11-18T19:23:55+00:00: **WARNING**

| Area | Check | Value | Status | Threshold |
|---|---|---|---|---|
| Collection | Agent wazuh.manager (server) | Active/Local | OK | Active |
| Collection | Agent hrmc-linux-srv01 | Active | OK | Active |
| Collection | Service wazuh-analysisd | running | OK | running |
| Collection | Service wazuh-remoted | running | OK | running |
| Collection | Service wazuh-logcollector | running | OK | running |
| Collection | Service wazuh-syscheckd | running | OK | running |
| Collection | Service wazuh-maild | running | OK | running |
| Collection | Service wazuh-db | running | OK | running |
| Collection | Service wazuh-modulesd | running | OK | running |
| Collection | Log file ehr_access.json | 6 events since start | OK | file monitored |
| Collection | Log file windows_security.json | 39 events since start | OK | file monitored |
| Collection | Log file auth.log | 0 events since start | OK | file monitored |
| Collection | Log file keycloak_login.json | 1 events since start | OK | file monitored |
| Collection | Log file keycloak_admin.json | 0 events since start | OK | file monitored |
| Collection | Last alert from source windows_security | 2 min ago (715 alerts) | OK | <= 60 min (imported sources replay on demand) |
| Collection | Last alert from source keycloak_admin | 1318 min ago (231 alerts) | WARNING | <= 60 min (imported sources replay on demand) |
| Collection | Last alert from source keycloak_login | 2 min ago (201 alerts) | OK | <= 60 min (imported sources replay on demand) |
| Collection | Last alert from source ehr_access | 2 min ago (120 alerts) | OK | <= 60 min (imported sources replay on demand) |
| Collection | Last alert from agent wazuh.manager | 2 min ago (1713 alerts) | OK | <= 60 min (imported sources replay on demand) |
| Collection | Last alert from agent hrmc-linux-srv01 | 6 min ago (212 alerts) | OK | <= 60 min (imported sources replay on demand) |
| Processing | Events decoded (total since start) | 247 | OK | > 0 |
| Processing | Events per second (last interval) | 0.0 | OK | baseline in section 3.3 |
| Processing | Events dropped | 0 | OK | 0 |
| Processing | Highest analysisd queue usage | 0.0% | OK | < 70% |
| Processing | Alerts written | 48 | OK | > 0 |
| Processing | Agent messages discarded (remoted) | 0 | OK | 0 |
| Storage | Indexer cluster health | green | OK | green/yellow (single node) |
| Storage | Alert indices size | 3.6 MB, 1925 alerts in 2 daily indices | OK | trend tracked |
| Storage | Indexer data disk free | 82% (197.9 GB) | OK | > 15% |
| Storage | Host (Mac) disk free | 22.8 GB (9%) | WARNING | > 3 GB (vulnerability detector disabled after it filled the disk on 2026-11-18) |
| Storage | Manager queue folder | 13 MB | OK | < 1,000 MB |
