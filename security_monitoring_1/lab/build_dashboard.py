#!/usr/bin/env python3
"""Creates the 'HRMC Security Monitoring' dashboard in the Wazuh dashboard (OpenSearch Dashboards saved objects).
Writes wazuh_config/hrmc_security_dashboard.ndjson and imports it (overwrite) through the saved-objects API."""
import json, os, ssl, base64, pathlib, urllib.request, uuid

HERE = pathlib.Path(__file__).resolve().parent
NDJSON = HERE.parent / "wazuh_config/hrmc_security_dashboard.ndjson"
BASE = "https://localhost:5601"
AUTH = base64.b64encode(os.environ.get("WAZUH_DASHBOARD_AUTH", "admin:SecretPassword").encode()).decode()  # lab default
CTX = ssl._create_unverified_context()
SCOPE = "rule.groups:sm1 or rule.groups:soc1 or agent.name:hrmc-linux-srv01"
IDX = "wazuh-alerts-*"


def vis(vid, title, vtype, params, aggs, query=SCOPE):
    return {"id": vid, "type": "visualization", "attributes": {
        "title": title, "visState": json.dumps({"title": title, "type": vtype, "params": params, "aggs": aggs}),
        "uiStateJSON": "{}", "description": "", "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                                                                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": IDX}]}


count = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}
terms = lambda i, f, size, schema="segment", label=None: {"id": i, "enabled": True, "type": "terms", "schema": schema,
                                                         "params": {"field": f, "size": size, "order": "desc", "orderBy": "1", "otherBucket": False,
                                                                    "missingBucket": True, "missingBucketLabel": "(agent / built-in)", **({"customLabel": label} if label else {})}}
metric_params = {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                 "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}], "labels": {"show": True}, "invertColors": False,
                 "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48}}}
pie = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}
bar = lambda: {"type": "histogram", "grid": {"categoryLines": False}, "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "labels": {"show": True, "truncate": 60}, "title": {}}],
               "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "labels": {"show": True}, "title": {"text": "Alerts"}}],
               "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Alerts", "id": "1"}, "valueAxis": "ValueAxis-1"}],
               "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False}
V = [
    vis("hrmc-v-total", "HRMC: monitored alerts", "metric", metric_params, [count]),
    vis("hrmc-v-high", "HRMC: high and critical alerts (level 10+)", "metric", metric_params, [count], f"({SCOPE}) and rule.level >= 10"),
    vis("hrmc-v-time", "HRMC: alerts over time by level", "histogram", bar(), [count,
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "range", "schema": "group", "params": {"field": "rule.level", "ranges": [{"from": 0, "to": 7}, {"from": 7, "to": 10}, {"from": 10, "to": 12}, {"from": 12, "to": 16}]}}]),
    vis("hrmc-v-source", "HRMC: alerts by log source", "pie", pie, [count, terms("2", "data.src", 10)]),
    vis("hrmc-v-agent", "HRMC: alerts by agent", "pie", pie, [count, terms("2", "agent.name", 10)]),
    vis("hrmc-v-rules", "HRMC: top rules", "table", {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
        [count, terms("2", "rule.id", 15, "bucket", "Rule"), terms("3", "rule.description", 1, "bucket", "Description"),
         {"id": "4", "enabled": True, "type": "max", "schema": "metric", "params": {"field": "rule.level", "customLabel": "Level"}}]),
    vis("hrmc-v-users", "HRMC: users with high alerts", "histogram", bar(), [count, terms("2", "data.username", 8)], f"({SCOPE}) and rule.level >= 10"),
    vis("hrmc-v-mitre", "HRMC: MITRE ATT&CK techniques", "pie", pie, [count, terms("2", "rule.mitre.technique", 10)]),
]
layout = [("hrmc-v-total", 0, 0, 12, 8), ("hrmc-v-high", 12, 0, 12, 8), ("hrmc-v-source", 24, 0, 12, 8), ("hrmc-v-agent", 36, 0, 12, 8),
          ("hrmc-v-time", 0, 8, 48, 13), ("hrmc-v-rules", 0, 21, 28, 16), ("hrmc-v-users", 28, 21, 20, 8), ("hrmc-v-mitre", 28, 29, 20, 8)]
panels, refs = [], []
for i, (vid, x, y, w, h) in enumerate(layout):
    panels.append({"version": "2.13.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)}, "panelIndex": str(i + 1),
                   "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
    refs.append({"name": f"panel_{i}", "type": "visualization", "id": vid})
dash = {"id": "hrmc-security-monitoring", "type": "dashboard", "attributes": {
    "title": "HRMC Security Monitoring", "description": "Security Monitoring 1: Windows (imported samples), Linux agent, Keycloak and EHR alerts",
    "panelsJSON": json.dumps(panels), "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}), "version": 1,
    "timeRestore": True, "timeFrom": "now-7d", "timeTo": "now", "refreshInterval": {"pause": False, "value": 30000},
    "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}}, "references": refs}
NDJSON.write_text("".join(json.dumps(o) + "\n" for o in V + [dash]))

boundary = uuid.uuid4().hex
body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hrmc.ndjson\"\r\nContent-Type: application/ndjson\r\n\r\n"
        + NDJSON.read_text() + f"\r\n--{boundary}--\r\n").encode()
req = urllib.request.Request(BASE + "/api/saved_objects/_import?overwrite=true", data=body, method="POST",
                             headers={"Authorization": "Basic " + AUTH, "osd-xsrf": "true", "Content-Type": f"multipart/form-data; boundary={boundary}"})
print(json.load(urllib.request.urlopen(req, context=CTX)))
print("open: https://localhost:5601/app/dashboards#/view/hrmc-security-monitoring")
