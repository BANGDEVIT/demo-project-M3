from pandas import json_normalize

raw = [
    {
        "@timestamp": "2020-09-21T17:30:12.000Z",
        "event": {"code": "1", "provider": "Microsoft-Windows-Sysmon"},
        "host": {"name": "WORKSTATION5"},
        "process": {
            "executable": r"C:\Windows\System32\cmd.exe",
            "parent": {"executable": r"C:\Windows\explorer.exe"},
        },
    },
    {
        "@timestamp": "2020-09-21T17:30:15.500Z",
        "event": {"code": "4624", "provider": "Microsoft-Windows-Security-Auditing"},
        "host": {"name": "DC01"},
    },
]

# transform = json_normalize(raw, sep="_").columns.tolist()

alerts = [
    {
        "alert_id": "A1",
        "host": "WS5",
        "events": [
            {"EventID": 1, "Image": "cmd.exe"},
            {"EventID": 3, "Image": "cmd.exe"},
        ],
    },
    {"alert_id": "A2", "host": "DC01", "events": [{"EventID": 4624}]},
]
transform = json_normalize(alerts, record_path="events", meta=["alert_id", "host"])
transform1 = json_normalize(alerts)
print(transform)
print(transform1)
