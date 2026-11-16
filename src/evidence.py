"""Chặng 3 · Buổi 7: nạp log OTRF vào bảng events chia theo ngày và dựng gói bằng chứng [E1]...[En]."""

import hashlib
import io
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
import psycopg
import requests
from psycopg.types.json import Jsonb

from .rag import PG_DSN

# Bức tranh tổng thể
# OTRF (bộ log tấn công mẫu trên GitHub, dạng .zip)
#    │ fetch()        tải về, kiểm MD5, đọc từng dòng JSON
#    │ normalize()    đưa về một bảng chung (kênh, máy, thời gian, tiến trình, đăng nhập, script)
#    │ attach_pid()   bù PID còn thiếu cho Sysmon EID 1
#    ▼
# Postgres: bảng events, chia theo ngày (events_20200810, …)
#    │
#    │ build_pack(alert_id)  từ MỘT event cảnh báo, đi tìm:
#    │    ① cây tiến trình: tổ tiên (cha, ông…) và con cháu      ← TREE_SQL (truy vấn đệ quy)
#    │    ② phiên đăng nhập sinh ra tiến trình đó (4624)        ← LOGON_SQL
#    │    ③ script PowerShell do các tiến trình đó chạy (4104)  ← PS_SQL
#    │    xếp ưu tiên, giữ tối đa 12 dòng, sắp lại theo thời gian
#    ▼
# render()  →  [E1] ...  [E2] ...  (gói bằng chứng dạng câu tiếng Việt)

ROOT = Path(__file__).resolve().parent.parent
OTRF_DIR = ROOT / "data" / "otrf"
OTRF_URL = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
DATASETS = {  # tên: (đường dẫn trong kho OTRF, MD5 của file zip)
    "empire_psremoting_stager": (
        "lateral_movement/host/empire_psremoting_stager.zip",
        "d5407ec1794ff2ce7dbb1488e6aadba3",
    ),
    "empire_shell_net_localgroup_administrators": (
        "discovery/host/empire_shell_net_localgroup_administrators.zip",
        "7cebc824e9c7cefe203d9822c02cce4c",
    ),
}
CHANNELS = {
    "microsoft-windows-sysmon/operational": "sysmon",
    "security": "security",
    "microsoft-windows-powershell/operational": "powershell",
}
LOGON_TYPES = {
    2: "tương tác tại máy",
    3: "qua mạng",
    4: "batch",
    5: "dịch vụ",
    7: "mở khóa",
    10: "từ xa (RDP)",
    11: "tương tác, dùng thông tin lưu sẵn",
}


# ---------- tải và chuẩn hóa ----------
def fetch(name):
    """Tải file zip của một bộ OTRF (nếu chưa có), kiểm MD5, trả danh sách sự kiện (dict)."""
    path, md5 = DATASETS[name]
    zpath = OTRF_DIR / f"{name}.zip"
    if not zpath.exists():
        OTRF_DIR.mkdir(parents=True, exist_ok=True)
        r = requests.get(OTRF_URL + path, timeout=120)
        r.raise_for_status()
        zpath.write_bytes(r.content)
    if hashlib.md5(zpath.read_bytes()).hexdigest() != md5:
        raise ValueError(f"MD5 của {zpath.name} không khớp")
    with zipfile.ZipFile(zpath) as z:
        text = z.read(z.namelist()[0]).decode("utf-8")
    return [json.loads(line) for line in io.StringIO(text) if line.strip()]


def _int(v, base=10):
    """Đổi chuỗi thành số nguyên; rỗng, '-' hoặc lỗi thì trả None."""
    try:
        return int(str(v), base)
    except (TypeError, ValueError):
        return None


def normalize(events, dataset):
    """Đưa sự kiện thô về một bảng thống nhất: kênh, máy, thời gian, tiến trình, đăng nhập, script."""
    rows = []
    for e in events:
        channel = CHANNELS.get(str(e.get("Channel", "")).lower())
        if channel is None:
            continue
        rows.append(
            {
                "dataset": dataset,
                "ts": pd.Timestamp(e["@timestamp"]),
                "host": str(e.get("Hostname", "")).split(".")[0].lower(),
                "channel": channel,
                "event_id": _int(e.get("EventID")),
                "proc_guid": (e.get("ProcessGuid") or "").lower() or None,
                "parent_guid": (e.get("ParentProcessGuid") or "").lower() or None,
                "pid": _int(e.get("ProcessId")) if channel == "sysmon" else None,
                "ppid": _int(e.get("ParentProcessId")),
                "image": e.get("Image") or e.get("NewProcessName"),
                "parent_image": e.get("ParentImage") or e.get("ParentProcessName"),
                "cmdline": e.get("CommandLine"),
                "user_name": e.get("User"),
                "logon_id": (e.get("LogonId") or e.get("SubjectLogonId") or "").lower()
                or None,
                "target_logon_id": (e.get("TargetLogonId") or "").lower() or None,
                "logon_type": _int(e.get("LogonType")),
                "target_user": (
                    f"{e.get('TargetDomainName')}\\{e['TargetUserName']}"
                    if e.get("TargetUserName")
                    else None
                ),
                "src_ip": e.get("IpAddress"),
                "new_pid": _int(e.get("NewProcessId"), 16)
                if e.get("NewProcessId")
                else None,
                "exec_pid": _int(e.get("ExecutionProcessID")),
                "script": e.get("ScriptBlockText"),
                "raw": e,
            }
        )
    return pd.DataFrame(rows)


def attach_pid(df, tolerance="5s"):
    """Sysmon EID 1 trong bộ OTRF thiếu ProcessId: lấy PID từ Security 4688 cùng máy, cùng lệnh."""
    proc = df[(df["channel"] == "sysmon") & (df["event_id"] == 1)]
    sec = df[(df["channel"] == "security") & (df["event_id"] == 4688)]
    for i, p in proc.iterrows():
        m = sec[
            (sec["host"] == p["host"])
            & (sec["cmdline"] == p["cmdline"])
            & ((sec["ts"] - p["ts"]).abs() <= pd.Timedelta(tolerance))
        ]
        if len(m):
            df.at[i, "pid"] = m["new_pid"].iloc[0]
    for col in ["event_id", "pid", "ppid", "logon_type", "exec_pid"]:
        df[col] = df[col].astype("Int64")
    return df


# ---------- bảng events chia theo ngày ----------
COLUMNS = [
    "dataset",
    "ts",
    "host",
    "channel",
    "event_id",
    "proc_guid",
    "parent_guid",
    "pid",
    "ppid",
    "image",
    "parent_image",
    "cmdline",
    "user_name",
    "logon_id",
    "target_logon_id",
    "logon_type",
    "target_user",
    "src_ip",
    "exec_pid",
    "script",
    "raw",
]


def connect(dsn=PG_DSN):
    """Kết nối Postgres (cùng database m3 của Buổi 5), làm việc theo giờ UTC."""
    conn = psycopg.connect(dsn, autocommit=True)
    conn.execute("SET TIME ZONE 'UTC'")
    return conn


def create_events_table(conn):
    """Bảng cha events, chia (partition) theo khoảng thời gian ts; chỉ mục cho các phép nối."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id              bigint GENERATED ALWAYS AS IDENTITY,
            dataset         text,
            ts              timestamptz NOT NULL,
            host            text NOT NULL,
            channel         text NOT NULL,
            event_id        int  NOT NULL,
            proc_guid       text, parent_guid text, pid int, ppid int,
            image           text, parent_image text, cmdline text, user_name text,
            logon_id        text, target_logon_id text, logon_type int, target_user text,
            src_ip          text, exec_pid int, script text,
            raw             jsonb,
            PRIMARY KEY (id, ts)
        ) PARTITION BY RANGE (ts)""")
    for cols in [
        "host, proc_guid",
        "host, parent_guid",
        "host, target_logon_id",
        "host, exec_pid",
        "host, channel, event_id, ts",
    ]:
        name = "events_" + cols.replace(", ", "_") + "_idx"
        conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON events ({cols})")


def ensure_partition(conn, day):
    """Tạo bảng con events_YYYYMMDD chứa đúng một ngày (UTC), nếu chưa có."""
    day = pd.Timestamp(day).normalize()
    nxt = day + pd.Timedelta(days=1)
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS events_{day:%Y%m%d} PARTITION OF events
        FOR VALUES FROM ('{day:%Y-%m-%d} 00:00:00+00') TO ('{nxt:%Y-%m-%d} 00:00:00+00')""")


def _py(col, v):
    """Đổi giá trị pandas sang kiểu Python mà psycopg hiểu (NaN -> None, 10116.0 -> 10116)."""
    if col == "raw":
        return Jsonb(v)
    if v is None or v is pd.NA or (isinstance(v, float) and v != v):
        return None
    if isinstance(v, np.generic):
        v = v.item()
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, pd.Timestamp):
        return v.to_pydatetime()
    return v


def insert_events(conn, df):
    """Tạo bảng con cho mọi ngày có trong df rồi ghi toàn bộ sự kiện."""
    for day in df["ts"].dt.tz_convert("UTC").dt.normalize().unique():
        ensure_partition(conn, day.tz_localize(None))
    sql = f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({', '.join(['%s'] * len(COLUMNS))})"
    rows = [
        tuple(_py(c, v) for c, v in zip(COLUMNS, row))
        for row in df[COLUMNS].astype(object).itertuples(index=False)
    ]
    with conn.cursor() as cur:
        cur.executemany(sql, rows)


# ---------- truy vấn dựng gói ----------
TREE_SQL = """
WITH RECURSIVE
alert AS (SELECT * FROM events WHERE id = %(alert_id)s),
up AS (
    SELECT e.id, e.proc_guid, e.parent_guid, 0 AS depth FROM alert e
    UNION ALL
    SELECT e.id, e.proc_guid, e.parent_guid, up.depth - 1
    FROM events e JOIN up ON e.proc_guid = up.parent_guid
    WHERE e.channel = 'sysmon' AND e.event_id = 1
      AND e.host = (SELECT host FROM alert)
      AND e.ts >= (SELECT ts FROM alert) - %(before_min)s * interval '1 minute'
      AND up.depth > -%(max_up)s
),
down AS (
    SELECT e.id, e.proc_guid, 0 AS depth FROM alert e
    UNION ALL
    SELECT e.id, e.proc_guid, down.depth + 1
    FROM events e JOIN down ON e.parent_guid = down.proc_guid
    WHERE e.channel = 'sysmon' AND e.event_id = 1
      AND e.host = (SELECT host FROM alert)
      AND e.ts <= (SELECT ts FROM alert) + %(after_min)s * interval '1 minute'
      AND down.depth < %(max_down)s
)
SELECT t.depth, e.id, e.ts, e.host, e.pid, e.image, e.parent_image, e.cmdline,
       e.user_name, e.logon_id
FROM (SELECT id, depth FROM up UNION SELECT id, depth FROM down) t
JOIN events e ON e.id = t.id
ORDER BY e.ts
"""

LOGON_SQL = """
SELECT e.id, e.ts, e.host, e.logon_type, e.target_user, e.target_logon_id, e.src_ip
FROM events e
WHERE e.channel = 'security' AND e.event_id = 4624
  AND e.host = %(host)s AND e.target_logon_id = %(logon_id)s
  AND e.ts <= %(ts)s
ORDER BY e.ts DESC
LIMIT 1
"""

PS_SQL = """
SELECT e.id, e.ts, e.host, e.exec_pid, e.script
FROM events e
WHERE e.channel = 'powershell' AND e.event_id = 4104
  AND e.host = %(host)s AND e.exec_pid = ANY(%(pids)s)
  AND e.ts BETWEEN %(ts)s - %(before_min)s * interval '1 minute'
               AND %(ts)s + %(after_min)s * interval '1 minute'
ORDER BY e.ts
LIMIT %(max_ps)s
"""


def _name(path):
    """Chỉ lấy tên file từ đường dẫn Windows."""
    return str(path or "?").split("\\")[-1]


def _cut(text, n):
    """Cắt chuỗi về n ký tự, đánh dấu nếu bị cắt."""
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[:n] + f"… [rút gọn, {len(text)} ký tự]"


def sentence(kind, r, cmd_chars=160):
    """Viết một dòng sự kiện thành câu ngắn, giữ nguyên các giá trị gốc."""
    t = f"{r['ts']:%H:%M:%S} {r['host']}"
    if kind == "proc":
        pid = f" (PID {int(r['pid'])})" if pd.notna(r["pid"]) else ""
        return (
            f"{t}: {_name(r['parent_image'])} tạo tiến trình {_name(r['image'])}{pid}, "
            f"tài khoản {r['user_name']}, LogonId {r['logon_id']}; lệnh: "
            f"{_cut(r['cmdline'], cmd_chars)}"
        )
    if kind == "logon":
        kieu = LOGON_TYPES.get(r["logon_type"], "khác")
        return (
            f"{t}: đăng nhập thành công kiểu {r['logon_type']} ({kieu}) của {r['target_user']}, "
            f"LogonId {r['target_logon_id']}, IP nguồn {r['src_ip']}"
        )
    return (
        f"{t}: PowerShell PID {r['exec_pid']} chạy script block; mở đầu: "
        f"{_cut(r['script'], cmd_chars)}"
    )


def build_pack(
    conn,
    alert_id,
    level=1,
    max_up=3,
    max_down=2,
    before_min=10,
    after_min=5,
    max_ps=2,
    max_lines=12,
):
    """Gói bằng chứng cho một cảnh báo. level=0: chỉ sự kiện cảnh báo; level=1: thêm liên kết."""
    p = dict(
        alert_id=alert_id,
        max_up=max_up,
        max_down=max_down,
        before_min=before_min,
        after_min=after_min,
    )
    tree = pd.DataFrame(
        conn.execute(TREE_SQL, p).fetchall(),
        columns=[
            "depth",
            "id",
            "ts",
            "host",
            "pid",
            "image",
            "parent_image",
            "cmdline",
            "user_name",
            "logon_id",
        ],
    )
    alert = tree[tree["id"] == alert_id].iloc[0]
    items = [(0, alert["ts"], "proc", alert, "cảnh báo")]
    if level >= 1:
        for _, r in tree[tree["id"] != alert_id].iterrows():
            items.append(
                (
                    2 if r["depth"] < 0 else 3,
                    r["ts"],
                    "proc",
                    r,
                    "tổ tiên" if r["depth"] < 0 else "con cháu",
                )
            )
        q = dict(host=alert["host"], logon_id=alert["logon_id"], ts=alert["ts"])
        for row in conn.execute(LOGON_SQL, q).fetchall():
            r = dict(
                zip(
                    [
                        "id",
                        "ts",
                        "host",
                        "logon_type",
                        "target_user",
                        "target_logon_id",
                        "src_ip",
                    ],
                    row,
                )
            )
            items.append((1, r["ts"], "logon", r, "đăng nhập"))
        pids = [int(x) for x in tree["pid"].dropna()]
        q = dict(
            host=alert["host"],
            pids=pids,
            ts=alert["ts"],
            before_min=before_min,
            after_min=after_min,
            max_ps=max_ps,
        )
        for row in conn.execute(PS_SQL, q).fetchall():
            r = dict(zip(["id", "ts", "host", "exec_pid", "script"], row))
            items.append((4, r["ts"], "ps", r, "PowerShell 4104"))
    items = sorted(
        items, key=lambda x: (x[0], abs((x[1] - alert["ts"]).total_seconds()))
    )
    items = sorted(items[:max_lines], key=lambda x: x[1])
    pack = pd.DataFrame(
        [
            {"nguon": src, "event_row": int(r["id"]), "cau": sentence(kind, r)}
            for _, _, kind, r, src in items
        ]
    )
    pack.insert(0, "ma", [f"E{i + 1}" for i in range(len(pack))])
    return pack


def render(pack):
    """Gói bằng chứng dạng chữ: mỗi dòng '[Ek] câu'."""
    return "\n".join(f"[{m}] {c}" for m, c in zip(pack["ma"], pack["cau"]))
