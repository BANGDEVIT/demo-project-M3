"""
Tải dữ liệu thực hành cho Chặng 1 (đồ án M3) và tạo các file luyện tập.

Chạy từ thư mục gốc của dự án (m3-eda/):
    python prepare_data.py

Kết quả nằm trong data/raw/:
    evtx_data.csv                  dữ liệu chính (EVTX-ATTACK-SAMPLES, đã parse sẵn)
    empire_launcher_vbs.zip        một bộ OTRF Security-Datasets (JSON Lines, nén zip)
    events_nested.jsonl            luyện json_normalize: mỗi dòng 1 event, lồng nhiều tầng
    alerts_by_file.json            luyện record_path/meta: mỗi alert chứa danh sách events
"""
import hashlib
import json
import urllib.request
from pathlib import Path

import pandas as pd

RAW = Path("data") / "raw"

SOURCES = {
    "evtx_data.csv": (
        "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/"
        "master/evtx_data.csv"
    ),
    "empire_launcher_vbs.zip": (
        "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
        "datasets/atomic/windows/execution/host/empire_launcher_vbs.zip"
    ),
}

# Các trường thuộc phần "event_data" (nội dung riêng của từng loại event)
EVENT_DATA_FIELDS = [
    "Image", "ParentImage", "CommandLine", "ParentCommandLine",
    "NewProcessName", "ProcessName", "Application",
    "User", "SubjectUserName", "TargetUserName", "LogonType",
    "IpAddress", "DestinationIp", "DestinationPort", "TargetFilename",
]


def md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


def download(name: str, url: str) -> Path:
    dest = RAW / name
    if dest.exists():
        print(f"[bỏ qua] {name} đã có")
    else:
        print(f"[tải] {name} ...")
        urllib.request.urlretrieve(url, dest)
    print(f"        {dest.stat().st_size:,} bytes, md5 {md5(dest)}")
    return dest


def clean(value):
    """Chuyển NaN thành None và số thực nguyên thành int để JSON gọn hơn."""
    if pd.isna(value):
        return None
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def to_nested_event(row: pd.Series) -> dict:
    """Chuyển 1 dòng CSV phẳng thành 1 event lồng nhau (kiểu Winlogbeat/Elastic)."""
    event_data = {}
    for field in EVENT_DATA_FIELDS:
        if field in row.index:
            value = clean(row[field])
            if value is not None and value != "-":
                event_data[field] = value

    nested = {
        "@timestamp": row["SystemTime"],
        "event": {"code": int(row["EventID"])},
        "winlog": {
            "channel": row["Channel"],
            "computer_name": row["Computer"],
            "record_id": clean(row["EventRecordID"]),
            "event_data": event_data,
        },
        "labels": {
            "evtx_file": row["EVTX_FileName"],
            "tactic": row["EVTX_Tactic"],
        },
    }
    # Chỉ một số event có trường "tags" dạng list, giống log thật
    if row["Channel"] == "Microsoft-Windows-Sysmon/Operational":
        nested["tags"] = ["sysmon", f"eid_{int(row['EventID'])}"]
    return nested


def build_practice_files(csv_path: Path) -> None:
    df = pd.read_csv(csv_path, low_memory=False)

    # 1) events_nested.jsonl: mỗi dòng là một event JSON lồng nhau
    out1 = RAW / "events_nested.jsonl"
    with out1.open("w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            f.write(json.dumps(to_nested_event(row), ensure_ascii=False) + "\n")
    print(f"[tạo] {out1.name}: {len(df):,} dòng")

    # 2) alerts_by_file.json: mỗi file EVTX được coi là 1 "alert" chứa nhiều event
    alerts = []
    for file_name, group in df.groupby("EVTX_FileName", sort=True):
        events = []
        for _, row in group.iterrows():
            ev = {
                "EventID": int(row["EventID"]),
                "Channel": row["Channel"],
                "SystemTime": row["SystemTime"],
            }
            for field in ("Image", "CommandLine", "ParentImage"):
                value = clean(row[field])
                if value is not None and value != "-":
                    ev[field] = value
            events.append(ev)
        alerts.append({
            "alert_id": file_name,
            "tactic": group["EVTX_Tactic"].iloc[0],
            "host": {"name": group["Computer"].iloc[0]},
            "event_count": len(events),
            "events": events,
        })
    out2 = RAW / "alerts_by_file.json"
    out2.write_text(json.dumps(alerts, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[tạo] {out2.name}: {len(alerts)} alert")


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    paths = {name: download(name, url) for name, url in SOURCES.items()}
    build_practice_files(paths["evtx_data.csv"])
    print("Xong. Ghi các mã md5 ở trên vào README.md.")


if __name__ == "__main__":
    main()
