# Đóng gói thành src/features.py
"""Dựng "tài liệu" văn bản từ event EVTX cho TF-IDF (dùng chung cho cấu hình A, B, C)."""

import re
from pathlib import Path

import pandas as pd

BEHAVIOR = [
    "Image",
    "ParentImage",
    "CommandLine",
    "NewProcessName",
    "ProcessName",
    "Application",
    "ShareName",
    "RelativeTargetName",
    "TargetFilename",
    "ImageLoaded",
    "TargetImage",
    "GrantedAccess",
    "PipeName",
    "TargetObject",
    "LogonType",
    "EventType",
    "TaskName",
    "AccessMask",
]
TOKEN = r"(?u)[\w\.\-<>]+"  # giữ dấu chấm, gạch ngang và nhãn <user>, <guid>, <ip>


def normalize(text):
    """Viết thường và thay định danh (người dùng, GUID, IP) bằng nhãn chung."""
    t = str(text).lower()
    t = re.sub(r"\busers([\\/])[^\\/\s\"']+", r"users\1<user>", t)
    t = re.sub(
        r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?",
        " <guid> ",
        t,
    )
    t = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", " <ip> ", t)
    return t


def build_doc(row):
    """Một event -> một chuỗi: kênh, EventID và các trường hành vi đã chuẩn hóa."""
    channel = str(row["Channel"]).split("/")[0].split("-")[-1].lower()
    parts = [f"ch_{channel}", f"eid_{row['EventID']}"]
    for col in BEHAVIOR:
        val = row[col]
        if pd.notna(val) and str(val) not in ("-", ""):
            parts.append(normalize(val))
    return " ".join(parts)


def load_m3(path):
    """Đọc evtx_data.csv, trả về (df, docs, y, groups)."""
    df = pd.read_csv(Path(path), low_memory=False)
    docs = df.apply(build_doc, axis=1)
    assert not docs.str.contains("ieuser|user01").any(), "còn sót tên người dùng"
    return df, docs, df["EVTX_Tactic"], df["EVTX_FileName"]
