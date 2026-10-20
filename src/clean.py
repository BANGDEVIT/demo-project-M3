"""
Hàm làm sạch dùng chung cho các notebook EDA của đồ án M3.

Cách dùng trong notebook (đặt notebook trong thư mục notebooks/):

    import sys
    from pathlib import Path
    sys.path.append(str(Path("..").resolve()))

    from src.clean import load_events, clean_events
    ev = clean_events(load_events(Path("..") / "data" / "raw" / "evtx_data.csv"))
"""

from pathlib import Path

import pandas as pd

# Các cột cần cho Chặng 1; bỏ bớt hơn 300 cột gần như trống của evtx_data.csv
KEEP_COLS = [
    "EVTX_FileName",
    "EVTX_Tactic",
    "Channel",
    "EventID",
    "EventRecordID",
    "SystemTime",
    "Computer",
    "Image",
    "ParentImage",
    "CommandLine",
    "NewProcessName",
    "ProcessName",
    "Application",
]

# Thứ tự ưu tiên khi gộp thông tin tiến trình (xem mục 6.3 của tài liệu)
PROCESS_COLS = ["Image", "NewProcessName", "ProcessName", "Application"]


def load_events(path: str | Path) -> pd.DataFrame:
    """Đọc evtx_data.csv và chỉ giữ các cột trong KEEP_COLS."""
    df = pd.read_csv(path, low_memory=False)
    missing = [c for c in KEEP_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Thiếu cột trong file dữ liệu: {missing}")
    return df[KEEP_COLS].copy()


def add_process_name(ev: pd.DataFrame) -> pd.DataFrame:
    """
    Gộp các cột tiến trình thành process_path, rồi tách tên file viết thường
    thành process_name. Giá trị giữ chỗ "-" hoặc chuỗi rỗng được coi là thiếu.
    """
    proc = ev[PROCESS_COLS[0]]
    for col in PROCESS_COLS[1:]:
        proc = proc.fillna(ev[col])

    ev["process_path"] = proc.replace({"-": pd.NA, "": pd.NA})
    ev["process_name"] = (
        ev["process_path"]
        .str.extract(r"([^\\/]+)$", expand=False)  # phần sau dấu \ hoặc / cuối cùng
        .str.lower()
    )
    return ev


def clean_events(ev: pd.DataFrame) -> pd.DataFrame:
    """
    Làm sạch bảng event:
      - ts: thời gian kiểu datetime (UTC), chấp nhận cả dạng có và không có phần giây lẻ
      - process_path, process_name: thông tin tiến trình đã chuẩn hóa
      - EVTX_Tactic, Channel: chuyển sang kiểu category cho gọn bộ nhớ
    Không xóa dòng nào; bước lọc để dành cho từng phân tích cụ thể.
    """
    ev = ev.copy()
    ev["ts"] = pd.to_datetime(
        ev["SystemTime"], format="mixed", errors="coerce", utc=True
    )
    ev = add_process_name(ev)
    ev["EVTX_Tactic"] = ev["EVTX_Tactic"].astype("category")
    ev["Channel"] = ev["Channel"].astype("category")
    return ev
