# Tạo src/baseline.py với log_run

# Tạo file src/baseline.py chứa GROUP_CV, make_model và log_run(run_id, split, scores, ...,
# **params). log_run ghi một dòng gồm tên lần chạy, cách chia, trung bình và độ lệch macro-F1, phiên
# bản sklearn, MD5 của file dữ liệu và mọi tham số thêm vào cuối results.csv. Khung dưới đây là nội dung file.


"""Cấu hình A (baseline) của M3: mô hình, cách chia và ghi kết quả."""

import hashlib
from pathlib import Path

import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

from src.features import TOKEN

GROUP_CV = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)


def make_model(C=1.0):
    """TF-IDF + Logistic Regression; mọi bước học nằm trong Pipeline."""
    return Pipeline(
        [
            ("tfidf", TfidfVectorizer(token_pattern=TOKEN, min_df=2)),
            ("clf", LogisticRegression(C=C, class_weight="balanced", max_iter=3000)),
        ]
    )


def log_run(
    run_id,
    split,
    scores,
    data_path="../data/raw/evtx_data.csv",
    out_path="../results/results.csv",
    **params,
):
    """Ghi thêm một dòng kết quả (kèm phiên bản sklearn và MD5 dữ liệu)."""
    row = {
        "run_id": run_id,
        "split": split,
        "macro_f1_mean": round(float(scores.mean()), 3),
        "macro_f1_std": round(float(scores.std()), 3),
        "sklearn": sklearn.__version__,
        "data_md5": hashlib.md5(
            Path(data_path).read_bytes()
        ).hexdigest(),  # Dấu vân tay của file dữ liệu: dữ liệu đổi một byte là MD5 đổi.
        **params,
    }
    out = Path(out_path)
    out.parent.mkdir(
        parents=True, exist_ok=True
    )  # ạo thư mục nếu chưa có, không lỗi nếu đã có.
    table = pd.DataFrame([row])
    if out.exists():  # đã có kết quả cũ -> nối vào
        table = pd.concat(
            [pd.read_csv(out), table], ignore_index=True
        )  # Nối bảng, đánh lại chỉ số dòng; cột thiếu được điền trống.
    table.to_csv(out, index=False)  # cột mới (vd. note) tự được thêm
    return row
