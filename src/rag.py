"""Chặng 3 · RAG: kho tri thức ATT&CK, embedding qua Ollama, lưu và tìm bằng Postgres + pgvector."""

import json
import os
import re
from pathlib import Path

import numpy as np
import pandas as pd
import psycopg
import requests
from pgvector.psycopg import register_vector

from .srs import ollama_url

ROOT = Path(__file__).resolve().parent.parent
STIX = ROOT / "data" / "attack" / "enterprise-attack-18.1.json"
EMBED_MODEL = "embeddinggemma"  # đổi cho khớp `ollama list`
DIM = 768
PG_DSN = os.environ.get("M3_PG_DSN", "postgresql://postgres:m3dev@localhost:5433/m3")


# ---------- kho tri thức từ ATT&CK STIX ----------
def clean(text):
    """Bỏ trích dẫn, link markdown, thẻ <code> và khoảng trắng thừa trong mô tả ATT&CK."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"</?code>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def build_kb(codes, stix_path=STIX):
    """Bảng kỹ thuật (ma, ten, chien_thuat, mo_ta) cho các mã trong codes, và phiên bản ATT&CK."""
    with open(stix_path, encoding="utf-8") as f:
        objects = json.load(f)["objects"]
    version = next(
        o["x_mitre_version"] for o in objects if o["type"] == "x-mitre-collection"
    )
    rows = []
    for o in objects:
        if (
            o["type"] != "attack-pattern"
            or o.get("revoked")
            or o.get("x_mitre_deprecated")
        ):
            continue
        ma = next(
            r["external_id"]
            for r in o["external_references"]
            if r["source_name"] == "mitre-attack"
        )
        if ma in codes:
            rows.append(
                {
                    "ma": ma,
                    "ten": o["name"],
                    "chien_thuat": ", ".join(
                        p["phase_name"] for p in o.get("kill_chain_phases", [])
                    ),
                    "mo_ta": clean(o.get("description", "")),
                }
            )
    kb = pd.DataFrame(rows).sort_values("ma").reset_index(drop=True)
    return kb, version


# ---------- embedding ----------


# truy vấn:  "task: search result | query: <gói bằng chứng>"
def as_query(text):
    """Định dạng câu truy vấn theo hướng dẫn của EmbeddingGemma."""
    return f"task: search result | query: {text}"


# tài liệu:  "title: LSASS Memory | text: Adversaries may attempt to access ..."
def as_doc(title, text):
    """Định dạng tài liệu theo hướng dẫn của EmbeddingGemma."""
    return f"title: {title} | text: {text}"


def embed(texts, batch=8):
    """Gọi /api/embed (qua FR-07), trả mảng numpy (số câu, DIM); vector đã chuẩn hóa độ dài 1."""
    out = []
    for i in range(0, len(texts), batch):
        r = requests.post(
            f"{ollama_url()}/api/embed",
            json={"model": EMBED_MODEL, "input": texts[i : i + batch]},
            timeout=600,
        )
        r.raise_for_status()
        out.extend(r.json()["embeddings"])
    return np.array(out, dtype=np.float32)


# ---------- Postgres + pgvector ----------
def connect(dsn=PG_DSN):
    """Mở kết nối, bật extension vector và đăng ký kiểu vector cho psycopg."""
    conn = psycopg.connect(dsn, autocommit=True)
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    register_vector(conn)
    return conn


def create_table(conn):
    """Tạo bảng attack_kb nếu chưa có."""
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS attack_kb (
            ma          text PRIMARY KEY,
            ten         text NOT NULL,
            chien_thuat text NOT NULL,
            mo_ta       text NOT NULL,
            attack_ver  text NOT NULL,
            embed_model text NOT NULL,
            embedding   vector({DIM}) NOT NULL
        )""")


# Hàm này ghi từng kỹ thuật ATT&CK kèm vector embedding của nó vào bảng attack_kb. Kỹ thuật nào chưa có thì thêm mới, kỹ thuật nào đã có thì cập nhật. Kiểu “thêm hoặc cập nhật” này gọi là upsert (update + insert
def upsert(conn, kb, vectors, version):
    """Ghi (hoặc ghi đè) từng kỹ thuật cùng vector của nó."""
    sql = """
        INSERT INTO attack_kb (ma, ten, chien_thuat, mo_ta, attack_ver, embed_model, embedding)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (ma) DO UPDATE SET
            ten = EXCLUDED.ten, chien_thuat = EXCLUDED.chien_thuat, mo_ta = EXCLUDED.mo_ta,
            attack_ver = EXCLUDED.attack_ver, embed_model = EXCLUDED.embed_model,
            embedding = EXCLUDED.embedding"""
    with conn.cursor() as cur:
        for row, vec in zip(kb.itertuples(index=False), vectors):
            cur.execute(
                sql,
                (
                    row.ma,
                    row.ten,
                    row.chien_thuat,
                    row.mo_ta,
                    version,
                    EMBED_MODEL,
                    vec,
                ),
            )


def search(conn, query_vec, k=5):
    """k kỹ thuật gần câu truy vấn nhất: (ma, ten, độ giống cosine)."""
    return conn.execute(
        """
        SELECT ma, ten, 1 - (embedding <=> %s) AS do_giong
        FROM attack_kb
        ORDER BY embedding <=> %s
        LIMIT %s""",
        (query_vec, query_vec, k),
    ).fetchall()


#  (query_vec, query_vec, k), -> $s
# #    └── 1 ──┘  └── 2 ──┘  └3┘

# LÀM 1 LẦN (dựng kho):
#   enterprise-attack-18.1.json ──build_kb──► bảng kb (ma, ten, chien_thuat, mo_ta)
#                                    │
#                          as_doc + embed
#                                    ▼
#                         vectors (số kỹ thuật × 768) ──upsert──► bảng attack_kb trong Postgres

# MỖI CẢNH BÁO (tìm ứng viên):
#   gói bằng chứng ──as_query + embed──► query_vec ──search──► top-k (ma, ten, do_giong)
