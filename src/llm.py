"""Hàm dùng chung cho Chặng 3: gọi Ollama, khuôn đầu ra Triage, kiểm hai tầng."""

import json
from typing import Literal

import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

OLLAMA = "http://localhost:11434"
MODEL = "qwen3.5:4b"  # đổi cho khớp `ollama list`

TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Unknown",
]


class Triage(BaseModel):
    """Khuôn đầu ra của một lần phân loại cảnh báo."""

    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=20, max_length=600)
    tactic: Literal[tuple(TACTICS)]
    technique_id: str | None = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1, max_length=10)
    severity: Literal["low", "medium", "high"]

    @model_validator(mode="after")
    def unknown_has_no_technique(self):
        if self.tactic == "Unknown" and self.technique_id is not None:
            raise ValueError("tactic là Unknown thì technique_id phải là null")
        return self


SCHEMA = (
    Triage.model_json_schema()
)  # Dòng này sinh ra bản mô tả cấu trúc của Triage dưới dạng JSON Schema (một dict)
SCHEMA_TEXT = json.dumps(
    SCHEMA, ensure_ascii=False
)  # Dòng này biến dict SCHEMA thành một chuỗi văn bản JSON, để ghép được vào prompt gửi cho LLM.


def call(messages, fmt=None, num_predict=400, num_ctx=4096):
    """Gọi /api/chat một lần (temperature 0, seed 42, tắt thinking), trả dict của Ollama."""
    body = {
        "model": MODEL,
        "messages": messages,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0,
            "seed": 42,
            "num_ctx": num_ctx,
            "num_predict": num_predict,
        },
    }
    if fmt is not None:
        body["format"] = fmt
    r = requests.post(f"{OLLAMA}/api/chat", json=body, timeout=900)
    r.raise_for_status()
    return r.json()


def check(raw, n_evidence):
    """Kiểm hai tầng: đúng khuôn (Pydantic) và mã bằng chứng có thật. Trả (obj | None, lỗi)."""
    try:
        t = Triage.model_validate_json(raw)
    except ValidationError as e:
        return None, [
            f"{'.'.join(map(str, err['loc'])) or '(toàn bộ)'}: {err['msg']}"
            for err in e.errors()
        ]
    allowed = {f"E{i}" for i in range(1, n_evidence + 1)}
    errs = [
        f"evidence_ids: {x} không có trong gói (chỉ có E1..E{n_evidence})"
        for x in t.evidence_ids
        if x not in allowed
    ]
    if len(set(t.evidence_ids)) < len(t.evidence_ids):
        errs.append("evidence_ids: có mã bị lặp")
    return (None if errs else t), errs


def evidence_lines(docs, groups, file, k=15):
    """Các dòng event khác nhau của một file, mỗi dòng tối đa 300 ký tự."""
    return docs[groups == file].drop_duplicates().str.slice(0, 300).head(k).tolist()
