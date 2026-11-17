"""Chặng 3 · Buổi 8: kiểm tra chặt đầu ra của LLM (10 luật xác định, mỗi luật một hàm)."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .rag import STIX
from .srs import suspicious

CONF_CAP = 0.5  # vi phạm luật 2–5 hoặc 10: độ tin cậy không được vượt mức này
MAX_SENTENCES = 10  # FR-02 / NFR-04
MAX_TECHNIQUES = 3


# ---------- khuôn đầu ra theo lộ trình ----------
class Technique(BaseModel):
    """Một kỹ thuật LLM đề xuất: mã, thứ hạng, mã bằng chứng, lý do."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1)
    rank: int = Field(ge=1)
    evidence: list[str]
    reason: str


class Analysis(BaseModel):
    """Kết quả phân tích một cảnh báo."""

    model_config = ConfigDict(extra="forbid")
    verdict: Literal["suspicious", "not_suspicious"]
    summary: str = Field(min_length=1)
    techniques: list[Technique]
    confidence: float = Field(ge=0, le=1)
    insufficient_evidence: bool


def output_schema(candidates):
    """JSON schema gửi cho Ollama: id chỉ được là một trong k ứng viên, tối đa 3 kỹ thuật."""
    schema = Analysis.model_json_schema()
    schema["$defs"]["Technique"]["properties"]["id"] = {
        "type": "string",
        "enum": list(candidates),
    }
    schema["properties"]["techniques"]["maxItems"] = MAX_TECHNIQUES
    return schema


# ---------- bảng ATT&CK đúng phiên bản đã nạp ----------
def load_attack(stix_path=STIX):
    """{mã: {"name", "tactics"}} của mọi kỹ thuật còn hiệu lực, và số phiên bản ATT&CK."""
    with open(stix_path, encoding="utf-8") as f:
        objects = json.load(f)["objects"]
    version = next(
        o["x_mitre_version"] for o in objects if o["type"] == "x-mitre-collection"
    )
    table = {}
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
        table[ma] = {
            "name": o["name"],
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
        }
    return table, version


# ---------- ngữ cảnh của một lần kiểm ----------
CODE_LIKE = re.compile(r"\b[A-Z]\d{4}(?:\.\d{3})?\b", re.I)
SAFE_REQUEST = re.compile(r"an toàn|không có kỹ thuật|safe|benign|not suspicious", re.I)


@dataclass
class Context:
    """Những gì validator cần biết ngoài đầu ra của LLM."""

    pack: dict  # {"E1": "câu 1", ...}
    candidates: list  # k mã ứng viên đã đưa vào enum
    attack: dict  # bảng ATT&CK từ load_attack()
    baseline_tactic: str | None = None
    injected_codes: set = field(default_factory=set)
    injected_safe: bool = False


def pack_from_lines(lines):
    """Danh sách dòng (chưa đánh số, như srs.evidence) -> {"E1": dòng 1, ...}."""
    return {f"E{i + 1}": line for i, line in enumerate(lines)}


def pack_from_df(pack):
    """DataFrame của evidence.build_pack -> {"E1": câu, ...}."""
    return dict(zip(pack["ma"], pack["cau"]))


def make_context(pack, candidates, attack, baseline_tactic=None):
    """Dựng Context; tự tìm mã và yêu cầu 'an toàn' nằm trong các dòng nghi chèn lệnh."""
    lines = list(pack.values())
    flagged = [pack[e] for e in suspicious(lines)]
    codes = {
        c.upper()
        for line in flagged
        for c in CODE_LIKE.findall(re.sub(r"[_\-]+", " ", line))
    }
    safe = any(SAFE_REQUEST.search(line) for line in flagged)
    return Context(pack, list(candidates), attack, baseline_tactic, codes, safe)


def _v(rule, detail, action):
    """Một vi phạm: luật nào, chi tiết, đã xử lý thế nào."""
    return {"rule": rule, "detail": detail, "action": action}


def _lower_confidence(res):
    res["confidence"] = min(res["confidence"], CONF_CAP)


# ---------- luật 1: đúng schema ----------
def r1_schema(raw):
    """JSON hợp lệ, đủ trường, đúng kiểu. Trả (dict | None, danh sách vi phạm)."""
    try:
        return Analysis.model_validate_json(raw).model_dump(), []
    except ValidationError as e:
        err = e.errors()[0]
        where = ".".join(map(str, err["loc"])) or "(toàn bộ)"
        return None, [_v("R1", f"{where}: {err['msg']}", "khong_hop_le")]


# ---------- luật 2: mã hợp lệ ----------
def r2_valid_codes(res, ctx):
    """Mỗi id phải thuộc k ứng viên VÀ có trong bảng ATT&CK đã nạp; sai thì loại kỹ thuật."""
    out, kept = [], []
    for t in res["techniques"]:
        t["id"] = t["id"].strip().upper()
        if t["id"] not in ctx.attack:
            out.append(
                _v(
                    "R2",
                    f"{t['id']} không có trong bảng ATT&CK đã nạp",
                    "loai_ky_thuat",
                )
            )
        elif t["id"] not in ctx.candidates:
            out.append(
                _v(
                    "R2",
                    f"{t['id']} không nằm trong {len(ctx.candidates)} ứng viên",
                    "loai_ky_thuat",
                )
            )
        else:
            kept.append(t)
    res["techniques"] = kept
    if out:
        _lower_confidence(res)
    return out


# ---------- luật 3: bằng chứng có thật ----------
CITE = re.compile(r"\[(E\d+)\]")


def r3_real_evidence(res, ctx):
    """Mọi id trong evidence và mọi [E…] trong summary phải có trong gói."""
    out = []
    for t in res["techniques"]:
        fake = [e for e in t["evidence"] if e not in ctx.pack]
        if fake:
            t["evidence"] = [e for e in t["evidence"] if e in ctx.pack]
            out.append(
                _v(
                    "R3",
                    f"{t['id']}: bằng chứng không có trong gói {fake}",
                    "bo_bang_chung",
                )
            )
    fake_cites = sorted({c for c in CITE.findall(res["summary"]) if c not in ctx.pack})
    if fake_cites:
        out.append(
            _v("R3", f"summary trích dẫn không có trong gói {fake_cites}", "ha_tin_cay")
        )
    if out:
        _lower_confidence(res)
    return out


# ---------- luật 4: mỗi kỹ thuật có ít nhất một bằng chứng ----------
def r4_has_evidence(res, ctx):
    """Kỹ thuật không còn bằng chứng nào (sau luật 3) thì bị loại."""
    out = [
        _v("R4", f"{t['id']} không có bằng chứng", "loai_ky_thuat")
        for t in res["techniques"]
        if not t["evidence"]
    ]
    res["techniques"] = [t for t in res["techniques"] if t["evidence"]]
    if out:
        _lower_confidence(res)
    return out


# ---------- luật 5: không thêm sự kiện (§2.3 SRS) ----------
ENTITY = {
    "IP": re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    "đường dẫn": re.compile(
        r"\b[A-Za-z]:\\[^\s\"',;()]+|(?<![\w.])/(?:[\w.-]+/)+[\w.-]+"
    ),
    "tiến trình": re.compile(
        r"\b[\w-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|php|sh|py|sys)\b", re.I
    ),
    "người dùng": re.compile(
        r"(?<![\\\w:])[A-Za-z][\w.-]*\\[\w.$-]+"
        r"|(?:\buser|tài khoản|người dùng|account)\s+[\"'`]?([A-Za-z0-9._$-]{2,})(?=[\s,.;:)\]\"'`]|$)",
        re.I,
    ),
}


def entities(text):
    """Các (loại, giá trị) trông như IP, đường dẫn, tên tiến trình, tên người dùng trong text."""
    found = []
    for kind, rx in ENTITY.items():
        for m in rx.finditer(text):
            value = m.group(1) if m.lastindex else m.group(0)
            found.append((kind, value.rstrip(".")))
    return found


def r5_no_new_facts(res, ctx):
    """Mọi IP, đường dẫn, tên tiến trình, tên người dùng trong summary phải có trong gói."""
    haystack = "\n".join(ctx.pack.values()).lower()
    new = sorted(
        {(k, v) for k, v in entities(res["summary"]) if v.lower() not in haystack}
    )
    if not new:
        return []
    _lower_confidence(res)
    return [_v("R5", f"{k} '{v}' không có trong gói", "ha_tin_cay") for k, v in new]


# ---------- luật 6: giới hạn ----------
SENTENCE_END = re.compile(r"(?<=[.!?…])\s+")


def r6_limits(res, ctx):
    """Tóm tắt ≤ 10 câu (cắt bớt), mã không lặp, rank không trùng, tối đa 3 kỹ thuật."""
    out = []
    sentences = [s for s in SENTENCE_END.split(res["summary"].strip()) if s]
    if len(sentences) > MAX_SENTENCES:
        res["summary"] = " ".join(sentences[:MAX_SENTENCES])
        out.append(
            _v("R6", f"summary có {len(sentences)} câu, cắt còn {MAX_SENTENCES}", "sua")
        )
    techs = sorted(
        res["techniques"], key=lambda t: t["rank"]
    )  # sorted giữ thứ tự khi bằng
    seen, unique = set(), []
    for t in techs:
        if t["id"] in seen:
            out.append(_v("R6", f"{t['id']} bị lặp", "sua"))
        else:
            seen.add(t["id"])
            unique.append(t)
    ranks = [t["rank"] for t in unique]
    if len(set(ranks)) < len(ranks):
        out.append(_v("R6", f"rank bị trùng {ranks}, đánh lại 1..{len(ranks)}", "sua"))
    if len(unique) > MAX_TECHNIQUES:
        out.append(
            _v(
                "R6",
                f"{len(unique)} kỹ thuật, giữ {MAX_TECHNIQUES} kỹ thuật rank cao nhất",
                "sua",
            )
        )
        unique = unique[:MAX_TECHNIQUES]
    for i, t in enumerate(unique):
        t["rank"] = i + 1
    res["techniques"] = unique
    return out


# ---------- luật 7: nhất quán ----------
def r7_consistency(res, ctx):
    """not_suspicious hoặc insufficient_evidence <=> danh sách kỹ thuật rỗng."""
    no_tech = res["verdict"] == "not_suspicious" or res["insufficient_evidence"]
    if no_tech and res["techniques"]:
        res["techniques"] = []
        return [
            _v(
                "R7",
                "verdict/insufficient_evidence nói không có kỹ thuật nhưng vẫn có mã",
                "bo_ma",
            )
        ]
    if not no_tech and not res["techniques"]:
        res["insufficient_evidence"] = True
        return [
            _v(
                "R7",
                "suspicious nhưng không còn kỹ thuật hợp lệ nào",
                "chuyen_thieu_can_cu",
            )
        ]
    return []


# ---------- luật 8: tên kỹ thuật lấy từ bảng ATT&CK ----------
def r8_names(res, ctx):
    """Gắn tên và chiến thuật từ bảng ATT&CK; không dùng chữ LLM viết làm tên."""
    for t in res["techniques"]:
        t["name"] = ctx.attack[t["id"]]["name"]
        t["tactics"] = ctx.attack[t["id"]]["tactics"]
    return []


# ---------- luật 9: lệch với baseline ML ----------
def slug(tactic):
    """'Lateral Movement' -> 'lateral-movement' (dạng phase_name của ATT&CK)."""
    return tactic.strip().lower().replace(" ", "-")


def r9_baseline(res, ctx):
    """Chiến thuật baseline TF-IDF + LR không nằm trong chiến thuật của kỹ thuật rank 1 → cần người xem."""
    if ctx.baseline_tactic is None or not res["techniques"]:
        return []
    top = res["techniques"][0]
    if slug(ctx.baseline_tactic) in ctx.attack[top["id"]]["tactics"]:
        return []
    return [
        _v(
            "R9",
            f"baseline đoán '{ctx.baseline_tactic}', {top['id']} thuộc "
            f"{ctx.attack[top['id']]['tactics']}",
            "can_nguoi_xem",
        )
    ]


# ---------- luật 10: chống chèn prompt ----------
def r10_injection(res, ctx):
    """Không trả mã mà câu chèn yêu cầu; câu chèn đòi 'an toàn' mà verdict an toàn → cần người xem."""
    out = []
    hit = [t["id"] for t in res["techniques"] if t["id"] in ctx.injected_codes]
    if hit:
        res["techniques"] = [
            t for t in res["techniques"] if t["id"] not in ctx.injected_codes
        ]
        out.append(_v("R10", f"mã do câu chèn yêu cầu: {hit}", "loai_ky_thuat"))
    if ctx.injected_safe and res["verdict"] == "not_suspicious":
        out.append(
            _v(
                "R10",
                "câu chèn đòi kết luận an toàn và verdict đúng là not_suspicious",
                "can_nguoi_xem",
            )
        )
    if out:
        _lower_confidence(res)
    return out


# ---------- chạy đủ 10 luật ----------
RULES = [
    r2_valid_codes,
    r10_injection,
    r3_real_evidence,
    r4_has_evidence,
    r6_limits,
    r5_no_new_facts,
    r7_consistency,
    r8_names,
    r9_baseline,
]


def validate(raw, ctx):
    """Đầu ra thô của LLM -> báo cáo: hợp lệ không, kết quả đã sửa, cần người xem, vi phạm."""
    res, violations = r1_schema(raw)
    if res is None:
        return {
            "valid": False,
            "needs_review": True,
            "result": None,
            "violations": violations,
        }
    for rule in RULES:
        violations += rule(res, ctx)
    return {
        "valid": True,
        "needs_review": bool(violations),
        "result": res,
        "violations": violations,
    }


def log_violations(alert_id, report, path):
    """Ghi thêm mỗi vi phạm thành một dòng JSON để thống kê sau."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with open(path, "a", encoding="utf-8") as f:
        for v in report["violations"]:
            f.write(
                json.dumps({"ts": now, "alert_id": alert_id, **v}, ensure_ascii=False)
                + "\n"
            )


def to_teacher(report):
    """Báo cáo -> khuôn của thầy (tom_tat, du_can_cu, ma_attack, bang_chung) để dùng srs.score."""
    res = report["result"]
    if res is None:
        return {"tom_tat": "", "du_can_cu": False, "ma_attack": [], "bang_chung": []}
    codes = [t["id"] for t in res["techniques"]]
    evidence = sorted(
        {e for t in res["techniques"] for e in t["evidence"]}, key=lambda e: int(e[1:])
    )
    return {
        "tom_tat": res["summary"],
        "du_can_cu": bool(codes) and not res["insufficient_evidence"],
        "ma_attack": codes,
        "bang_chung": evidence,
    }
