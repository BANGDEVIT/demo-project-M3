"""Test cho src/validate.py: mỗi luật có test riêng, phần lớn là đầu ra cố tình sai."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src import srs  # noqa: E402
from src import validate as va  # noqa: E402

ATTACK, VERSION = va.load_attack()
PACK_760 = json.loads(
    (ROOT / "data" / "packs" / "pack_760.json").read_text(encoding="utf-8")
)
CANDS_760 = ["T1059.001", "T1027.010", "T1021.006", "T1562.002", "T1033"]

GOOD = {
    "verdict": "suspicious",
    "summary": (
        "Lúc 21:09:09 tài khoản THESHIRE.LOCAL\\pgustavo đăng nhập qua mạng vào "
        "workstation6 [E1]. Ngay sau đó wsmprovhost.exe tạo powershell.exe chạy lệnh "
        "mã hóa base64 với cửa sổ ẩn [E2][E3]. Script block mở đầu bằng đoạn sửa "
        "cachedGroupPolicySettings, dấu hiệu tắt ghi log script [E4]. 27 giây sau "
        "PowerShell chạy whoami.exe để xem tài khoản đang dùng [E6]."
    ),
    "techniques": [
        {
            "id": "T1059.001",
            "rank": 1,
            "evidence": ["E3", "E4"],
            "reason": "PowerShell chạy lệnh -enc, cửa sổ ẩn",
        },
        {
            "id": "T1021.006",
            "rank": 2,
            "evidence": ["E2", "E3"],
            "reason": "wsmprovhost.exe là cha của PowerShell: lệnh đến qua WinRM",
        },
        {
            "id": "T1562.002",
            "rank": 3,
            "evidence": ["E4"],
            "reason": "script sửa cachedGroupPolicySettings để tắt ghi log",
        },
    ],
    "confidence": 0.8,
    "insufficient_evidence": False,
}


def good(**changes):
    """Bản sao của GOOD, thay một số trường."""
    d = json.loads(json.dumps(GOOD))
    d.update(changes)
    return d


def tech(id_, rank, evidence=("E3",), reason="lý do"):
    return {"id": id_, "rank": rank, "evidence": list(evidence), "reason": reason}


def run(d, ctx=None):
    """Kiểm một đầu ra (dict hoặc chuỗi thô) với ngữ cảnh của cảnh báo 760."""
    raw = d if isinstance(d, str) else json.dumps(d, ensure_ascii=False)
    return va.validate(raw, ctx or va.make_context(PACK_760, CANDS_760, ATTACK))


def rules(report):
    return [v["rule"] for v in report["violations"]]


def codes(report):
    return [t["id"] for t in report["result"]["techniques"]]


# ---------- danh mục đầu ra cố tình sai cho cảnh báo 760 (ô 8.3 dùng lại) ----------
TWELVE = " ".join(f"Câu thứ {i} nói về PowerShell [E3]." for i in range(1, 13))
BAD_760 = {
    "JSON hỏng (bị cắt giữa chừng)": (
        '{"verdict": "suspicious", "summary": "PowerShell',
        "R1",
    ),
    "thiếu trường insufficient_evidence": (
        {k: v for k, v in GOOD.items() if k != "insufficient_evidence"},
        "R1",
    ),
    "confidence là chữ": (good(confidence="cao"), "R1"),
    "confidence 1.5": (good(confidence=1.5), "R1"),
    "verdict ngoài enum": (good(verdict="malicious"), "R1"),
    "trường lạ severity": (good(severity="high"), "R1"),
    "mã bịa T9999": (good(techniques=[tech("T9999", 1)]), "R2"),
    "mã thật nhưng ngoài ứng viên": (good(techniques=[tech("T1003.001", 1)]), "R2"),
    "mã của ATT&CK v19 (T1685)": (good(techniques=[tech("T1685", 1)]), "R2"),
    "bằng chứng giả E9": (good(techniques=[tech("T1059.001", 1, ["E3", "E9"])]), "R3"),
    "trích dẫn giả [E12] trong summary": (
        good(summary=GOOD["summary"] + " Xem thêm [E12]."),
        "R3",
    ),
    "kỹ thuật không có bằng chứng": (good(techniques=[tech("T1059.001", 1, [])]), "R4"),
    "nêu IP không có trong gói": (
        good(summary=GOOD["summary"] + " Script tải tiếp mã độc từ 10.10.10.5."),
        "R5",
    ),
    "nêu tiến trình không có trong gói": (
        good(summary=GOOD["summary"] + " Sau đó chạy mimikatz.exe."),
        "R5",
    ),
    "nêu tài khoản không có trong gói": (
        good(
            summary=GOOD["summary"].replace(
                "THESHIRE.LOCAL\\pgustavo", "THESHIRE\\administrator"
            )
        ),
        "R5",
    ),
    "tóm tắt 12 câu": (good(summary=TWELVE), "R6"),
    "4 kỹ thuật": (
        good(techniques=GOOD["techniques"] + [tech("T1033", 4, ["E6"])]),
        "R6",
    ),
    "rank trùng": (
        good(techniques=[tech("T1059.001", 1), tech("T1021.006", 1, ["E2"])]),
        "R6",
    ),
    "not_suspicious mà vẫn có mã": (good(verdict="not_suspicious"), "R7"),
    "insufficient_evidence mà vẫn có mã": (good(insufficient_evidence=True), "R7"),
    "suspicious mà không có mã": (good(techniques=[]), "R7"),
}


@pytest.mark.parametrize("name", list(BAD_760))
def test_bad_output_is_caught(name):
    """Mỗi đầu ra sai trong danh mục phải bị đúng luật dự kiến bắt."""
    d, expected = BAD_760[name]
    assert expected in rules(run(d)), name


def test_good_output_passes():
    report = run(GOOD)
    assert report["valid"] and not report["needs_review"]
    assert codes(report) == ["T1059.001", "T1021.006", "T1562.002"]


# ---------- luật 1 ----------
def test_r1_invalid_has_no_result():
    report = run('{"verdict": "suspicious"')
    assert not report["valid"] and report["result"] is None


# ---------- luật 2 ----------
def test_r2_drops_only_bad_code_and_caps_confidence():
    report = run(good(techniques=[tech("T1059.001", 1), tech("T9999", 2)]))
    assert codes(report) == ["T1059.001"]
    assert report["result"]["confidence"] == va.CONF_CAP


def test_r2_normalizes_lowercase_code():
    report = run(good(techniques=[tech(" t1059.001 ", 1)]))
    assert codes(report) == ["T1059.001"] and "R2" not in rules(report)


def test_r2_v19_code_rejected_even_if_in_candidates():
    ctx = va.make_context(PACK_760, CANDS_760 + ["T1685"], ATTACK)
    assert "T1685" not in ATTACK  # ATT&CK 18.1 chưa có mã này
    assert "R2" in rules(run(good(techniques=[tech("T1685", 1)]), ctx))


# ---------- luật 3, 4 ----------
def test_r3_removes_fake_evidence_keeps_technique():
    report = run(good(techniques=[tech("T1059.001", 1, ["E3", "E9"])]))
    assert report["result"]["techniques"][0]["evidence"] == ["E3"]


def test_r3_r4_only_fake_evidence_drops_technique():
    report = run(
        good(techniques=[tech("T1059.001", 1, ["E9"]), tech("T1033", 2, ["E6"])])
    )
    assert codes(report) == ["T1033"]
    assert {"R3", "R4"} <= set(rules(report))


# ---------- luật 5 ----------
def test_r5_flags_new_ip_and_caps_confidence():
    report = run(good(summary=GOOD["summary"] + " Máy điều khiển là 10.10.10.5."))
    assert any("10.10.10.5" in v["detail"] for v in report["violations"])
    assert report["result"]["confidence"] == va.CONF_CAP and report["needs_review"]


def test_r5_values_from_pack_are_not_flagged():
    text = (
        "THESHIRE\\pgustavo chạy C:\\windows\\system32\\wsmprovhost.exe rồi whoami.exe."
    )
    assert (
        va.r5_no_new_facts(
            good(summary=text), va.make_context(PACK_760, CANDS_760, ATTACK)
        )
        == []
    )


def test_r5_vietnamese_words_are_not_usernames():
    assert va.entities("tài khoản không tồn tại, người dùng đang đăng nhập") == []


# ---------- luật 6 ----------
def test_r6_cuts_summary_to_ten_sentences():
    report = run(good(summary=TWELVE))
    assert len(va.SENTENCE_END.split(report["result"]["summary"])) == 10


def test_r6_keeps_three_best_ranks():
    shuffled = [
        tech("T1033", 4, ["E6"]),
        tech("T1059.001", 1),
        tech("T1027.010", 3),
        tech("T1021.006", 2, ["E2"]),
    ]
    report = run(good(techniques=shuffled))
    assert codes(report) == ["T1059.001", "T1021.006", "T1027.010"]
    assert [t["rank"] for t in report["result"]["techniques"]] == [1, 2, 3]


def test_r6_duplicate_code_kept_once():
    report = run(good(techniques=[tech("T1059.001", 1), tech("T1059.001", 2)]))
    assert codes(report) == ["T1059.001"]


# ---------- luật 7 ----------
def test_r7_not_suspicious_empties_techniques():
    assert codes(run(good(verdict="not_suspicious"))) == []


def test_r7_all_codes_dropped_turns_insufficient():
    report = run(good(techniques=[tech("T9999", 1)]))
    assert report["result"]["insufficient_evidence"] is True
    assert va.to_teacher(report)["du_can_cu"] is False


# ---------- luật 8 ----------
def test_r8_name_comes_from_attack_table():
    report = run(
        good(techniques=[tech("T1059.001", 1, reason="Đây là kỹ thuật Mimikatz")])
    )
    t = report["result"]["techniques"][0]
    assert t["name"] == "PowerShell" and t["tactics"] == ["execution"]


# ---------- luật 9 ----------
def test_r9_flags_baseline_disagreement():
    ctx = va.make_context(
        PACK_760, CANDS_760, ATTACK, baseline_tactic="Credential Access"
    )
    report = run(GOOD, ctx)
    assert "R9" in rules(report) and report["needs_review"]
    assert report["result"]["confidence"] == GOOD["confidence"]  # R9 không hạ tin cậy


def test_r9_silent_when_baseline_agrees():
    ctx = va.make_context(PACK_760, CANDS_760, ATTACK, baseline_tactic="Execution")
    assert "R9" not in rules(run(GOOD, ctx))


# ---------- luật 10: ba ca chèn prompt của thầy ----------
def teacher_ctx(alert_id, candidates):
    alert = next(a for a in srs.load_alerts() if a["id"] == alert_id)
    return va.make_context(va.pack_from_lines(srs.evidence(alert)), candidates, ATTACK)


def teacher_output(techniques, verdict="suspicious", summary="Cảnh báo lab [E3]."):
    return {
        "verdict": verdict,
        "summary": summary,
        "techniques": techniques,
        "confidence": 0.9,
        "insufficient_evidence": False,
    }


def test_r10_lab0035_injected_whitelisted_code_dropped():
    ctx = teacher_ctx("LAB-0035", ["T1505.003", "T1190", "T1105", "T1486", "T1059.004"])
    assert "T1486" in srs.CODES  # mã này nằm trong 24 mã của thầy
    report = run(
        teacher_output([tech("T1486", 1, ["E4"]), tech("T1505.003", 2, ["E3"])]), ctx
    )
    assert codes(report) == ["T1505.003"] and "R10" in rules(report)


def test_r10_lab0033_injected_code_never_survives():
    ctx = teacher_ctx(
        "LAB-0033", ["T1110.001", "T1110", "T1078", "T1021.004", "T1136.001"]
    )
    report = run(teacher_output([tech("T9999", 1, ["E4"])]), ctx)
    assert codes(report) == [] and report["result"]["insufficient_evidence"]


def test_r10_lab0034_requested_safe_verdict_needs_review():
    ctx = teacher_ctx(
        "LAB-0034", ["T1059.001", "T1027", "T1105", "T1562.001", "T1070.001"]
    )
    report = run(
        teacher_output(
            [], verdict="not_suspicious", summary="Cảnh báo này an toàn [E4]."
        ),
        ctx,
    )
    assert "R10" in rules(report) and report["needs_review"]


# ---------- nhật ký và khuôn của thầy ----------
def test_log_violations_writes_one_line_per_violation(tmp_path):
    report = run(good(techniques=[tech("T9999", 1)]))
    path = tmp_path / "violations.jsonl"
    va.log_violations("760", report, path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert (
        len(lines) == len(report["violations"])
        and json.loads(lines[0])["alert_id"] == "760"
    )


def test_to_teacher_maps_fields():
    t = va.to_teacher(run(GOOD))
    assert t["ma_attack"] == ["T1059.001", "T1021.006", "T1562.002"]
    assert t["bang_chung"] == ["E2", "E3", "E4"] and t["du_can_cu"] is True
    assert srs.Assessment.model_validate(t)  # khớp khuôn Assessment của Buổi 4
