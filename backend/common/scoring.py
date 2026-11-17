from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SCORING_VERSION = '2.0'

SAFE_MIN = 80
SUSPICIOUS_MIN = 50

# Mức trừ tối đa theo từng nhóm tín hiệu.
CATEGORY_CAPS: Dict[str, int] = {
    'reputation': 100,   # VirusTotal, Safe Browsing, URLhaus, MalwareBazaar, ClamAV
    'url': 55,           # cấu trúc URL / tên miền
    'domain': 40,        # tuổi domain, redirect, chứng chỉ, trang đích
    'sender': 45,        # SPF/DKIM/DMARC, giả mạo người gửi
    'content': 60,       # nội dung email (NLP luật)
    'links': 70,         # điểm của các link nằm trong email
    'attachment': 90,    # điểm của tệp đính kèm trong email
    'file': 80,          # phân tích tĩnh tệp
}


@dataclass(frozen=True)
class Finding:
    code: str
    value: float = 1
    detail: str = ''
    evidence: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class Rule:
    category: str
    reason: str                              # str.format(value=..., detail=...)
    penalty: int = 0                         # điểm trừ cố định
    per_unit: float = 0                      # điểm trừ cho mỗi đơn vị ``value``
    max_penalty: Optional[int] = None        # trần cho per_unit
    tiers: Tuple[Tuple[float, int], ...] = ()  # ((ngưỡng, điểm trừ), ...)
    tier_mode: str = 'ge'                    # 'ge': value >= ngưỡng (giảm dần); 'le': value <= ngưỡng (tăng dần)
    ceiling: Optional[int] = None
    ceiling_tiers: Tuple[Tuple[float, int], ...] = ()


def _tier(tiers, value, mode):
    for threshold, amount in tiers:
        if (mode == 'ge' and value >= threshold) or (mode == 'le' and value <= threshold):
            return amount
    return 0


# --------------------------------------------------------------------------- #
# BẢNG LUẬT CHẤM ĐIỂM
# --------------------------------------------------------------------------- #
RULES: Dict[str, Rule] = {
    # ---- Uy tín từ nguồn bên ngoài -------------------------------------------------
    'VT_MALICIOUS': Rule('reputation', '{value:.0f} công cụ bảo mật (VirusTotal) báo link độc hại',
                         tiers=((5, 85), (2, 60), (1, 35))),
    'VT_SUSPICIOUS': Rule('reputation', '{value:.0f} công cụ bảo mật (VirusTotal) báo đáng ngờ',
                          per_unit=15, max_penalty=30),
    'GSB_MATCH': Rule('reputation', 'Google Safe Browsing xếp vào danh sách nguy hiểm ({detail})',
                      penalty=80, ceiling=20),
    'URLHAUS_LISTED': Rule('reputation', 'URLhaus ghi nhận link đang phát tán mã độc ({detail})',
                           penalty=80, ceiling=20),
    'FILE_VT_MALICIOUS': Rule('reputation', '{value:.0f} công cụ diệt virus (VirusTotal) phát hiện mã độc',
                              tiers=((5, 100), (2, 70), (1, 40)), ceiling=None,
                              ceiling_tiers=((5, 0),)),
    'FILE_VT_SUSPICIOUS': Rule('reputation', '{value:.0f} công cụ diệt virus báo tệp đáng ngờ',
                               per_unit=15, max_penalty=30),
    'MALWAREBAZAAR_HIT': Rule('reputation', 'Mã băm tệp có trong cơ sở dữ liệu mã độc MalwareBazaar ({detail})',
                              penalty=100, ceiling=0),
    'CLAMAV_INFECTED': Rule('reputation', 'ClamAV phát hiện mã độc ({detail})', penalty=100, ceiling=0),

    # ---- Cấu trúc URL ------------------------------------------------------------
    'NO_HTTPS': Rule('url', 'Không dùng kết nối bảo mật (HTTPS)', penalty=10),
    'IP_HOST': Rule('url', 'Dùng địa chỉ IP thay cho tên miền', penalty=30),
    'SUSPICIOUS_TLD': Rule('url', 'Đuôi tên miền hay bị lạm dụng ({detail})', penalty=15),
    'URL_KEYWORDS': Rule('url', 'Chứa từ khóa nhạy cảm: {detail}', per_unit=8, max_penalty=24),
    'BRAND_IMPERSONATION': Rule('url', 'Tên miền chứa tên "{detail}" nhưng không phải trang chính thức', penalty=30),
    'PUNYCODE_IDN': Rule('url', 'Tên miền dùng ký tự quốc tế dễ gây nhầm lẫn ({detail})', penalty=20),
    'USERINFO_AT': Rule('url', 'Link chứa ký tự "@" để đánh lừa tên miền thật', penalty=25),
    'MANY_HYPHENS': Rule('url', 'Tên miền có quá nhiều dấu gạch ngang', penalty=12),
    'MANY_SUBDOMAINS': Rule('url', 'Tên miền có quá nhiều tầng tên miền con', penalty=10),
    'URL_SHORTENER': Rule('url', 'Link rút gọn che giấu địa chỉ thật ({detail})', penalty=10),
    'NONSTANDARD_PORT': Rule('url', 'Link dùng cổng kết nối bất thường (:{detail})', penalty=8),
    'FREE_HOSTING': Rule('url', 'Trang nằm trên dịch vụ lưu trữ miễn phí ({detail})', penalty=8),

    # ---- Tên miền, chuyển hướng, trang đích ----------------------------------------
    'DOMAIN_NEW': Rule('domain', 'Tên miền mới đăng ký cách đây {value:.0f} ngày',
                       tiers=((7, 35), (30, 25), (90, 10)), tier_mode='le'),
    'REDIRECT_CHAIN': Rule('domain', 'Link chuyển hướng qua {value:.0f} bước',
                           tiers=((4, 20), (3, 15), (2, 8))),
    'REDIRECT_CROSS_DOMAIN': Rule('domain', 'Link chuyển hướng sang tên miền khác ({detail})', penalty=12),
    'SSL_INVALID': Rule('domain', 'Chứng chỉ bảo mật (SSL) không hợp lệ', penalty=15),
    'LANDING_PASSWORD_FORM': Rule('domain', 'Trang đích có ô nhập mật khẩu', penalty=15),
    'FORM_ACTION_EXTERNAL': Rule('domain', 'Biểu mẫu trên trang gửi dữ liệu sang tên miền khác ({detail})', penalty=15),

    # ---- Người gửi email -----------------------------------------------------------
    'SPF_FAIL': Rule('sender', 'Email không vượt qua kiểm tra SPF', penalty=15),
    'SPF_SOFTFAIL': Rule('sender', 'Email bị đánh dấu SPF softfail', penalty=8),
    'DKIM_FAIL': Rule('sender', 'Email không vượt qua kiểm tra chữ ký DKIM', penalty=15),
    'DMARC_FAIL': Rule('sender', 'Email vi phạm chính sách xác thực DMARC', penalty=20),
    'REPLYTO_MISMATCH': Rule('sender', 'Địa chỉ trả lời khác tên miền người gửi ({detail})', penalty=15),
    'RETURNPATH_MISMATCH': Rule('sender', 'Return-Path khác tên miền người gửi ({detail})', penalty=10),
    'DISPLAY_NAME_SPOOF': Rule('sender', 'Tên hiển thị giả danh nơi khác ({detail})', penalty=20),
    'SENDER_BRAND_MISMATCH': Rule('sender', 'Tên miền người gửi giả mạo thương hiệu "{detail}"', penalty=25),

    # ---- Nội dung email (luật NLP) --------------------------------------------------
    'URGENT_PHRASES': Rule('content', 'Có cụm từ gây áp lực, hối thúc: {detail}', per_unit=10, max_penalty=30),
    'CREDENTIAL_REQUEST': Rule('content', 'Yêu cầu cung cấp thông tin nhạy cảm (mật khẩu, OTP, thẻ)', penalty=25),
    'LURE_PHRASES': Rule('content', 'Có cụm từ dụ dỗ trúng thưởng/hoàn tiền: {detail}', penalty=15),
    'LINK_TEXT_MISMATCH': Rule('content', 'Văn bản link hiển thị tên miền khác với địa chỉ thật ({detail})', penalty=25),

    # ---- Điểm của thành phần con trong email ----------------------------------------
    'EMAIL_LINK_RISK': Rule('links', 'Link trong email có độ tin cậy thấp ({detail})',
                            per_unit=0.7, max_penalty=70),
    'EMAIL_ATTACHMENT_RISK': Rule('attachment', 'Tệp đính kèm có độ tin cậy thấp ({detail})',
                                  per_unit=0.9, max_penalty=90),

    # ---- Phân tích tĩnh tệp ---------------------------------------------------------
    'HIGH_RISK_EXT': Rule('file', 'Đuôi tệp thực thi/script rủi ro cao ({detail})', penalty=25),
    'DOUBLE_EXTENSION': Rule('file', 'Tên tệp có đuôi kép giả mạo ({detail})', penalty=45),
    'RLO_FILENAME': Rule('file', 'Tên tệp chứa ký tự đảo chiều để che đuôi thật', penalty=45),
    'EXEC_DISGUISED': Rule('file', 'Tệp mang đuôi {detail} nhưng thực chất là chương trình thực thi', penalty=45),
    'MAGIC_MISMATCH': Rule('file', 'Nội dung tệp không khớp với đuôi tệp ({detail})', penalty=25),
    'YARA_MATCH': Rule('file', 'Khớp {value:.0f} mẫu chữ ký mã độc: {detail}', per_unit=20, max_penalty=50),
    'OFFICE_MACRO': Rule('file', 'Tệp Office chứa macro VBA', penalty=25),
    'OFFICE_REMOTE_TEMPLATE': Rule('file', 'Tệp Office tải mẫu/đối tượng từ máy chủ bên ngoài', penalty=30),
    'PDF_ACTIVE_CONTENT': Rule('file', 'Tệp PDF chứa mã chủ động ({detail})', penalty=25),
    'ARCHIVE_CONTAINS_EXECUTABLE': Rule('file', 'Tệp nén chứa chương trình thực thi ({detail})', penalty=30),
    'ARCHIVE_ENCRYPTED': Rule('file', 'Tệp nén đặt mật khẩu nên không thể quét nội dung', penalty=15),
    'HTML_CREDENTIAL_FORM': Rule('file', 'Tệp HTML có biểu mẫu thu thập mật khẩu', penalty=35),
    'HIGH_ENTROPY': Rule('file', 'Entropy rất cao ({detail}/8.0), dấu hiệu tệp bị nén/mã hóa (packed)', penalty=35),
}


@dataclass
class Signal:
    code: str
    category: str
    penalty: int
    reason: str
    ceiling: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {'code': self.code, 'category': self.category,
                               'penalty': self.penalty, 'reason': self.reason}
        if self.ceiling is not None:
            out['ceiling'] = self.ceiling
        return out


@dataclass
class ScoreResult:
    score: int
    risk_level: str
    confidence: str
    reasons: List[str]
    signals: List[Signal] = field(default_factory=list)
    ceiling_applied: Optional[int] = None


def risk_level_for(score: int) -> str:
    if score >= SAFE_MIN:
        return 'SAFE'
    if score >= SUSPICIOUS_MIN:
        return 'SUSPICIOUS'
    return 'DANGEROUS'


def _evaluate(finding: Finding) -> Optional[Signal]:
    rule = RULES.get(finding.code)
    if rule is None:
        print(f'[scoring] bỏ qua finding không có luật: {finding.code}')
        return None
    value = finding.value
    if rule.tiers:
        penalty = _tier(rule.tiers, value, rule.tier_mode)
    elif rule.per_unit:
        penalty = round(rule.per_unit * value)
        if rule.max_penalty is not None:
            penalty = min(penalty, rule.max_penalty)
    else:
        penalty = rule.penalty
    ceiling = rule.ceiling
    if rule.ceiling_tiers:
        tiered = _tier(rule.ceiling_tiers, value, rule.tier_mode)
        # _tier trả 0 khi không khớp nên cần phân biệt "không khớp" với "trần = 0"
        matched = any((value >= t) if rule.tier_mode == 'ge' else (value <= t)
                      for t, _ in rule.ceiling_tiers)
        if matched:
            ceiling = tiered if ceiling is None else min(ceiling, tiered)
    if penalty <= 0 and ceiling is None:
        return None
    reason = rule.reason.format(value=value, detail=finding.detail)
    return Signal(finding.code, rule.category, int(penalty), reason, ceiling)


def compute_score(findings: List[Finding], *, reputation_ok: int = 0,
                  reputation_needed: bool = True) -> ScoreResult:
    """Tổng hợp các finding thành điểm tin cậy 0-100.
    """
    # 1. Mỗi mã chỉ tính một lần (giữ bản trừ nặng nhất) để không cộng trùng.
    best: Dict[str, Signal] = {}
    for f in findings:
        sig = _evaluate(f)
        if sig is None:
            continue
        old = best.get(sig.code)
        if old is None or sig.penalty > old.penalty:
            best[sig.code] = sig
    signals = sorted(best.values(), key=lambda s: (-s.penalty, s.code))

    # 2. Cộng theo nhóm, áp trần từng nhóm.
    totals: Dict[str, int] = {}
    for s in signals:
        totals[s.category] = totals.get(s.category, 0) + s.penalty
    deducted = sum(min(v, CATEGORY_CAPS.get(cat, 100)) for cat, v in totals.items())
    score = 100 - deducted

    # 3. Mức trần của các tín hiệu nghiêm trọng.
    ceilings = [s.ceiling for s in signals if s.ceiling is not None]
    ceiling_applied = min(ceilings) if ceilings else None
    if ceiling_applied is not None:
        score = min(score, ceiling_applied)
    score = max(0, min(100, score))

    if not reputation_needed:
        confidence = 'MEDIUM'
    else:
        confidence = 'HIGH' if reputation_ok >= 2 else 'MEDIUM' if reputation_ok == 1 else 'LOW'

    reasons: List[str] = []
    for s in signals:
        if s.reason not in reasons:
            reasons.append(s.reason)
    if confidence == 'LOW':
        reasons.append('Chưa đối chiếu được với nguồn dữ liệu bảo mật bên ngoài nào, '
                       'kết quả chỉ dựa trên phân tích kỹ thuật')

    return ScoreResult(score=score, risk_level=risk_level_for(score), confidence=confidence,
                       reasons=reasons, signals=signals, ceiling_applied=ceiling_applied)


def build_result(score: ScoreResult, details: Dict[str, Any], *, scanned_at: Optional[int] = None) -> Dict[str, Any]:
    """Đóng gói kết quả theo đúng format mà status_lambda và frontend đang đọc."""
    return {
        'trust_score': score.score,
        'risk_level': score.risk_level,
        'confidence': score.confidence,
        'reasons': score.reasons,
        'signals': [s.as_dict() for s in score.signals],
        'details': details,
        'scoring_version': SCORING_VERSION,
        'scanned_at': scanned_at if scanned_at is not None else int(time.time()),
    }


def error_result(message: str, *, scanned_at: Optional[int] = None) -> Dict[str, Any]:
    """Kết quả khi quét lỗi. Frontend nhận ra qua risk_level bắt đầu bằng 'SCAN ERROR'."""
    return {
        'trust_score': 0,
        'risk_level': 'SCAN ERROR',
        'confidence': 'LOW',
        'reasons': [],
        'signals': [],
        'details': {'error': str(message)[:200]},
        'scoring_version': SCORING_VERSION,
        'scanned_at': scanned_at if scanned_at is not None else int(time.time()),
    }
