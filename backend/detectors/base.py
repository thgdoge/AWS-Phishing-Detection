"""Kiểu dữ liệu chung mà mọi detector trả về cho Scoring Engine."""
from dataclasses import dataclass, field
from typing import Any, Dict, List

from common.scoring import Finding


@dataclass
class Analysis:
    details: Dict[str, Any]
    findings: List[Finding] = field(default_factory=list)
    reputation_ok: int = 0            # số nguồn uy tín bên ngoài đã trả lời được
    reputation_needed: bool = True    # False: không có gì để tra cứu (vd. email chỉ có chữ)
