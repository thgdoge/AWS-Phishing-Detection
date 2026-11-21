from dataclasses import dataclass, field
from typing import Any, Dict, List

from common.scoring import Finding


@dataclass
class Analysis:
    details: Dict[str, Any]
    findings: List[Finding] = field(default_factory=list)
    reputation_ok: int = 0            
    reputation_needed: bool = True
