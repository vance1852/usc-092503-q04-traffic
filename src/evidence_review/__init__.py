"""交通事故结构化证据的基础组件。"""

from .contracts import EvidenceItem, EvidenceProtocol, ValidationError
from .analysis import ALGORITHM_VERSION, analyze, bootstrap_mean_interval
from .custody import CustodyService, event_hash, mask_contact, verify_chain
from .numeric import NumericSummary, WilsonInterval
from .service import EvidenceReviewService

__all__ = [
    "NumericSummary",
    "EvidenceItem",
    "EvidenceProtocol",
    "ValidationError",
    "WilsonInterval",
    "ALGORITHM_VERSION",
    "EvidenceReviewService",
    "CustodyService",
    "analyze",
    "bootstrap_mean_interval",
    "event_hash",
    "mask_contact",
    "verify_chain",
]

__version__ = "0.1.0"
