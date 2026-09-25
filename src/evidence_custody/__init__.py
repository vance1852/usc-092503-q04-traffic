"""交通事故证据材料保全链服务的基础组件。"""

from .service import HANDOVER_ROLES, ROLE_PERMISSIONS, EvidenceCustodyService, mask_contact

__all__ = [
    "EvidenceCustodyService",
    "HANDOVER_ROLES",
    "ROLE_PERMISSIONS",
    "mask_contact",
]

__version__ = "0.1.0"
