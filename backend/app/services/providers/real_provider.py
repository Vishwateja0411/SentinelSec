from typing import Any, Dict, List, Tuple
from backend.app.models.assessment import Assessment
from backend.app.models.target import Target
from backend.app.schemas.finding import FindingCreate
from backend.app.services.providers.base import BaseScannerProvider


class RealScannerProvider(BaseScannerProvider):
    """
    Live Scanner Provider Interface.
    Enforces that live network scanning remains strictly disabled until
    isolated scanner worker sandboxes and comprehensive safe execution controls
    are fully implemented and verified.
    
    Never falls back silently to demonstration data.
    """

    async def execute_assessment(
        self, assessment: Assessment, target: Target
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        raise NotImplementedError(
            "Real assessment execution is currently disabled. "
            "Isolated scanning worker sandboxes, scope boundary validation, "
            "and rate-limiting controls must be implemented and verified before live scanning can be enabled."
        )
