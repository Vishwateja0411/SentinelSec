from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from backend.app.models.assessment import Assessment
from backend.app.models.target import Target
from backend.app.schemas.finding import FindingCreate


class BaseScannerProvider(ABC):
    """
    Abstract interface for security assessment execution and analysis providers.
    Supports modular source analysis, supply-chain checks, configuration audits,
    and demonstration fixtures.
    """

    @abstractmethod
    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        """
        Execute or evaluate assessment checks.
        Returns:
            Tuple of:
            - List of FindingCreate schemas to persist
            - Tool execution status dictionary (e.g. {'semgrep_sast': 'completed'})
            - Execution metadata / incomplete checks notes
        """
        pass
