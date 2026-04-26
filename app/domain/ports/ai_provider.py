from typing import Protocol, runtime_checkable

from domain.entities import GateDecision, ImageReport


@runtime_checkable
class AIProviderPort(Protocol):
    @property
    def provider_name(self) -> str: ...

    async def analyze(self, report: ImageReport) -> GateDecision: ...

    async def generate_summary(
        self, report: ImageReport, decision: str, reason: str
    ) -> str | None: ...
