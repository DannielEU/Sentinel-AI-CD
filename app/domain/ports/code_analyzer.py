from typing import Protocol, runtime_checkable

from domain.code_entities import CodeFile, CodeVulnerability


@runtime_checkable
class CodeAnalyzerPort(Protocol):
    @property
    def analyzer_name(self) -> str: ...

    async def analyze_file(self, file: CodeFile) -> list[CodeVulnerability]: ...
