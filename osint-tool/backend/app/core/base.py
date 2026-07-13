"""
Common interface for all OSINT modules (plugin architecture).

To add a new source:
    1. Create a class that inherits from OSINTModule.
    2. Declare `name` and `supported_types`.
    3. Implement `_run(target)`.
    4. Register the class with @register.

You do not need to modify core or the orchestrator.
"""
import time
from abc import ABC, abstractmethod

from .models import ModuleResult, ModuleStatus, TargetType, Finding


# Registro global de módulos disponibles
REGISTRY: list[type["OSINTModule"]] = []


def register(cls: type["OSINTModule"]) -> type["OSINTModule"]:
    """Decorador para registrar un módulo automáticamente."""
    REGISTRY.append(cls)
    return cls


class OSINTModule(ABC):
    name: str = "base"
    supported_types: list[TargetType] = []
    # If the module requires an API key, mark it here so it can be
    # cleanly skipped when the key is not configured.
    requires_key: bool = False

    def supports(self, target_type: TargetType) -> bool:
        return target_type in self.supported_types

    async def run(self, target: str, target_type: TargetType) -> ModuleResult:
        """Envuelve _run con medición de tiempo y captura de errores.

        Un fallo en un módulo NUNCA debe tumbar el escaneo completo.
        """
        start = time.perf_counter()
        try:
            findings = await self._run(target)
            status = ModuleStatus.OK if findings else ModuleStatus.EMPTY
            result = ModuleResult(
                module=self.name,
                target=target,
                target_type=target_type,
                status=status,
                findings=findings,
            )
        except Exception as exc:  # noqa: BLE001 - queremos aislar cualquier fallo
            result = ModuleResult(
                module=self.name,
                target=target,
                target_type=target_type,
                status=ModuleStatus.ERROR,
                error=f"{type(exc).__name__}: {exc}",
            )
        result.elapsed_ms = int((time.perf_counter() - start) * 1000)
        return result

    @abstractmethod
    async def _run(self, target: str) -> list[Finding]:
        """Source-specific logic. Returns a list of findings."""
        ...
