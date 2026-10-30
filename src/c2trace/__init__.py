"""C2Trace alert-first C2 traceback package."""

from .execution import (
    LlmCallProvenance,
    McpToolReceipt,
    PreparedToolCall,
    ResponseAuthorization,
    TargetLock,
    TargetObservation,
    ToolClient,
)

__all__ = [
    "LlmCallProvenance",
    "McpToolReceipt",
    "PreparedToolCall",
    "ResponseAuthorization",
    "TargetLock",
    "TargetObservation",
    "ToolClient",
    "__version__",
]

__version__ = "0.1.0"
