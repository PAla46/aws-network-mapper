"""Turning the connectivity model into artefacts.

``mermaid``  the single topology diagram.
``reports``  CSV, JSON and Markdown evidence, written only with ``--reports``.

Both are pure functions of a ``Topology`` and the flow model, so re-rendering
from cache needs no API access.
"""

from . import mermaid, reports  # noqa: F401

__all__ = ["mermaid", "reports"]
