"""Turning the connectivity model into artefacts.

``mermaid``  the single topology diagram, as Mermaid source.
``d2``       the same diagram as D2 source (opt-in with ``--d2``).
``scene``    content shared by both renderers: palette, titles, classifications.
``reports``  CSV, JSON and Markdown evidence, written only with ``--reports``.

Both diagrams are pure functions of a ``Topology`` and the flow model, so
re-rendering from cache needs no API access.
"""

from . import d2, mermaid, reports, scene  # noqa: F401

__all__ = ["d2", "mermaid", "reports", "scene"]
