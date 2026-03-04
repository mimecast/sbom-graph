"""Unit tests for trust score Celery tasks and the propagation algorithm."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sbom_graph_enrichment.tasks import (
    _propagate,
    _reverse_topological_sort,
    _serialise_findings,
    _deserialise_findings,
)
from sbom_graph_enrichment.certifiers.base import Finding, FindingKind


class TestPropagate:
    """Tests for the _propagate algorithm."""

    def test_leaf_node_effective_equals_direct(self) -> None:
        """A node with no deps has effective == direct."""
        direct = {"A": 8.0}
        children: dict[str, list[str]] = {}

        eff, inh, mp, dc = _propagate(direct, children, alpha=0.4, decay=0.8, max_depth=20)

        assert eff["A"] == 8.0
        assert inh["A"] == 0.0
        assert mp["A"] == 8.0
        assert dc["A"] == 0

    def test_simple_chain(self) -> None:
        """A -> B -> C  (linear chain)."""
        direct = {"A": 8.0, "B": 6.0, "C": 4.0}
        children = {"A": ["B"], "B": ["C"]}

        eff, inh, mp, dc = _propagate(direct, children, alpha=0.4, decay=0.8, max_depth=20)

        assert eff["C"] == 4.0
        assert mp["A"] <= 4.0
        assert dc["A"] >= 2

    def test_diamond_dependency(self) -> None:
        """A -> B, A -> C, B -> D, C -> D  (diamond)."""
        direct = {"A": 8.0, "B": 7.0, "C": 6.0, "D": 3.0}
        children = {"A": ["B", "C"], "B": ["D"], "C": ["D"]}

        eff, inh, mp, dc = _propagate(direct, children, alpha=0.4, decay=0.8, max_depth=20)

        assert eff["D"] == 3.0
        assert mp["A"] <= 3.0
        assert dc["A"] >= 3

    def test_no_scored_deps_treated_as_leaf(self) -> None:
        """A -> B where B has no TrustScore."""
        direct = {"A": 7.0}
        children = {"A": ["B"]}

        eff, inh, mp, dc = _propagate(direct, children, alpha=0.4, decay=0.8, max_depth=20)

        assert eff["A"] == 7.0
        assert dc["A"] == 0

    def test_alpha_zero_pure_inheritance(self) -> None:
        """With alpha=0, effective is pure inherited score."""
        direct = {"A": 10.0, "B": 2.0}
        children = {"A": ["B"]}

        eff, inh, mp, dc = _propagate(direct, children, alpha=0.0, decay=0.8, max_depth=20)

        assert eff["B"] == 2.0
        assert abs(eff["A"] - 2.0) < 0.01

    def test_alpha_one_ignores_inheritance(self) -> None:
        """With alpha=1, effective equals direct even with bad deps."""
        direct = {"A": 10.0, "B": 0.0}
        children = {"A": ["B"]}

        eff, inh, mp, dc = _propagate(direct, children, alpha=1.0, decay=0.8, max_depth=20)

        assert eff["A"] == 10.0

    def test_cycle_handled_gracefully(self) -> None:
        """A -> B -> A (cycle) should not hang."""
        direct = {"A": 7.0, "B": 5.0}
        children = {"A": ["B"], "B": ["A"]}

        eff, inh, mp, dc = _propagate(direct, children, alpha=0.4, decay=0.8, max_depth=20)

        assert "A" in eff
        assert "B" in eff


class TestReverseTopologicalSort:
    """Tests for _reverse_topological_sort."""

    def test_linear_chain(self) -> None:
        nodes = {"A", "B", "C"}
        children = {"A": ["B"], "B": ["C"]}

        order = _reverse_topological_sort(nodes, children)

        assert order.index("C") < order.index("B")
        assert order.index("B") < order.index("A")

    def test_diamond(self) -> None:
        nodes = {"A", "B", "C", "D"}
        children = {"A": ["B", "C"], "B": ["D"], "C": ["D"]}

        order = _reverse_topological_sort(nodes, children)

        assert order.index("D") < order.index("B")
        assert order.index("D") < order.index("C")
        assert order.index("B") < order.index("A")

    def test_disconnected_nodes(self) -> None:
        nodes = {"A", "B", "C"}
        children: dict[str, list[str]] = {}

        order = _reverse_topological_sort(nodes, children)

        assert set(order) == nodes

    def test_cycle_includes_all_nodes(self) -> None:
        nodes = {"A", "B"}
        children = {"A": ["B"], "B": ["A"]}

        order = _reverse_topological_sort(nodes, children)

        assert set(order) == nodes


class TestSerialiseFindingsRoundTrip:
    """Tests for serialise/deserialise roundtrip."""

    def test_roundtrip(self) -> None:
        findings = [
            Finding(
                kind=FindingKind.SCORECARD,
                source="scorecard",
                package_url="pkg:npm/test@1.0",
                data={"overall_score": 7.5},
            ),
            Finding(
                kind=FindingKind.VULNERABILITY,
                source="osv",
                package_url="pkg:npm/test@1.0",
                data={"id": "CVE-1"},
            ),
        ]

        serialised = _serialise_findings(findings)
        assert len(serialised) == 2
        assert serialised[0]["kind"] == "scorecard"

        roundtripped = _deserialise_findings(serialised)
        assert len(roundtripped) == 2
        assert roundtripped[0].kind == FindingKind.SCORECARD
        assert roundtripped[1].data["id"] == "CVE-1"

    def test_deserialise_skips_invalid(self) -> None:
        data = [
            {"kind": "scorecard", "source": "scorecard", "data": {}},
            {"kind": "INVALID", "source": "x", "data": {}},
            {"source": "y", "data": {}},
        ]
        result = _deserialise_findings(data)
        assert len(result) == 1
