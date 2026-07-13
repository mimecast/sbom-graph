"""Tests for license dashboard report route.

The dashboard is backed by a split, streaming-friendly service API
(``get_license_risk_stats`` + paged ``get_license_risk_rows``) so the full
package set is never materialised (Phase 8 aggregate-materialization ceiling).
"""

from unittest.mock import MagicMock, patch


def _mock_service(stats, rows):
    """Build a mock FalkorDB service for the license-dashboard route.

    ``stats`` is the ``get_license_risk_stats`` payload; ``rows`` is the full
    flat package list. ``get_license_risk_rows`` honours the ``category`` filter
    and ``limit``/``offset`` slicing so both the streamed (JSON/Excel) and the
    per-category HTML sample paths behave realistically.
    """
    m = MagicMock()
    m.get_license_risk_stats.return_value = stats

    def _rows(internal_only=False, limit=None, offset=0, category=None):
        subset = [r for r in rows if category is None or r["category"] == category]
        if limit is None:
            return subset[offset:]
        return subset[offset : offset + limit]

    m.get_license_risk_rows.side_effect = _rows
    m.count_license_risk_rows.return_value = len(rows)
    return m


class TestLicenseDashboardRoute:
    """Tests for GET /reports/license-dashboard endpoint."""

    def test_returns_html_by_default(self, client):
        """License dashboard returns HTML by default with counts + samples."""
        stats = {
            "total_packages": 2,
            "categories": {
                "permissive": {"count": 1, "pct": 50.0},
                "weak_copyleft": {"count": 0, "pct": 0.0},
                "strong_copyleft": {"count": 1, "pct": 50.0},
                "proprietary": {"count": 0, "pct": 0.0},
                "unknown": {"count": 0, "pct": 0.0},
            },
        }
        rows = [
            {
                "category": "permissive",
                "purl": "pkg:maven/com.example/lib@1.0",
                "project_name": "lib",
                "version_name": "1.0",
                "spdx_id": "MIT",
                "license_name": "MIT License",
            },
            {
                "category": "strong_copyleft",
                "purl": "pkg:maven/com.example/gpl@2.0",
                "project_name": "gpl",
                "version_name": "2.0",
                "spdx_id": "GPL-3.0",
                "license_name": "GPL v3",
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=_mock_service(stats, rows),
        ):
            response = client.get("/reports/license-dashboard")

        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"
        assert b"License Compliance Dashboard" in response.data
        assert b"permissive" in response.data
        assert b"strong_copyleft" in response.data
        assert b"lib" in response.data
        assert b"gpl" in response.data

    def test_returns_json_when_requested(self, client):
        """License dashboard returns the flat streamed JSON contract."""
        stats = {
            "total_packages": 1,
            "categories": {"permissive": {"count": 1, "pct": 100.0}},
        }
        rows = [
            {
                "category": "permissive",
                "purl": "pkg:maven/com.example/foo@1.0",
                "project_name": "foo",
                "version_name": "1.0",
                "spdx_id": "Apache-2.0",
                "license_name": "Apache 2.0",
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=_mock_service(stats, rows),
        ):
            response = client.get("/reports/license-dashboard?format=json")

        assert response.status_code == 200
        data = response.get_json()
        assert data["report_type"] == "license-dashboard"
        assert data["stats"]["total_packages"] == 1
        assert "permissive" in data["stats"]["categories"]
        assert data["data"] == rows
        # Total result size is exposed to API consumers via the header.
        assert response.headers.get("X-Total-Count") == "1"

    def test_returns_excel_when_requested(self, client):
        """License dashboard returns Excel when format=excel."""
        stats = {
            "total_packages": 1,
            "categories": {"unknown": {"count": 1, "pct": 100.0}},
        }
        rows = [
            {
                "category": "unknown",
                "purl": "pkg:maven/com.example/unk@1.0",
                "project_name": "unk",
                "version_name": "1.0",
                "spdx_id": "",
                "license_name": "",
            },
        ]

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=_mock_service(stats, rows),
        ):
            response = client.get("/reports/license-dashboard?format=excel")

        assert response.status_code == 200
        assert (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            in response.content_type
        )
        assert "license_dashboard.xlsx" in response.headers.get("Content-Disposition", "")

    def test_internal_only_filter(self, client):
        """internal_only parameter is passed through to the stats query."""
        stats = {"total_packages": 0, "categories": {}}
        mock_service = _mock_service(stats, [])

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=mock_service,
        ):
            client.get("/reports/license-dashboard?internal_only=true")

        mock_service.get_license_risk_stats.assert_called_once_with(internal_only=True)

    def test_empty_data_shows_no_packages_message(self, client):
        """Empty dashboard shows appropriate message."""
        stats = {
            "total_packages": 0,
            "categories": {
                "permissive": {"count": 0, "pct": 0.0},
                "weak_copyleft": {"count": 0, "pct": 0.0},
                "strong_copyleft": {"count": 0, "pct": 0.0},
                "proprietary": {"count": 0, "pct": 0.0},
                "unknown": {"count": 0, "pct": 0.0},
            },
        }

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=_mock_service(stats, []),
        ):
            response = client.get("/reports/license-dashboard")

        assert response.status_code == 200
        assert b"No packages found" in response.data

    def test_html_sample_truncation_note(self, client):
        """When a category has more packages than the sample cap, a note shows."""
        stats = {
            "total_packages": 250,
            "categories": {"permissive": {"count": 250, "pct": 100.0}},
        }
        rows = [
            {
                "category": "permissive",
                "purl": f"pkg:maven/com.example/p{i}@1.0",
                "project_name": f"p{i}",
                "version_name": "1.0",
                "spdx_id": "MIT",
                "license_name": "MIT License",
            }
            for i in range(250)
        ]

        with patch(
            "sbom_graph_api.routes.reports.compliance.get_falkordb_service",
            return_value=_mock_service(stats, rows),
        ):
            response = client.get("/reports/license-dashboard")

        assert response.status_code == 200
        html = response.data.decode("utf-8")
        # Exact count from stats, but only the capped sample is rendered.
        assert "Showing 100 of 250 packages" in html
