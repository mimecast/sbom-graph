"""Tests for export modules."""

from io import BytesIO
from unittest.mock import MagicMock

from sbom_graph_api.exports.excel import (
    auto_adjust_column_widths,
    create_all_projects_excel,
    create_self_dependency_report_excel,
    create_snapshot_report_excel,
    create_version_dependencies_excel,
    style_header_row,
)


class TestStyleHeaderRow:
    """Tests for style_header_row function."""

    def test_styles_header_cells(self):
        """Test header row styling is applied."""
        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        ws.cell(row=1, column=1, value="Header 1")
        ws.cell(row=1, column=2, value="Header 2")

        style_header_row(ws, 2)

        # Check that styling was applied (cell has fill)
        assert ws.cell(row=1, column=1).fill.start_color.rgb is not None


class TestAutoAdjustColumnWidths:
    """Tests for auto_adjust_column_widths function."""

    def test_adjusts_column_width(self):
        """Test column width adjustment."""
        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        ws.cell(row=1, column=1, value="Short")
        ws.cell(row=2, column=1, value="A much longer value here")

        auto_adjust_column_widths(ws)

        # Width should be adjusted (greater than default)
        assert ws.column_dimensions["A"].width > 0


class TestCreateVersionDependenciesExcel:
    """Tests for create_version_dependencies_excel function."""

    # Positive tests

    def test_returns_bytesio_buffer(self):
        """Test returns BytesIO buffer."""
        mock_service = MagicMock()
        mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
        mock_service.get_direct_dependants.return_value = []

        result = create_version_dependencies_excel("test-project", mock_service)

        assert isinstance(result, BytesIO)
        assert result.tell() == 0  # Position should be at start

    def test_creates_valid_excel_file(self):
        """Test creates a valid Excel file."""
        from openpyxl import load_workbook

        mock_service = MagicMock()
        mock_service.get_all_versions_of_project.return_value = ["1.0.0", "2.0.0"]
        mock_service.get_direct_dependants.return_value = [
            {
                "dependant_project": "dep-a",
                "dependant_version": "1.0.0",
                "target_project": "test",
                "target_version": "1.0.0",
            }
        ]

        result = create_version_dependencies_excel("test", mock_service)

        # Load and verify the workbook
        wb = load_workbook(result)
        assert "Version Dependencies" in wb.sheetnames
        assert "Summary" in wb.sheetnames

    def test_includes_dependant_data(self):
        """Test includes dependant data in Excel."""
        from openpyxl import load_workbook

        mock_service = MagicMock()
        mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
        mock_service.get_direct_dependants.return_value = [
            {
                "dependant_project": "dependant-project",
                "dependant_version": "2.0.0",
                "target_project": "test",
                "target_version": "1.0.0",
            }
        ]

        result = create_version_dependencies_excel("test", mock_service)
        wb = load_workbook(result)
        ws = wb["Version Dependencies"]

        # Check data is present (headers + 1 data row)
        assert ws.max_row >= 2

    # Negative tests

    def test_handles_no_dependants(self):
        """Test handles project with no dependants."""
        mock_service = MagicMock()
        mock_service.get_all_versions_of_project.return_value = ["1.0.0"]
        mock_service.get_direct_dependants.return_value = []

        result = create_version_dependencies_excel("isolated", mock_service)

        assert isinstance(result, BytesIO)


class TestCreateAllProjectsExcel:
    """Tests for create_all_projects_excel function."""

    # Positive tests

    def test_returns_bytesio_buffer(self):
        """Test returns BytesIO buffer."""
        mock_service = MagicMock()
        mock_service.get_all_projects.return_value = []

        result = create_all_projects_excel(mock_service)

        assert isinstance(result, BytesIO)

    def test_includes_all_projects_data(self):
        """Test includes all projects in Excel."""
        from openpyxl import load_workbook

        mock_service = MagicMock()
        mock_service.get_all_projects.return_value = [
            {"project_name": "project-a", "version": "1.0.0"},
            {"project_name": "project-b", "version": "2.0.0"},
        ]

        result = create_all_projects_excel(mock_service, limit=100)
        wb = load_workbook(result)
        ws = wb["All Projects"]

        # Headers + 2 data rows
        assert ws.max_row == 3

    def test_respects_limit_parameter(self):
        """Test respects limit parameter."""
        mock_service = MagicMock()
        mock_service.get_all_projects.return_value = []

        create_all_projects_excel(mock_service, limit=500)

        mock_service.get_all_projects.assert_called_once_with(500, False)

    def test_internal_only_filter(self):
        """Test internal_only filter changes sheet title and summary."""
        from openpyxl import load_workbook

        mock_service = MagicMock()
        mock_service.get_all_projects.return_value = [
            {"project_name": "acme_corp-lib", "version": "1.0.0"},
        ]

        result = create_all_projects_excel(mock_service, limit=100, internal_only=True)

        # Verify internal_only was passed
        mock_service.get_all_projects.assert_called_once_with(100, True)

        # Check workbook structure
        wb = load_workbook(result)
        assert "Internal Projects" in wb.sheetnames

        # Check summary includes filter info
        summary = wb["Summary"]
        assert summary.cell(row=3, column=1).value == "Filter"
        assert summary.cell(row=3, column=2).value == "Internal Only"

    # Negative tests

    def test_handles_empty_database(self):
        """Test handles empty database."""
        mock_service = MagicMock()
        mock_service.get_all_projects.return_value = []

        result = create_all_projects_excel(mock_service)

        assert isinstance(result, BytesIO)


class TestCreateSnapshotReportExcel:
    """Tests for create_snapshot_report_excel function."""

    # Positive tests

    def test_returns_bytesio_buffer(self):
        """Test returns BytesIO buffer."""
        result = create_snapshot_report_excel([])
        assert isinstance(result, BytesIO)

    def test_includes_snapshot_data(self):
        """Test includes SNAPSHOT data in Excel."""
        from openpyxl import load_workbook

        data = [
            {
                "application": "app-a",
                "app_version": "1.0.0",
                "dependency": "lib-a",
                "dep_version": "1.0.0-SNAPSHOT",
            },
            {
                "application": "app-b",
                "app_version": "2.0.0",
                "dependency": "lib-b",
                "dep_version": "2.0.0-SNAPSHOT",
            },
        ]

        result = create_snapshot_report_excel(data)
        wb = load_workbook(result)
        ws = wb["SNAPSHOT Dependencies"]

        # Headers + 2 data rows
        assert ws.max_row == 3

    def test_includes_summary_sheet(self):
        """Test includes summary sheet."""
        from openpyxl import load_workbook

        data = [
            {
                "application": "app-a",
                "app_version": "1.0.0",
                "dependency": "lib-a",
                "dep_version": "1.0.0-SNAPSHOT",
            },
        ]

        result = create_snapshot_report_excel(data)
        wb = load_workbook(result)

        assert "Summary" in wb.sheetnames

    # Negative tests

    def test_handles_empty_data(self):
        """Test handles empty data list."""
        result = create_snapshot_report_excel([])
        assert isinstance(result, BytesIO)


class TestCreateSelfDependencyReportExcel:
    """Tests for create_self_dependency_report_excel function."""

    # Positive tests

    def test_returns_bytesio_buffer(self):
        """Test returns BytesIO buffer."""
        result = create_self_dependency_report_excel([])
        assert isinstance(result, BytesIO)

    def test_includes_self_dependency_data(self):
        """Test includes self-dependency data in Excel."""
        from openpyxl import load_workbook

        data = [
            {
                "project_name": "self-ref",
                "version": "1.0.0",
                "relationship_type": "DEPENDS_ON",
            },
        ]

        result = create_self_dependency_report_excel(data)
        wb = load_workbook(result)
        ws = wb["Self Dependencies"]

        # Headers + 1 data row
        assert ws.max_row == 2

    def test_includes_summary_statistics(self):
        """Test includes summary statistics."""
        from openpyxl import load_workbook

        data = [
            {"project_name": "a", "version": "1.0.0", "relationship_type": "DEPENDS_ON"},
            {"project_name": "a", "version": "2.0.0", "relationship_type": "DEPENDS_ON"},
            {"project_name": "b", "version": "1.0.0", "relationship_type": "DEPENDS_ON"},
        ]

        result = create_self_dependency_report_excel(data)
        wb = load_workbook(result)
        summary = wb["Summary"]

        # Check summary values
        assert summary.cell(row=1, column=2).value == 3  # Total self dependencies
        assert summary.cell(row=2, column=2).value == 2  # Affected projects (a and b)

    # Negative tests

    def test_handles_empty_data(self):
        """Test handles empty data list."""
        result = create_self_dependency_report_excel([])
        assert isinstance(result, BytesIO)
