"""Tests for input validation and sanitization utilities."""

import pytest
from flask import Flask

from sbom_graph_api.utils.validation import (
    build_url_params,
    build_url_with_params,
    is_safe_redirect_url,
    get_safe_redirect_url,
    validate_boolean,
    validate_css_dimension,
    validate_format,
    validate_layout,
    validate_limit,
    validate_max_depth,
    validate_project_group,
    validate_project_name,
    validate_purl,
    validate_version_name,
)


@pytest.fixture
def app():
    """Minimal Flask app for request context tests."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test"

    @app.route("/")
    def index():
        return "ok"

    return app


class TestValidateCssDimension:
    """Tests for validate_css_dimension function."""

    # Positive tests

    def test_valid_pixel_value(self):
        assert validate_css_dimension("800px") == "800px"

    def test_valid_percentage(self):
        assert validate_css_dimension("100%") == "100%"

    def test_valid_em(self):
        assert validate_css_dimension("50em") == "50em"

    def test_valid_rem(self):
        assert validate_css_dimension("16rem") == "16rem"

    def test_valid_vh(self):
        assert validate_css_dimension("100vh") == "100vh"

    def test_valid_vw(self):
        assert validate_css_dimension("100vw") == "100vw"

    def test_valid_pt(self):
        assert validate_css_dimension("12pt") == "12pt"

    def test_auto(self):
        assert validate_css_dimension("auto") == "auto"

    def test_auto_case_insensitive(self):
        assert validate_css_dimension("AUTO") == "auto"

    def test_number_without_unit(self):
        assert validate_css_dimension("800") == "800"

    def test_custom_default(self):
        assert validate_css_dimension("", default="100%") == "100%"

    def test_zero_value(self):
        assert validate_css_dimension("0px") == "0px"

    def test_whitespace_stripped(self):
        assert validate_css_dimension("  800px  ") == "800px"

    # Negative tests

    def test_empty_string_returns_default(self):
        assert validate_css_dimension("") == "800px"

    def test_none_returns_default(self):
        assert validate_css_dimension(None) == "800px"

    def test_invalid_unit_returns_default(self):
        assert validate_css_dimension("100xyz") == "800px"

    def test_negative_value_returns_default(self):
        assert validate_css_dimension("-100px") == "800px"

    def test_exceeds_max_returns_default(self):
        assert validate_css_dimension("10001px") == "800px"

    def test_boundary_max_valid(self):
        assert validate_css_dimension("10000px") == "10000px"

    def test_script_injection_returns_default(self):
        assert validate_css_dimension("<script>alert(1)</script>") == "800px"

    def test_expression_returns_default(self):
        assert validate_css_dimension("expression(alert(1))") == "800px"


class TestValidateMaxDepth:
    """Tests for validate_max_depth function."""

    # Positive tests

    def test_valid_value(self):
        assert validate_max_depth(10) == 10

    def test_minimum_value(self):
        assert validate_max_depth(1) == 1

    def test_maximum_value(self):
        assert validate_max_depth(100) == 100

    def test_string_numeric_value(self):
        assert validate_max_depth("50") == 50

    # Negative tests

    def test_none_returns_default(self):
        assert validate_max_depth(None) is None

    def test_none_with_custom_default(self):
        assert validate_max_depth(None, default=10) == 10

    def test_zero_returns_default(self):
        assert validate_max_depth(0) is None

    def test_negative_returns_default(self):
        assert validate_max_depth(-5) is None

    def test_exceeds_max_returns_default(self):
        assert validate_max_depth(101) is None

    def test_non_numeric_string_returns_default(self):
        assert validate_max_depth("abc") is None

    def test_float_string_returns_default(self):
        assert validate_max_depth("1.5") is None


class TestValidateLimit:
    """Tests for validate_limit function."""

    # Positive tests

    def test_valid_value(self):
        assert validate_limit(500) == 500

    def test_minimum_value(self):
        assert validate_limit(1) == 1

    def test_maximum_value(self):
        assert validate_limit(100000) == 100000

    def test_string_numeric(self):
        assert validate_limit("5000") == 5000

    # Negative tests

    def test_none_returns_default(self):
        assert validate_limit(None) == 10000

    def test_none_with_custom_default(self):
        assert validate_limit(None, default=50) == 50

    def test_zero_returns_default(self):
        assert validate_limit(0) == 10000

    def test_negative_returns_default(self):
        assert validate_limit(-1) == 10000

    def test_exceeds_max_returns_default(self):
        assert validate_limit(100001) == 10000

    def test_non_numeric_returns_default(self):
        assert validate_limit("abc") == 10000


class TestValidateFormat:
    """Tests for validate_format function."""

    # Positive tests

    def test_html(self):
        assert validate_format("html") == "html"

    def test_excel(self):
        assert validate_format("excel") == "excel"

    def test_json(self):
        assert validate_format("json") == "json"

    def test_case_insensitive(self):
        assert validate_format("HTML") == "html"

    def test_with_whitespace(self):
        assert validate_format("  json  ") == "json"

    # Negative tests

    def test_none_returns_default(self):
        assert validate_format(None) == "html"

    def test_empty_returns_default(self):
        assert validate_format("") == "html"

    def test_invalid_format_returns_default(self):
        assert validate_format("csv") == "html"

    def test_custom_default(self):
        assert validate_format("invalid", default="json") == "json"


class TestValidateLayout:
    """Tests for validate_layout function."""

    # Positive tests

    def test_spring(self):
        assert validate_layout("spring") == "spring"

    def test_radial(self):
        assert validate_layout("radial") == "radial"

    def test_shell(self):
        assert validate_layout("shell") == "shell"

    def test_bfs(self):
        assert validate_layout("bfs") == "bfs"

    def test_circular(self):
        assert validate_layout("circular") == "circular"

    def test_case_insensitive(self):
        assert validate_layout("SPRING") == "spring"

    # Negative tests

    def test_none_returns_default(self):
        assert validate_layout(None) == "spring"

    def test_empty_returns_default(self):
        assert validate_layout("") == "spring"

    def test_invalid_returns_default(self):
        assert validate_layout("grid") == "spring"

    def test_custom_default(self):
        assert validate_layout(None, default="radial") == "radial"


class TestValidateBoolean:
    """Tests for validate_boolean function."""

    # Positive tests

    def test_true_string(self):
        assert validate_boolean("true") is True

    def test_true_uppercase(self):
        assert validate_boolean("TRUE") is True

    def test_true_mixed_case(self):
        assert validate_boolean("True") is True

    def test_true_with_whitespace(self):
        assert validate_boolean("  true  ") is True

    # Negative tests

    def test_false_string(self):
        assert validate_boolean("false") is False

    def test_none_returns_default(self):
        assert validate_boolean(None) is False

    def test_empty_returns_default(self):
        assert validate_boolean("") is False

    def test_custom_default_true(self):
        assert validate_boolean(None, default=True) is True

    def test_arbitrary_string_returns_false(self):
        assert validate_boolean("yes") is False

    def test_one_returns_false(self):
        assert validate_boolean("1") is False


class TestValidateProjectName:
    """Tests for validate_project_name function."""

    # Positive tests

    def test_simple_name(self):
        assert validate_project_name("my-project") == "my-project"

    def test_with_dots(self):
        assert validate_project_name("com.example.lib") == "com.example.lib"

    def test_with_underscores(self):
        assert validate_project_name("my_project") == "my_project"

    def test_alphanumeric(self):
        assert validate_project_name("project123") == "project123"

    def test_single_char(self):
        assert validate_project_name("a") == "a"

    def test_whitespace_stripped(self):
        assert validate_project_name("  my-project  ") == "my-project"

    # Negative / security tests

    def test_empty_returns_none(self):
        assert validate_project_name("") is None

    def test_none_returns_none(self):
        assert validate_project_name(None) is None

    def test_path_traversal_rejected(self):
        assert validate_project_name("../../../etc/passwd") is None

    def test_starts_with_dot_rejected(self):
        assert validate_project_name(".hidden") is None

    def test_starts_with_hyphen_rejected(self):
        assert validate_project_name("-project") is None

    def test_slash_rejected(self):
        assert validate_project_name("my/project") is None

    def test_space_rejected(self):
        assert validate_project_name("my project") is None

    def test_exceeds_max_length(self):
        assert validate_project_name("a" * 257) is None

    def test_at_max_length(self):
        assert validate_project_name("a" * 256) == "a" * 256

    def test_special_chars_rejected(self):
        assert validate_project_name("project<script>") is None

    def test_semicolon_rejected(self):
        assert validate_project_name("project;drop") is None


class TestValidateVersionName:
    """Tests for validate_version_name function."""

    # Positive tests

    def test_semver(self):
        assert validate_version_name("1.0.0") == "1.0.0"

    def test_snapshot(self):
        assert validate_version_name("2.0.0-SNAPSHOT") == "2.0.0-SNAPSHOT"

    def test_prefix_version(self):
        assert validate_version_name("v1.2.3") == "v1.2.3"

    def test_build_version(self):
        assert validate_version_name("build-123") == "build-123"

    def test_plus_sign(self):
        assert validate_version_name("1.0.0+build.1") == "1.0.0+build.1"

    def test_latest(self):
        assert validate_version_name("latest") == "latest"

    # Negative / security tests

    def test_empty_returns_none(self):
        assert validate_version_name("") is None

    def test_none_returns_none(self):
        assert validate_version_name(None) is None

    def test_path_traversal(self):
        assert validate_version_name("../1.0.0") is None

    def test_slash_rejected(self):
        assert validate_version_name("1.0.0/evil") is None

    def test_exceeds_max_length(self):
        assert validate_version_name("a" * 129) is None

    def test_at_max_length(self):
        assert validate_version_name("a" * 128) == "a" * 128

    def test_starts_with_dot_rejected(self):
        assert validate_version_name(".1.0") is None

    def test_space_rejected(self):
        assert validate_version_name("1.0 beta") is None


class TestIsSafeRedirectUrl:
    """Tests for is_safe_redirect_url function."""

    # Positive tests

    def test_simple_path(self):
        assert is_safe_redirect_url("/dashboard") is True

    def test_nested_path(self):
        assert is_safe_redirect_url("/reports/projects") is True

    def test_path_with_query(self):
        assert is_safe_redirect_url("/search?q=test") is True

    # Negative / security tests

    def test_none(self):
        assert is_safe_redirect_url(None) is False

    def test_empty(self):
        assert is_safe_redirect_url("") is False

    def test_protocol_relative(self):
        """Reject //evil.com (protocol-relative URL, open redirect)."""
        assert is_safe_redirect_url("//evil.com") is False

    def test_backslash_variant(self):
        assert is_safe_redirect_url("/\\evil.com") is False

    def test_absolute_url(self):
        assert is_safe_redirect_url("https://evil.com") is False

    def test_embedded_credentials(self):
        assert is_safe_redirect_url("/redirect@evil.com") is False

    def test_crlf_injection(self):
        assert is_safe_redirect_url("/path\r\nHeader: injected") is False

    def test_newline_injection(self):
        assert is_safe_redirect_url("/path\nevil") is False

    def test_tab_injection(self):
        assert is_safe_redirect_url("/path\tevil") is False

    def test_null_byte(self):
        assert is_safe_redirect_url("/path%00evil") is False

    def test_encoded_newline(self):
        assert is_safe_redirect_url("/path%0aevil") is False

    def test_encoded_carriage_return(self):
        assert is_safe_redirect_url("/path%0devil") is False

    def test_backslash_in_path(self):
        assert is_safe_redirect_url("/path\\evil") is False

    def test_no_leading_slash(self):
        assert is_safe_redirect_url("relative/path") is False


class TestGetSafeRedirectUrl:
    """Tests for get_safe_redirect_url function."""

    def test_valid_next_url(self, app):
        """Returns the next param when it passes validation."""
        with app.test_request_context("/?next=/dashboard"):
            result = get_safe_redirect_url("index")
            assert result == "/dashboard"

    def test_unsafe_next_url_falls_back(self, app):
        """Falls back to default endpoint when next is unsafe."""
        with app.test_request_context("/?next=//evil.com"):
            result = get_safe_redirect_url("index")
            assert result == "/"

    def test_no_next_param(self, app):
        """Falls back to default endpoint when next is missing."""
        with app.test_request_context("/"):
            result = get_safe_redirect_url("index")
            assert result == "/"

    def test_empty_next_param(self, app):
        """Falls back to default endpoint when next is empty."""
        with app.test_request_context("/?next="):
            result = get_safe_redirect_url("index")
            assert result == "/"


class TestBuildUrlParams:
    """Tests for build_url_params function."""

    def test_no_params(self):
        assert build_url_params() == ""

    def test_format_only(self):
        assert build_url_params(format="excel") == "format=excel"

    def test_internal_only(self):
        assert build_url_params(internal_only=True) == "internal_only=true"

    def test_internal_only_false_omitted(self):
        assert build_url_params(internal_only=False) == ""

    def test_longest_only_false_included(self):
        result = build_url_params(longest_only=False)
        assert "longest_only=false" in result

    def test_longest_only_true_omitted(self):
        """Default longest_only=True is omitted from params."""
        assert build_url_params(longest_only=True) == ""

    def test_latest_only_true(self):
        assert build_url_params(latest_only=True) == "latest_only=true"

    def test_limit_and_depth(self):
        result = build_url_params(limit=50, max_depth=10)
        assert "limit=50" in result
        assert "max_depth=10" in result

    def test_all_params(self):
        result = build_url_params(
            format="json",
            limit=100,
            max_depth=5,
            internal_only=True,
            longest_only=False,
            latest_only=True,
        )
        assert "format=json" in result
        assert "limit=100" in result
        assert "max_depth=5" in result
        assert "internal_only=true" in result
        assert "longest_only=false" in result
        assert "latest_only=true" in result


class TestBuildUrlWithParams:
    """Tests for build_url_with_params function."""

    def test_no_params(self):
        assert build_url_with_params("/reports/projects") == "/reports/projects"

    def test_with_format(self):
        result = build_url_with_params("/reports/projects", format="excel")
        assert result == "/reports/projects?format=excel"

    def test_with_multiple_params(self):
        result = build_url_with_params(
            "/reports/projects",
            format="json",
            internal_only=True,
        )
        assert result.startswith("/reports/projects?")
        assert "format=json" in result
        assert "internal_only=true" in result


class TestValidatePurl:
    """Tests for validate_purl function."""

    def test_maven_purl(self):
        assert validate_purl("pkg:maven/com.example/foo@1.0.0") == "pkg:maven/com.example/foo@1.0.0"

    def test_npm_purl(self):
        assert validate_purl("pkg:npm/lodash@4.17.21") == "pkg:npm/lodash@4.17.21"

    def test_pypi_purl(self):
        assert validate_purl("pkg:pypi/requests@2.28.0") == "pkg:pypi/requests@2.28.0"

    def test_purl_without_version(self):
        assert validate_purl("pkg:maven/com.example/foo") == "pkg:maven/com.example/foo"

    def test_purl_with_namespace(self):
        assert validate_purl("pkg:npm/%40scope/package@1.0.0") == "pkg:npm/%40scope/package@1.0.0"

    def test_whitespace_trimmed(self):
        assert validate_purl("  pkg:pypi/requests@2.28.0  ") == "pkg:pypi/requests@2.28.0"

    def test_empty_returns_none(self):
        assert validate_purl("") is None

    def test_none_returns_none(self):
        assert validate_purl(None) is None

    def test_no_pkg_prefix(self):
        assert validate_purl("maven/com.example/foo@1.0.0") is None

    def test_bare_string(self):
        assert validate_purl("not-a-purl") is None

    def test_too_long(self):
        assert validate_purl("pkg:maven/" + "a" * 1020) is None

    def test_at_max_length(self):
        name = "a" * (1024 - len("pkg:maven/"))
        purl = "pkg:maven/" + name
        assert validate_purl(purl) == purl

    def test_missing_type(self):
        assert validate_purl("pkg:/name@1.0") is None

    def test_script_injection(self):
        assert validate_purl("<script>alert(1)</script>") is None

    def test_embedded_newline_rejected(self):
        assert validate_purl("pkg:maven/com.example/foo\nevil") is None

    def test_trailing_newline_trimmed(self):
        assert validate_purl("pkg:maven/com.example/foo\n") == "pkg:maven/com.example/foo"


class TestValidateProjectGroup:
    """Tests for validate_project_group function."""

    def test_dotted_group(self):
        assert validate_project_group("com.example") == "com.example"

    def test_multi_dotted_group(self):
        assert validate_project_group("org.acme.internal") == "org.acme.internal"

    def test_simple_group(self):
        assert validate_project_group("mygroup") == "mygroup"

    def test_hyphenated_group(self):
        assert validate_project_group("my-group") == "my-group"

    def test_underscore_group(self):
        assert validate_project_group("my_group") == "my_group"

    def test_whitespace_trimmed(self):
        assert validate_project_group("  com.example  ") == "com.example"

    def test_none_returns_none(self):
        assert validate_project_group(None) is None

    def test_empty_returns_none(self):
        assert validate_project_group("") is None

    def test_too_long(self):
        assert validate_project_group("a" * 257) is None

    def test_at_max_length(self):
        assert validate_project_group("a" * 256) == "a" * 256

    def test_starts_with_dot_rejected(self):
        assert validate_project_group(".hidden") is None

    def test_starts_with_hyphen_rejected(self):
        assert validate_project_group("-group") is None

    def test_slash_rejected(self):
        assert validate_project_group("com/example") is None

    def test_space_in_middle_rejected(self):
        assert validate_project_group("com example") is None

    def test_special_chars_rejected(self):
        assert validate_project_group("com.example<script>") is None

    def test_semicolon_rejected(self):
        assert validate_project_group("group;drop") is None
