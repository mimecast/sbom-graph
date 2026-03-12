"""Unit tests for the Celery application configuration."""

from __future__ import annotations

import logging

from sbom_graph_enrichment.celery_app import _RedactSecretsFilter


class TestRedactSecretsFilter:
    """Tests for the log redaction filter."""

    def _make_record(
        self, msg: str, args: tuple | dict | None = None
    ) -> logging.LogRecord:
        record = logging.LogRecord(
            name="celery",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=msg,
            args=None,
            exc_info=None,
        )
        if args is not None:
            record.args = args
        return record

    def test_redacts_password_in_msg(self) -> None:
        f = _RedactSecretsFilter()
        record = self._make_record("Connected to redis://:s3cret@redis-host:6379/1")
        f.filter(record)
        assert "s3cret" not in record.msg
        assert "redis://:*****@redis-host:6379/1" in record.msg

    def test_redacts_rediss_scheme(self) -> None:
        f = _RedactSecretsFilter()
        record = self._make_record("Broker: rediss://:p@ssw0rd!@host:6380/2")
        f.filter(record)
        assert "p@ssw0rd!" not in record.msg
        assert "rediss://:*****@host:6380/2" in record.msg

    def test_no_password_unchanged(self) -> None:
        f = _RedactSecretsFilter()
        record = self._make_record("Connected to redis://redis-host:6379/1")
        f.filter(record)
        assert record.msg == "Connected to redis://redis-host:6379/1"

    def test_redacts_password_in_tuple_args(self) -> None:
        f = _RedactSecretsFilter()
        record = self._make_record("Trying %s", ("redis://:secret@host:6379",))
        f.filter(record)
        assert "secret" not in str(record.args)

    def test_redacts_password_in_dict_args(self) -> None:
        f = _RedactSecretsFilter()
        record = self._make_record(
            "%(url)s failed",
            {"url": "redis://:mypass@host:6379/0"},
        )
        f.filter(record)
        assert "mypass" not in str(record.args)

    def test_filter_always_returns_true(self) -> None:
        f = _RedactSecretsFilter()
        record = self._make_record("plain message")
        assert f.filter(record) is True
