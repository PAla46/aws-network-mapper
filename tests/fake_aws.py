"""Fixture-driven collector used by the self-test (and ``--offline-demo``)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_network_mapper.discovery import Collector


class FixtureCollector(Collector):
    """A :class:`Collector` that serves canned ``describe_*`` payloads."""

    def __init__(self, fixtures: Dict[str, Dict[str, Any]], regions: Optional[List[str]] = None, **kwargs):
        super().__init__(regions=list(fixtures.keys()), **kwargs)
        self.fixtures = fixtures
        self.account_id = "111122223333"
        self.partition = "aws"
        self.calls: List[str] = []

    def start(self) -> None:  # no boto3 session needed
        self._started = True
        return None

    def _call(self, region: str, key: str, fn: Any) -> Any:
        self.calls.append(f"{region}/{key}")
        payload = self.fixtures.get(region, {})
        if key not in payload:
            raise KeyError(f"fixture missing {region}/{key}")
        # honour the cache so the offline rebuild path is exercised too
        self.cache.save(region, key, payload[key])
        return payload[key]


class FakePool:
    def __init__(self, region: str):
        self.region = region

    def get(self, service: str) -> Any:
        return FakeClient(self.region, service)


class FakeClient:
    def __init__(self, region: str, service: str):
        self.region = region
        self.service = service

    def __getattr__(self, op: str):
        def call(**kwargs):
            raise RuntimeError(f"unexpected live call {self.service}.{op}")

        return call
