"""Offline test support: a synthetic scenario and a boto3 stand-in."""

from .fake_aws import FakeClient, FakePool, FixtureCollector  # noqa: F401
from .scenario import build_fixtures  # noqa: F401

__all__ = ["FakeClient", "FakePool", "FixtureCollector", "build_fixtures"]
