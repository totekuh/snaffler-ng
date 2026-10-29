"""End-to-end AD integration tests: discovery + scanning against real Samba DC."""

import os
from unittest.mock import MagicMock

import pytest

from tests.ad_env.conftest import _make_cfg, AD_CONFIG, AD_ENABLED

pytestmark = pytest.mark.skipif(not AD_ENABLED, reason="AD DC not available")


class TestDomainUserDiscoveryToRules:

    def test_discover_users_and_scan_content(self, ad_dc):
        from snaffler.discovery.ad import ADDiscovery
        from snaffler.classifiers.loader import build_domain_user_rule
        from snaffler.classifiers.evaluator import RuleEvaluator
        from snaffler.classifiers.rules import Triage
        from snaffler.analysis.file_scanner import FileScanner
        from tests.conftest import make_scanner_cfg

        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        users = ad.get_domain_users()

        assert len(users) >= 3
        assert "svc_sql" in users

        rule = build_domain_user_rule(users, domain=cfg.auth.domain)
        evaluator = RuleEvaluator(
            file_rules=[],
            content_rules=[rule],
            postmatch_rules=[],
        )
        scanner_cfg = make_scanner_cfg()
        accessor = MagicMock()
        accessor.read.return_value = b"[Database]\nRunAs=svc_sql\nPassword=secret"
        scanner = FileScanner(cfg=scanner_cfg, file_accessor=accessor, rule_evaluator=evaluator)

        result = scanner.scan_file("//DC01/data/config.ini", 100, 0.0)

        assert result is not None
        assert result.triage == Triage.RED
        assert result.rule_name == "DynamicDomainUsers"
        assert "svc_sql" in result.match

    def test_netbios_variant_matches(self, ad_dc):
        from snaffler.discovery.ad import ADDiscovery
        from snaffler.classifiers.loader import build_domain_user_rule
        from snaffler.classifiers.evaluator import RuleEvaluator
        from snaffler.analysis.file_scanner import FileScanner
        from tests.conftest import make_scanner_cfg

        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        users = ad.get_domain_users()
        rule = build_domain_user_rule(users, domain=cfg.auth.domain)

        evaluator = RuleEvaluator(file_rules=[], content_rules=[rule], postmatch_rules=[])
        accessor = MagicMock()
        accessor.read.return_value = b"service_account=TESTLAB\\svc_sql"
        scanner = FileScanner(
            cfg=make_scanner_cfg(), file_accessor=accessor, rule_evaluator=evaluator,
        )

        result = scanner.scan_file("//DC01/data/app.config", 50, 0.0)
        assert result is not None
        assert "svc_sql" in result.match.lower()


class TestComputerDiscovery:

    def test_discover_computers_count(self, ad_dc):
        from snaffler.discovery.ad import ADDiscovery

        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        computers = ad.get_domain_computers()

        assert len(computers) == 4
        hostnames = {c.split(".")[0] for c in computers}
        assert "FILESERVER1" in hostnames
        assert "DBSERVER1" in hostnames
        assert "WEBSERVER1" in hostnames
        assert "DC01" in hostnames
        assert "DISABLED-PC" not in hostnames

    def test_all_fqdn(self, ad_dc):
        from snaffler.discovery.ad import ADDiscovery

        cfg = _make_cfg()
        ad = ADDiscovery(cfg)
        computers = ad.get_domain_computers()

        for c in computers:
            assert c.endswith(".TESTLAB.LOCAL"), f"{c} is not FQDN"


class TestShareFilters:

    def test_include_filter(self, ad_dc):
        from snaffler.discovery.shares import share_matches_filter

        assert share_matches_filter("data", include=["data"], exclude=[]) is True
        assert share_matches_filter("finance", include=["data"], exclude=[]) is False
        assert share_matches_filter("it", include=["data"], exclude=[]) is False

    def test_exclude_filter(self, ad_dc):
        from snaffler.discovery.shares import share_matches_filter

        assert share_matches_filter("data", include=[], exclude=["finance"]) is True
        assert share_matches_filter("finance", include=[], exclude=["finance"]) is False
        assert share_matches_filter("it", include=[], exclude=["finance"]) is True

    def test_glob_pattern(self, ad_dc):
        from snaffler.discovery.shares import share_matches_filter

        assert share_matches_filter("data", include=["d*"], exclude=[]) is True
        assert share_matches_filter("finance", include=["d*"], exclude=[]) is False

    def test_combined_include_exclude(self, ad_dc):
        from snaffler.discovery.shares import share_matches_filter

        assert share_matches_filter("data", include=["*"], exclude=["finance"]) is True
        assert share_matches_filter("finance", include=["*"], exclude=["finance"]) is False
