"""
Tests for the OWASP LLM Top 10 Scanner.

Unit tests cover test case structure, heuristic evaluation logic, and report generation.
Integration tests (marked slow) require live API keys.
"""

import pytest
import sys
import os

# Ensure the scanner module can be imported from parent directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from llm_scanner import TestCase, evaluate_response, TEST_SUITE, OWASP_CATEGORIES
    SCANNER_IMPORTABLE = True
except ImportError:
    SCANNER_IMPORTABLE = False

pytestmark = pytest.mark.skipif(not SCANNER_IMPORTABLE, reason="llm_scanner not importable")


class TestTestSuiteIntegrity:
    """Validate that all test cases in TEST_SUITE are well-formed."""

    def test_test_suite_not_empty(self):
        assert len(TEST_SUITE) > 0, "TEST_SUITE must have at least one test case"

    def test_all_cases_have_required_fields(self):
        required = {"id", "name", "owasp_id", "payload", "indicators_of_vuln", "indicators_of_safe", "severity"}
        for tc in TEST_SUITE:
            missing = required - set(vars(tc).keys())
            assert not missing, f"Test case {tc.id} missing fields: {missing}"

    def test_all_owasp_ids_are_valid(self):
        valid_ids = {f"LLM{str(i).zfill(2)}" for i in range(1, 11)}
        for tc in TEST_SUITE:
            assert tc.owasp_id in valid_ids, f"{tc.id} has invalid OWASP ID: {tc.owasp_id}"

    def test_all_severities_are_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for tc in TEST_SUITE:
            assert tc.severity in valid, f"{tc.id} has invalid severity: {tc.severity}"

    def test_all_cases_have_nonempty_indicators(self):
        for tc in TEST_SUITE:
            assert len(tc.indicators_of_vuln) > 0 or len(tc.indicators_of_safe) > 0, \
                f"{tc.id} has no indicators — evaluation will always return UNKNOWN"

    def test_no_duplicate_test_ids(self):
        ids = [tc.id for tc in TEST_SUITE]
        assert len(ids) == len(set(ids)), f"Duplicate test IDs: {[i for i in ids if ids.count(i) > 1]}"

    def test_covers_prompt_injection(self):
        owasp_ids = [tc.owasp_id for tc in TEST_SUITE]
        assert "LLM01" in owasp_ids, "TEST_SUITE must include at least one LLM01 (Prompt Injection) test"

    def test_covers_sensitive_disclosure(self):
        owasp_ids = [tc.owasp_id for tc in TEST_SUITE]
        assert "LLM06" in owasp_ids, "TEST_SUITE must include at least one LLM06 (Sensitive Information Disclosure) test"


class TestEvaluateResponse:
    """Test the heuristic response evaluation function."""

    def test_detects_vulnerability_indicator(self):
        tc = TestCase(
            id="TEST-01", name="Test", owasp_id="LLM01", category="Prompt Injection",
            payload="...", expected_behavior="Refuse",
            indicators_of_vuln=["sure, here is", "of course"],
            indicators_of_safe=["I cannot", "I'm unable"],
            severity="HIGH",
        )
        result = evaluate_response("Sure, here is the code you asked for.", tc)
        assert result["status"] == "VULNERABLE"

    def test_detects_safe_indicator(self):
        tc = TestCase(
            id="TEST-02", name="Test", owasp_id="LLM06", category="Sensitive Disclosure",
            payload="...", expected_behavior="Refuse",
            indicators_of_vuln=["my system prompt is", "secret:"],
            indicators_of_safe=["I cannot share", "I don't have access"],
            severity="HIGH",
        )
        result = evaluate_response("I don't have access to any system prompt information.", tc)
        assert result["status"] == "SAFE"

    def test_unknown_when_no_indicators_match(self):
        tc = TestCase(
            id="TEST-03", name="Test", owasp_id="LLM01", category="Prompt Injection",
            payload="...", expected_behavior="Refuse",
            indicators_of_vuln=["very specific string xyz"],
            indicators_of_safe=["another very specific string abc"],
            severity="MEDIUM",
        )
        result = evaluate_response("Here is some generic response.", tc)
        assert result["status"] == "UNKNOWN"

    def test_case_insensitive_matching(self):
        tc = TestCase(
            id="TEST-04", name="Test", owasp_id="LLM01", category="Prompt Injection",
            payload="...", expected_behavior="Refuse",
            indicators_of_vuln=["SURE HERE IS"],
            indicators_of_safe=[],
            severity="HIGH",
        )
        result = evaluate_response("sure here is your answer", tc)
        assert result["status"] == "VULNERABLE"
