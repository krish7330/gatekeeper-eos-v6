"""Tests for orchestrator output schemas: recon, scan, report."""

import json
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = PROJECT_ROOT / "schemas"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

RECON_SCHEMA = SCHEMA_DIR / "recon.schema.json"
SCAN_SCHEMA = SCHEMA_DIR / "scan.schema.json"
REPORT_SCHEMA = SCHEMA_DIR / "report.schema.json"


@pytest.fixture(scope="module")
def jsonschema_validator():
    """Import jsonschema lazily (optional dependency)."""
    pytest.importorskip("jsonschema", reason="jsonschema not installed")
    from jsonschema import Draft7Validator, ValidationError
    return Draft7Validator, ValidationError


@pytest.fixture
def recon_schema():
    return json.loads(RECON_SCHEMA.read_text())


@pytest.fixture
def scan_schema():
    return json.loads(SCAN_SCHEMA.read_text())


@pytest.fixture
def report_schema():
    return json.loads(REPORT_SCHEMA.read_text())


# ===========================================================================
# Schema file existence & validity
# ===========================================================================


class TestSchemaExistence:
    """All three schema files must exist and be valid JSON."""

    def test_recon_schema_exists(self):
        assert RECON_SCHEMA.exists(), f"Missing: {RECON_SCHEMA}"

    def test_scan_schema_exists(self):
        assert SCAN_SCHEMA.exists(), f"Missing: {SCAN_SCHEMA}"

    def test_report_schema_exists(self):
        assert REPORT_SCHEMA.exists(), f"Missing: {REPORT_SCHEMA}"

    def test_schemas_are_valid_json(self):
        for path in [RECON_SCHEMA, SCAN_SCHEMA, REPORT_SCHEMA]:
            raw = path.read_text()
            try:
                json.loads(raw)
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON in {path.name}: {e}")

    def test_schemas_are_draft07(self):
        """Every schema must declare $schema as draft-07."""
        for path in [RECON_SCHEMA, SCAN_SCHEMA, REPORT_SCHEMA]:
            schema = json.loads(path.read_text())
            assert schema.get("$schema") == "http://json-schema.org/draft-07/schema#", (
                f"{path.name} uses wrong $schema version"
            )

    def test_schemas_have_consistent_ids(self):
        """All schemas should have IDs under the same base URL."""
        base = "https://github.com/krishanumala/gatekeeper-eos-v6/schemas/"
        expected = {
            RECON_SCHEMA: f"{base}recon.schema.json",
            SCAN_SCHEMA: f"{base}scan.schema.json",
            REPORT_SCHEMA: f"{base}report.schema.json",
        }
        for path, expected_id in expected.items():
            schema = json.loads(path.read_text())
            assert schema.get("$id") == expected_id, (
                f"{path.name}: expected $id {expected_id}, got {schema.get('$id')}"
            )


# ===========================================================================
# Schema structure
# ===========================================================================


class TestSchemaStructure:
    """Schemas must have required structural properties."""

    def test_all_have_title_and_description(self):
        for path in [RECON_SCHEMA, SCAN_SCHEMA, REPORT_SCHEMA]:
            schema = json.loads(path.read_text())
            assert "title" in schema, f"{path.name} missing title"
            assert "description" in schema, f"{path.name} missing description"
            assert "type" in schema, f"{path.name} missing type"
            assert schema["type"] == "object"

    def test_all_have_required_fields(self):
        for path in [RECON_SCHEMA, SCAN_SCHEMA, REPORT_SCHEMA]:
            schema = json.loads(path.read_text())
            assert "required" in schema, f"{path.name} missing required array"
            assert isinstance(schema["required"], list)
            assert len(schema["required"]) >= 3

    def test_all_reject_additional_properties(self):
        for path in [RECON_SCHEMA, SCAN_SCHEMA, REPORT_SCHEMA]:
            schema = json.loads(path.read_text())
            assert schema.get("additionalProperties") is False, (
                f"{path.name} must set additionalProperties: false"
            )

    def test_all_have_session_id_pattern(self):
        """Schemas should enforce a session_id pattern."""
        for path in [RECON_SCHEMA, SCAN_SCHEMA, REPORT_SCHEMA]:
            schema = json.loads(path.read_text())
            session_id = schema.get("properties", {}).get("session_id", {})
            assert "pattern" in session_id, f"{path.name} missing session_id pattern"
            assert session_id["type"] == "string"

    def test_all_have_completed_at(self):
        """Every output must have a completed_at timestamp."""
        for path in [RECON_SCHEMA, SCAN_SCHEMA, REPORT_SCHEMA]:
            schema = json.loads(path.read_text())
            assert "completed_at" in schema.get("properties", {}), (
                f"{path.name} missing completed_at"
            )

    def test_all_have_drift_flagged(self):
        for path in [RECON_SCHEMA, SCAN_SCHEMA, REPORT_SCHEMA]:
            schema = json.loads(path.read_text())
            assert "drift_flagged" in schema.get("properties", {}), (
                f"{path.name} missing drift_flagged"
            )


# ===========================================================================
# Recon schema — validation
# ===========================================================================


class TestReconSchemaValidation:
    """Test recon.schema.json with valid and invalid data."""

    VALID_RECON = {
        "session_id": "recon-01",
        "plan_id": "PTO-001",
        "findings": [
            {
                "type": "dns",
                "asset": "example.com",
                "confidence": "High",
                "description": "Discovered DNS A record pointing to 10.0.0.10",
            }
        ],
        "summary": {"total_findings": 1, "high_confidence": 1},
        "completed_at": "2026-06-01T00:00:00Z",
    }

    def test_valid_passes(self, recon_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        errors = list(Draft7Validator(recon_schema).iter_errors(self.VALID_RECON))
        assert errors == [], f"Validation errors on valid data: {errors}"

    def test_missing_findings_fails(self, recon_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = {k: v for k, v in self.VALID_RECON.items() if k != "findings"}
        errors = list(Draft7Validator(recon_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_invalid_finding_type_fails(self, recon_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_RECON)
        data["findings"][0]["type"] = "invalid_type"
        errors = list(Draft7Validator(recon_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_invalid_session_id_pattern_fails(self, recon_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_RECON)
        data["session_id"] = "bad-session"
        errors = list(Draft7Validator(recon_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_additional_property_rejected(self, recon_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_RECON)
        data["extra_field"] = "should-not-exist"
        errors = list(Draft7Validator(recon_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_empty_findings_allowed(self, recon_schema, jsonschema_validator):
        """Empty findings array should be valid (no findings discovered)."""
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_RECON)
        data["findings"] = []
        data["summary"] = {"total_findings": 0}
        errors = list(Draft7Validator(recon_schema).iter_errors(data))
        assert errors == []

    def test_drift_flagged_true_requires_reason(self, recon_schema, jsonschema_validator):
        """When drift_flagged is true, drift_reason should be a string."""
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_RECON)
        data["drift_flagged"] = True
        # Valid: drift_reason is a string
        data["drift_reason"] = "Target scope deviation detected"
        errors = list(Draft7Validator(recon_schema).iter_errors(data))
        assert errors == []


# ===========================================================================
# Scan schema — validation
# ===========================================================================


class TestScanSchemaValidation:
    """Test scan.schema.json with valid and invalid data."""

    VALID_SCAN = {
        "session_id": "scan-01",
        "plan_id": "PTO-001",
        "vulnerabilities": [
            {
                "id": "CVE-2024-1234",
                "title": "SQL Injection in login endpoint",
                "severity": "Critical",
                "affected_component": "/api/login",
                "description": "Blind SQL injection via username parameter",
                "cvss_score": 9.1,
            }
        ],
        "summary": {"total_vulnerabilities": 1, "critical": 1},
        "completed_at": "2026-06-01T00:00:00Z",
    }

    def test_valid_passes(self, scan_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        errors = list(Draft7Validator(scan_schema).iter_errors(self.VALID_SCAN))
        assert errors == [], f"Validation errors on valid data: {errors}"

    def test_missing_vulnerabilities_fails(self, scan_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = {k: v for k, v in self.VALID_SCAN.items() if k != "vulnerabilities"}
        errors = list(Draft7Validator(scan_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_invalid_severity_fails(self, scan_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_SCAN)
        data["vulnerabilities"][0]["severity"] = "Unknown"
        errors = list(Draft7Validator(scan_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_cvss_out_of_range_fails(self, scan_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_SCAN)
        data["vulnerabilities"][0]["cvss_score"] = 11.0
        errors = list(Draft7Validator(scan_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_cve_pattern_enforced(self, scan_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_SCAN)
        data["vulnerabilities"][0]["id"] = "not-a-cve"
        errors = list(Draft7Validator(scan_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_min_length_on_title(self, scan_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_SCAN)
        data["vulnerabilities"][0]["title"] = "XSS"
        errors = list(Draft7Validator(scan_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_additional_property_rejected(self, scan_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_SCAN)
        data["unauthorized_field"] = "rejected"
        errors = list(Draft7Validator(scan_schema).iter_errors(data))
        assert len(errors) >= 1


# ===========================================================================
# Report schema — validation
# ===========================================================================


class TestReportSchemaValidation:
    """Test report.schema.json with valid and invalid data."""

    VALID_REPORT = {
        "session_id": "report-01",
        "plan_id": "PTO-001",
        "executive_summary": {
            "overall_risk": "High",
            "top_findings": ["SQL Injection in /api/login"],
            "metrics": {"total_findings": 1, "critical": 1},
        },
        "findings": [
            {
                "finding_id": "PENTEST-001",
                "title": "SQL Injection in login endpoint",
                "severity": "Critical",
                "affected_component": "/api/login",
                "description": "Blind SQL injection in username parameter allowing data exfiltration.",
                "steps_to_reproduce": "Send ' OR 1=1 -- to /api/login",
            }
        ],
        "recommendations": {
            "short_term": ["Use prepared statements"],
            "medium_term": ["Add WAF rules"],
            "long_term": ["Security architecture review"],
        },
        "completed_at": "2026-06-01T00:00:00Z",
    }

    def test_valid_passes(self, report_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        errors = list(Draft7Validator(report_schema).iter_errors(self.VALID_REPORT))
        assert errors == [], f"Validation errors on valid data: {errors}"

    def test_missing_executive_summary_fails(self, report_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = {k: v for k, v in self.VALID_REPORT.items() if k != "executive_summary"}
        errors = list(Draft7Validator(report_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_missing_recommendations_fails(self, report_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = {k: v for k, v in self.VALID_REPORT.items() if k != "recommendations"}
        errors = list(Draft7Validator(report_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_invalid_overall_risk_fails(self, report_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_REPORT)
        data["executive_summary"]["overall_risk"] = "Unknown"
        errors = list(Draft7Validator(report_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_finding_pattern_enforced(self, report_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_REPORT)
        data["findings"][0]["finding_id"] = "bad-id"
        errors = list(Draft7Validator(report_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_empty_findings_allowed(self, report_schema, jsonschema_validator):
        """No findings is valid (clean assessment)."""
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_REPORT)
        data["findings"] = []
        errors = list(Draft7Validator(report_schema).iter_errors(data))
        assert errors == []

    def test_additional_property_rejected(self, report_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_REPORT)
        data["extra_field"] = "rejected"
        errors = list(Draft7Validator(report_schema).iter_errors(data))
        assert len(errors) >= 1

    def test_finding_min_length_description(self, report_schema, jsonschema_validator):
        Draft7Validator, _ = jsonschema_validator
        data = dict(self.VALID_REPORT)
        data["findings"][0]["description"] = "Short"
        errors = list(Draft7Validator(report_schema).iter_errors(data))
        assert len(errors) >= 1


# ===========================================================================
# Cross-schema consistency
# ===========================================================================


class TestCrossSchemaConsistency:
    """All schemas share common patterns for drift, timestamps, etc."""

    SCHEMA_NAMES = ["recon.schema.json", "scan.schema.json", "report.schema.json"]

    def test_all_have_plan_id_pattern(self):
        """All schemas should enforce the PTO-NNN plan ID pattern."""
        for name in self.SCHEMA_NAMES:
            schema = json.loads((SCHEMA_DIR / name).read_text())
            plan_id = schema.get("properties", {}).get("plan_id", {})
            assert "pattern" in plan_id, f"{name} missing plan_id pattern"
            assert "^PTO-" in plan_id["pattern"], (
                f"{name} plan_id pattern should enforce PTO- prefix"
            )

    def test_all_required_fields_include_session_and_plan(self):
        for name in self.SCHEMA_NAMES:
            schema = json.loads((SCHEMA_DIR / name).read_text())
            required = set(schema.get("required", []))
            assert "session_id" in required, f"{name} missing session_id from required"
            assert "plan_id" in required, f"{name} missing plan_id from required"
            assert "completed_at" in required, f"{name} missing completed_at from required"

    def test_no_undocumented_required_fields(self):
        """Every field in 'required' must also appear in 'properties'."""
        for name in self.SCHEMA_NAMES:
            schema = json.loads((SCHEMA_DIR / name).read_text())
            props = set(schema.get("properties", {}).keys())
            required = set(schema.get("required", []))
            undocumented = required - props
            assert not undocumented, (
                f"{name}: required fields missing from properties: {undocumented}"
            )
