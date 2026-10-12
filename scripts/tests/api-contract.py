#!/usr/bin/env python3
"""Validate cross-language DTO examples against the actual OpenAPI schemas."""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker
import yaml


ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = yaml.safe_load((ROOT / "openapi/sandbox-api.yaml").read_text())
SCHEMAS = DOCUMENT["components"]["schemas"]
SECURITY = json.loads(
    (ROOT / "tests/fixtures/security/instance-security.json").read_text()
)
AUTOMATION_CAPABILITIES = json.loads(
    (ROOT / "sdk/typescript/test/fixtures/capabilities-automation.json").read_text()
)
AUTOMATION_NOTIFICATION = json.loads(
    (ROOT / "sdk/typescript/test/fixtures/automation-notification.json").read_text()
)
VALIDATOR = Draft202012Validator(
    {"$ref": "#/components/schemas/InstanceSecurity", "components": DOCUMENT["components"]},
    # Construction fails when either required checker is unavailable; the
    # standard unrestricted checker silently accepts unknown formats.
    format_checker=FormatChecker(formats=["date-time", "uuid"]),
)


def references(value):
    if isinstance(value, dict):
        if "$ref" in value:
            yield value["$ref"]
        for item in value.values():
            yield from references(item)
    elif isinstance(value, list):
        for item in value:
            yield from references(item)


class ApiContract(unittest.TestCase):
    def test_tenant_audit_projection_rejects_project_records_and_private_details(self):
        page = json.loads((ROOT / "sdk/typescript/test/fixtures/tenant-audit-page.json").read_text())
        validator = Draft202012Validator(
            {"$ref": "#/components/schemas/TenantAuditRecordPage", "components": DOCUMENT["components"]},
            format_checker=FormatChecker(formats=["date-time", "uuid"]),
        )
        validator.validate(page)
        for field, value in (("project_id", page["items"][0]["id"]), ("details", {"credential": "private"})):
            invalid = copy.deepcopy(page)
            invalid["items"][0][field] = value
            self.assertTrue(list(validator.iter_errors(invalid)))
        invalid = copy.deepcopy(page)
        del invalid["items"][0]["project_id"]
        self.assertTrue(list(validator.iter_errors(invalid)))
        route = DOCUMENT["paths"]["/v1/tenant-audit-records"]["get"]
        self.assertEqual({p["name"] for p in route["parameters"]}, {"limit", "cursor"})
        self.assertTrue({"400", "401", "403", "404"}.issubset(route["responses"]))

    def test_all_local_references_and_schema_syntax(self):
        self.assertEqual(DOCUMENT["openapi"], "3.1.0")
        for reference in references(DOCUMENT):
            with self.subTest(reference=reference):
                self.assertTrue(reference.startswith("#/"))
                target = DOCUMENT
                for part in reference[2:].split("/"):
                    target = target[part.replace("~1", "/").replace("~0", "~")]
                self.assertIsInstance(target, dict)
        for name, schema in SCHEMAS.items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)

    def test_recorded_example(self):
        VALIDATOR.validate(SECURITY)

    def test_unavailable_and_nullable_evidence(self):
        value = copy.deepcopy(SECURITY)
        policy = value["desired"]["security_policy"]
        policy.update(document_status="UNAVAILABLE", rules_sha256=None, profile=None)
        observation = value["observations"]
        observation["lifecycle"].update(observed_at=None, age_seconds=None, freshness="MISSING")
        observation["policy_object"].update(
            status="UNAVAILABLE", ledger_status=None, recorded_generation=None, observed_at=None
        )
        observation["launch_validation"].update(
            status="UNAVAILABLE", observed_at=None, generation=None,
            matches_current_launch=False, matches_current_cluster_epoch=False,
        )
        observation["node_authorization"].update(status="UNAVAILABLE", valid_until=None)
        for state in ("NONE", "REDACTED", "UNAVAILABLE"):
            with self.subTest(state=state):
                value["active_operation"].update(state=state, resource=None)
                VALIDATOR.validate(value)
        # A nullable error is required even when the operation has no error.
        value["active_operation"] = copy.deepcopy(SECURITY["active_operation"])
        value["active_operation"]["resource"]["error"] = None
        VALIDATOR.validate(value)

    def test_disclosure_and_unknown_guards(self):
        cases = []
        value = copy.deepcopy(SECURITY)
        value["desired"]["security_policy"]["rules"] = {"private": "not disclosed"}
        cases.append(("raw policy", value))
        value = copy.deepcopy(SECURITY)
        value["applied_policy"]["status"] = "APPLIED"
        cases.append(("invented applied evidence", value))
        value = copy.deepcopy(SECURITY)
        value["runtime_certification"] = "CERTIFIED"
        cases.append(("invented certification", value))
        value = copy.deepcopy(SECURITY)
        value["findings"] = ["free-form internal host detail"]
        cases.append(("unbounded finding", value))
        value = copy.deepcopy(SECURITY)
        del value["desired"]["security_policy"]["profile"]
        cases.append(("omitted nullable key", value))
        value = copy.deepcopy(SECURITY)
        value["observations"]["node_authorization"]["valid_until"] = "not a timestamp"
        cases.append(("invalid observation timestamp", value))
        for name, value in cases:
            with self.subTest(case=name):
                self.assertTrue(list(VALIDATOR.iter_errors(value)))

    def test_security_route_and_feature_reference(self):
        route = DOCUMENT["paths"]["/v1/instances/{id}/security"]["get"]
        self.assertEqual(route["operationId"], "getInstanceSecurity")
        schema = route["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(schema["$ref"], "#/components/schemas/InstanceSecurity")
        feature = SCHEMAS["ApiFeatures"]
        self.assertIn("instance_security", feature["required"])
        self.assertEqual(feature["properties"]["instance_security"]["const"], True)

    def test_automation_capability_is_required_nullable_and_scoped_to_discovery(self):
        validator = Draft202012Validator(
            {"$ref": "#/components/schemas/Capabilities", "components": DOCUMENT["components"]},
            format_checker=FormatChecker(formats=["date-time", "uuid"]),
        )
        validator.validate(AUTOMATION_CAPABILITIES)
        disabled = copy.deepcopy(AUTOMATION_CAPABILITIES)
        disabled["automation"] = None
        disabled["api_features"]["scheduled_tasks"] = False
        disabled["api_features"]["event_automation"] = False
        disabled["api_features"]["automation_notifications"] = False
        validator.validate(disabled)
        del disabled["automation"]
        self.assertTrue(list(validator.iter_errors(disabled)))
        route = DOCUMENT["paths"]["/v1/capabilities"]["get"]
        self.assertEqual(route["operationId"], "getCapabilities")
        self.assertEqual(
            route["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Capabilities",
        )

    def test_automation_discovery_actions_and_triggers_match_acceptance_schemas(self):
        contract = AUTOMATION_CAPABILITIES["automation"]
        for advertised, schema_name in (
            ("supported_actions", "AutomationAction"),
            ("supported_triggers", "AutomationTrigger"),
        ):
            implemented = {
                kind
                for branch in SCHEMAS[schema_name]["oneOf"]
                for kind in branch["properties"]["kind"]["enum"]
            }
            self.assertEqual(set(contract[advertised]), implemented)
            self.assertEqual(len(contract[advertised]), len(implemented))

    def test_automation_capability_rejects_invented_semantics_limits_and_disclosure(self):
        validator = Draft202012Validator(
            {"$ref": "#/components/schemas/AutomationCapability", "components": DOCUMENT["components"]}
        )
        original = AUTOMATION_CAPABILITIES["automation"]
        changes = [
            ("version", ("schema_version",), 2),
            ("invented action", ("supported_actions",), ["START", "STOP", "RESTART", "DELETE", "RENEW", "EXECUTE", "RESTORE"]),
            ("duplicate action", ("supported_actions",), ["START"] * 7),
            ("missing trigger", ("supported_triggers",), ["ONCE", "CRON_UTC"]),
            ("local clock", ("clock",), "LOCAL"),
            ("timezone conversion", ("time_zone",), "Asia/Shanghai"),
            ("six fields", ("cron", "field_count"), 6),
            ("cron union", ("cron", "day_of_month_and_week"), "UNION"),
            ("catchup bursts", ("missed_run_policy",), "CATCH_UP_ALL"),
            ("skip budget bypass", ("skipped_runs_consume_budget",), False),
            ("retrigger", ("known_automated_events_retrigger",), True),
            ("unknown replay", ("outcome_unknown_policy",), "RETRY_WITH_NEW_KEY"),
            ("runtime assertion", ("assurance",), "CERTIFIED"),
            ("run limit", ("limits", "run_budget", "maximum"), 10001),
            ("inclusive delegation minimum", ("limits", "delegation_lifetime_seconds", "exclusive_minimum"), 59),
            ("remaining quota", ("limits", "live_policies_per_project"), 0),
            ("private details", ("host_credentials",), {"private": "not disclosed"}),
        ]
        for name, path, replacement in changes:
            with self.subTest(case=name):
                value = copy.deepcopy(original)
                target = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                self.assertTrue(list(validator.iter_errors(value)))
        for field in SCHEMAS["AutomationCapability"]["required"]:
            with self.subTest(missing=field):
                value = copy.deepcopy(original)
                del value[field]
                self.assertTrue(list(validator.iter_errors(value)))

    def test_notification_resource_page_and_acknowledgement_receipt(self):
        def validate(name, value):
            Draft202012Validator(
                {"$ref": f"#/components/schemas/{name}", "components": DOCUMENT["components"]},
                format_checker=FormatChecker(formats=["date-time", "uuid"]),
            ).validate(value)

        for status in ("FAILED", "OUTCOME_UNKNOWN"):
            value = copy.deepcopy(AUTOMATION_NOTIFICATION)
            value["source_status"] = status
            validate("AutomationNotification", value)
        acknowledged = copy.deepcopy(AUTOMATION_NOTIFICATION)
        acknowledged.update(
            acknowledged_at="2026-10-11T00:02:00+00:00",
            acknowledged_by="00000000-0000-4000-8000-000000000007",
            version=2,
        )
        validate("AutomationNotification", acknowledged)
        validate("AutomationNotificationPage", {
            "items": [AUTOMATION_NOTIFICATION, acknowledged],
            "next_cursor": "signed-continuation",
            "cutoff": "2026-10-11T00:03:00Z",
        })
        validate("AutomationNotificationPage", {
            "items": [], "next_cursor": None, "cutoff": "2026-10-11T00:03:00Z",
        })
        validate("AutomationNotificationReceipt", {
            "resource": acknowledged, "idempotency_expires_at": "2026-10-18T00:02:00Z",
        })

    def test_notification_contract_excludes_payloads_and_invented_resolution(self):
        validator = Draft202012Validator(
            {"$ref": "#/components/schemas/AutomationNotification", "components": DOCUMENT["components"]},
            format_checker=FormatChecker(formats=["date-time", "uuid"]),
        )
        for field, replacement in (
            ("source_status", "SUCCEEDED"), ("source_status", "SKIPPED"),
            ("source_run_version", 0), ("version", 0),
            ("run_id", "not-a-uuid"), ("source_event_id", None),
            ("created_at", "2026-10-11T08:00:00+08:00"),
            ("acknowledged_at", "2026-10-11T08:00:00+08:00"),
            ("payload", {"command": "not disclosed"}),
            ("failure_code", "private internal detail"),
            ("issuer", "private issuer"), ("sub", "private identity"),
            ("resolved", True),
        ):
            with self.subTest(field=field, replacement=replacement):
                value = copy.deepcopy(AUTOMATION_NOTIFICATION)
                value[field] = replacement
                self.assertTrue(list(validator.iter_errors(value)))
        self.assertFalse(SCHEMAS["AutomationNotification"]["additionalProperties"])
        self.assertEqual(
            set(SCHEMAS["AutomationNotification"]["required"]),
            set(SCHEMAS["AutomationNotification"]["properties"]),
        )
        for field in SCHEMAS["AutomationNotification"]["required"]:
            with self.subTest(missing=field):
                value = copy.deepcopy(AUTOMATION_NOTIFICATION)
                del value[field]
                self.assertTrue(list(validator.iter_errors(value)))
        for name, value in (
            ("AutomationNotificationPage", {"items": [], "next_cursor": None}),
            ("AutomationNotificationReceipt", {
                "resource": AUTOMATION_NOTIFICATION,
                "idempotency_expires_at": "2026-10-18T00:02:00Z", "resolved": True,
            }),
        ):
            with self.subTest(schema=name):
                nested = Draft202012Validator(
                    {"$ref": f"#/components/schemas/{name}", "components": DOCUMENT["components"]}
                )
                self.assertTrue(list(nested.iter_errors(value)))

    def test_notification_routes_require_scoped_filters_and_original_precondition(self):
        paths = DOCUMENT["paths"]
        listing = paths["/v1/automation-notifications"]["get"]
        detail = paths["/v1/automation-notifications/{id}"]["get"]
        acknowledge = paths["/v1/automation-notifications/{id}/actions/acknowledge"]["post"]
        for route, operation, schema in (
            (listing, "listAutomationNotifications", "AutomationNotificationPage"),
            (detail, "getAutomationNotification", "AutomationNotification"),
            (acknowledge, "acknowledgeAutomationNotification", "AutomationNotificationReceipt"),
        ):
            with self.subTest(operation=operation):
                self.assertEqual(route["operationId"], operation)
                self.assertEqual(route["x-implementation-stage"], "formal-0042")
                self.assertEqual(
                    route["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                    f"#/components/schemas/{schema}",
                )
        queries = {value["name"]: value for value in listing["parameters"]}
        self.assertEqual(set(queries), {"project_id", "instance_id", "limit", "cursor"})
        self.assertTrue(queries["project_id"]["required"])
        self.assertEqual(queries["project_id"]["schema"]["format"], "uuid")
        self.assertEqual(queries["limit"]["schema"], {"type": "integer", "minimum": 1, "maximum": 100})
        self.assertEqual(queries["cursor"]["schema"]["maxLength"], 2048)
        self.assertEqual(
            [value["$ref"] for value in acknowledge["parameters"]],
            ["#/components/parameters/IdempotencyKey", "#/components/parameters/AutomationNotificationIfMatch"],
        )
        for route in (detail, acknowledge):
            self.assertEqual(
                route["responses"]["200"]["headers"]["ETag"]["$ref"],
                "#/components/headers/AutomationNotificationETag",
            )
        self.assertTrue(acknowledge["requestBody"]["required"])
        body = acknowledge["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(body["$ref"], "#/components/schemas/AutomationEmptyAction")
        empty = Draft202012Validator(SCHEMAS["AutomationEmptyAction"])
        empty.validate({})
        for invalid in (None, [], {"run_id": AUTOMATION_NOTIFICATION["run_id"]}, {"resolved": True}):
            self.assertTrue(list(empty.iter_errors(invalid)))
        self.assertTrue({"409", "410", "412", "428"}.issubset(acknowledge["responses"]))
        feature = SCHEMAS["ApiFeatures"]
        self.assertIn("automation_notifications", feature["required"])
        self.assertEqual(feature["properties"]["automation_notifications"]["type"], "boolean")


if __name__ == "__main__":
    unittest.main(verbosity=2)
