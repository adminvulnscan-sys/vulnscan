import unittest
from scripts.reconcile_billing import proposals

UID = "11111111-1111-4111-8111-111111111111"


class ReconciliationTests(unittest.TestCase):
    def snapshot(self, metadata=None):
        return {"auth_users": [{"id": UID, "email": "same@example.test"}],
                "subscriptions": [{"id": "sub_test", "customer": "cus_test", "livemode": False,
                    "metadata": metadata or {"email": "same@example.test"}}]}

    def test_email_alone_does_not_link(self):
        result = proposals(self.snapshot())
        self.assertEqual(result["proposals"][0]["action"], "manual_review")
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["database_writes"], 0)

    def test_metadata_identity_proposes_only(self):
        result = proposals(self.snapshot({"user_id": UID}))
        self.assertEqual(result["proposals"][0]["database_binding"]["billing_user_id"], UID)

    def test_manual_evidence_required(self):
        binding = {"subscription_id": "sub_test", "customer_id": "cus_test", "user_id": UID,
                   "approved_by": "reviewer", "evidence_ref": "test-proof-1", "evidence_type": "email"}
        with self.assertRaises(ValueError):
            proposals(self.snapshot(), [binding])
        binding["evidence_type"] = "authenticated_account_ownership"
        self.assertEqual(proposals(self.snapshot(), [binding])["proposals"][0]["action"], "propose_binding")

    def test_conflicts_and_live_snapshots_blocked(self):
        snapshot = self.snapshot({"user_id": UID})
        snapshot["subscriptions"][0]["livemode"] = True
        self.assertEqual(proposals(snapshot)["proposals"][0]["action"], "blocked")
        snapshot["subscriptions"][0]["livemode"] = False
        snapshot["subscriptions"].append({**snapshot["subscriptions"][0], "id": "sub_other"})
        self.assertTrue(all(p["action"] == "blocked" for p in proposals(snapshot)["proposals"]))

    def test_existing_customer_conflict(self):
        snapshot = self.snapshot({"user_id": UID})
        snapshot["profiles"] = [{"billing_user_id": UID, "stripe_customer_id": "cus_other"}]
        self.assertEqual(proposals(snapshot)["proposals"][0]["reason"], "existing_binding_conflict")
