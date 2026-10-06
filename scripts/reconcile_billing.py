"""Reconciliación offline: genera propuestas, nunca llama a Stripe/Supabase ni escribe BD."""
import argparse
import json
from pathlib import Path
from uuid import UUID


def proposals(snapshot, reviewed_bindings=()):
    users = {str(UUID(user["id"])) for user in snapshot["auth_users"]}
    approvals = {}
    for binding in reviewed_bindings:
        if not binding.get("approved_by") or not binding.get("evidence_ref"):
            raise ValueError("La revisión manual requiere responsable y referencia de prueba")
        if binding.get("evidence_type") not in ("authenticated_account_ownership", "verified_paid_checkout"):
            raise ValueError("El correo no es prueba de titularidad")
        key = binding["subscription_id"]
        if key in approvals:
            raise ValueError("Revisión ambigua")
        approvals[key] = binding
    output = []
    seen_users, seen_customers = set(), set()
    for sub in snapshot["subscriptions"]:
        uid = sub.get("metadata", {}).get("user_id")
        approval = approvals.get(sub["id"])
        if approval and uid and uid != approval["user_id"]:
            output.append({"subscription_id": sub["id"], "action": "blocked", "reason": "identity_conflict"})
            continue
        if not uid and approval and approval["customer_id"] == sub["customer"]:
            uid = approval["user_id"]
        row = {"subscription_id": sub["id"], "customer_id": sub["customer"]}
        if uid not in users:
            output.append({**row, "action": "manual_review", "reason": "no_trusted_identity"})
            continue
        if sub.get("livemode") is not False:
            output.append({**row, "action": "blocked", "reason": "test_mode_required"})
            continue
        if uid in seen_users or sub["customer"] in seen_customers:
            output.append({**row, "action": "blocked", "reason": "multiple_subscriptions_or_owners"})
            # Mark previous candidate as blocked too, never pick the first by accident.
            for prior in output:
                if prior.get("user_id") == uid or prior.get("customer_id") == sub["customer"]:
                    prior.update(action="blocked", reason="multiple_subscriptions_or_owners")
            continue
        seen_users.add(uid); seen_customers.add(sub["customer"])
        profile = next((p for p in snapshot.get("profiles", []) if p.get("billing_user_id") == uid), None)
        if profile and (profile.get("stripe_customer_id") not in (None, sub["customer"]) or
                        profile.get("stripe_subscription_id") not in (None, sub["id"])):
            output.append({**row, "user_id": uid, "action": "blocked", "reason": "existing_binding_conflict"})
            continue
        output.append({**row, "user_id": uid, "action": "propose_binding",
            "evidence": "stripe_user_id_metadata" if sub.get("metadata", {}).get("user_id") else approval["evidence_ref"],
            "stripe_metadata_patch": {"user_id": uid},
            "database_binding": {"billing_user_id": uid, "stripe_customer_id": sub["customer"],
                                 "stripe_subscription_id": sub["id"]},
            "requires_fresh_stripe_read_and_atomic_billing_apply": True})
    return {"dry_run": True, "network_calls": 0, "database_writes": 0, "proposals": output}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path, help="Exportación de prueba: auth_users, subscriptions, profiles")
    parser.add_argument("--reviewed-bindings", type=Path, help="Pruebas de titularidad revisadas; nunca solo correos")
    parser.add_argument("--dry-run", action="store_true", help="Siempre activo; no existe modo de aplicación")
    args = parser.parse_args()
    bindings = json.loads(args.reviewed_bindings.read_text()) if args.reviewed_bindings else []
    result = proposals(json.loads(args.snapshot.read_text()), bindings)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
