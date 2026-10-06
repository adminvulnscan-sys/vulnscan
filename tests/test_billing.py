import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from billing import (session_client, change_subscription, refresh_payment_return,
                     clear_account_state, require_public_key, spend_credit)


def client(email="a@example.test", user_id="a"):
    db = Mock()
    db.auth.get_user.return_value.user = SimpleNamespace(email=email, id=user_id)
    db.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"stripe_subscription_id": "sub_test", "stripe_customer_id": "cus_test"}]
    return db


def stripe_mock():
    stripe = Mock()
    stripe.Subscription.retrieve.return_value = {
        "id": "sub_test", "customer": "cus_test", "metadata": {"user_id": "a"},
        "status": "active"}
    stripe.Subscription.modify.return_value = {
        "cancel_at_period_end": True, "current_period_end": 1793577600}
    return stripe


class BillingTests(unittest.TestCase):
    def test_client_isolated_and_reused_per_session(self):
        a, b = {}, {}
        factory = Mock(side_effect=[client(), client("b@example.test", "b")])
        ca = session_client(a, factory)
        cb = session_client(b, factory)
        self.assertIs(ca, session_client(a, factory))
        self.assertIsNot(ca, cb)
        ca.auth.sign_out()
        cb.auth.sign_out.assert_not_called()
        self.assertEqual(cb.auth.get_user().user.email, "b@example.test")

    def test_cancel_confirmed_and_no_database_write(self):
        db, stripe = client(), stripe_mock()
        result = change_subscription(stripe, db, "a@example.test", True)
        self.assertTrue(result["cancelacion_pendiente"])
        self.assertNotEqual(result["fecha_vencimiento"], "Pendiente de sincronizar")
        stripe.Subscription.modify.assert_called_once_with("sub_test", cancel_at_period_end=True)
        db.table.return_value.update.assert_not_called()

    def test_reactivation(self):
        stripe = stripe_mock()
        stripe.Subscription.modify.return_value = {"cancel_at_period_end": False,
            "items": {"data": [{"current_period_end": 1793577600}]}}
        self.assertFalse(change_subscription(stripe, client(), "a@example.test", False)["cancelacion_pendiente"])

    def test_failed_cancellation_leaves_ui_state_unchanged(self):
        for filename in ("app.py", "vulnscan.py"):
            tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
            fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_cambiar_renovacion")
            stripe, db = stripe_mock(), client()
            stripe.Subscription.modify.side_effect = RuntimeError("simulated failure")
            state = {"email_usuario": "a@example.test", "cancelacion_pendiente": False, "tokens_pdf": 0}
            ui = SimpleNamespace(session_state=state, error=Mock())
            namespace = {"st": ui, "stripe": stripe, "supabase": db, "change_subscription": change_subscription}
            exec(compile(ast.Module(body=[fn], type_ignores=[]), filename, "exec"), namespace)
            before = dict(state)
            self.assertFalse(namespace["_cambiar_renovacion"](True))
            self.assertEqual(before, state)
            ui.error.assert_called_once()

    def test_wrong_identity_and_owner_rejected(self):
        stripe = stripe_mock()
        with self.assertRaises(ValueError):
            change_subscription(stripe, client(), "b@example.test", True)
        stripe.Subscription.retrieve.assert_not_called()
        stripe.Subscription.retrieve.return_value["metadata"]["user_id"] = "b"
        with self.assertRaises(ValueError):
            change_subscription(stripe, client(), "a@example.test", True)
        stripe.Subscription.modify.assert_not_called()

    def test_unconfirmed_return_never_grants_tokens(self):
        for filename in ("app.py", "vulnscan.py"):
            tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
            fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_confirmar_compra_pdf_tras_stripe")
            state = {"tokens_pdf": 0, "reporte_pdf_desbloqueado": None}
            load, restore = Mock(), Mock()
            namespace = {"supabase": client(), "refresh_payment_return": refresh_payment_return,
                         "cargar_perfil_usuario": load, "restaurar_ultimo_escaneo_supabase": restore}
            exec(compile(ast.Module(body=[fn], type_ignores=[]), filename, "exec"), namespace)
            namespace["_confirmar_compra_pdf_tras_stripe"]("a@example.test")
            self.assertEqual(state, {"tokens_pdf": 0, "reporte_pdf_desbloqueado": None})
            load.assert_called_once_with("a@example.test")
            restore.assert_called_once_with("a@example.test")
            self.assertNotIn("actualizar_usuario_supabase", ast.unparse(fn))

    def test_return_rejects_other_user(self):
        load, restore = Mock(), Mock()
        with self.assertRaises(ValueError):
            refresh_payment_return(client(), "b@example.test", load, restore)
        load.assert_not_called()
        restore.assert_not_called()

    def test_case_variant_identity_cannot_refresh_another_profile(self):
        load, restore = Mock(), Mock()
        with self.assertRaises(ValueError):
            refresh_payment_return(client("Alice@example.test"), "alice@example.test", load, restore)
        load.assert_not_called()
        restore.assert_not_called()

    def test_spoofed_query_email_cannot_change_identity(self):
        for filename in ("app.py", "vulnscan.py"):
            tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
            branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
                          and ast.unparse(n.test) == "pago_param == 'exitoso'")
            for logged_in in (False, True):
                state = {"usuario_autenticado": logged_in, "email_usuario": "a@example.test"}
                ui = SimpleNamespace(session_state=state,
                    query_params={"pago": "exitoso", "email": "b@example.test"},
                    warning=Mock(), info=Mock())
                refresh = Mock()
                namespace = {"st": ui, "pago_param": "exitoso",
                             "_confirmar_compra_pdf_tras_stripe": refresh}
                exec(compile(ast.Module(body=[branch], type_ignores=[]), filename, "exec"), namespace)
                self.assertEqual(state["email_usuario"], "a@example.test")
                if logged_in:
                    refresh.assert_called_once_with("a@example.test")
                else:
                    refresh.assert_not_called()

    def test_checkout_metadata_and_price_validation(self):
        tree = ast.parse(Path("app.py").read_text(encoding="utf-8"))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "generar_link_pago")
        stripe, db = stripe_mock(), client()
        db.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []
        stripe.checkout.Session.create.return_value.url = "https://checkout.example.test"
        namespace = {"stripe": stripe, "supabase": db, "authenticated_user": __import__("billing").authenticated_user,
                     "STRIPE_PRICES": {"pro_recurrente": "price_test"},
                     "os": SimpleNamespace(getenv=lambda key, default: default)}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), "app.py", "exec"), namespace)
        checkout = namespace["generar_link_pago"]
        with self.assertRaises(ValueError):
            checkout("price_wrong", "a@example.test", "pro_recurrente", "subscription")
        stripe.checkout.Session.create.assert_not_called()
        checkout("price_test", "a@example.test", "pro_recurrente", "subscription")
        args = stripe.checkout.Session.create.call_args.kwargs
        self.assertEqual(args["subscription_data"]["metadata"]["user_id"], "a")
        self.assertNotIn("email=", args["success_url"])
        self.assertIn("{CHECKOUT_SESSION_ID}", args["success_url"])

    def test_logout_cleans_only_account_data(self):
        state = {"_vs_lang": "es", "mostrar_terminos": True,
                 "email_usuario": "a@example.test", "tokens_pdf": 3,
                 "dominios_verificados": ["example.test"], "_supabase_client": object()}
        clear_account_state(state)
        self.assertEqual(state, {"_vs_lang": "es", "mostrar_terminos": True})

    def test_interface_rejects_service_role_keys(self):
        import base64
        import json
        payload = base64.urlsafe_b64encode(json.dumps({"role": "service_role"}).encode()).decode().rstrip("=")
        for key in (None, "sb_secret_fake", "header." + payload + ".signature"):
            with self.assertRaises(ValueError):
                require_public_key(key)
        self.assertEqual(require_public_key("sb_publishable_fake"), "sb_publishable_fake")

    def test_spend_uses_rpc_and_never_writes_balance_directly(self):
        db = client()
        db.rpc.return_value.execute.return_value.data = {"remaining": 2}
        self.assertEqual(spend_credit(db, "tokens_pro", "operation_test"), 2)
        db.rpc.assert_called_once_with("billing_spend", {"p_credit": "tokens_pro", "p_operation": "operation_test"})
        db.table.assert_not_called()

    def test_failed_pdf_authorization_does_not_serve_bytes(self):
        for filename in ("app.py", "vulnscan.py"):
            tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
            fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_descargar_pdf_seguro")
            db = client(); db.rpc.return_value.execute.side_effect = RuntimeError("simulated")
            ui = SimpleNamespace(session_state={"escaneo_actual_id": "42"}, warning=Mock(), download_button=Mock())
            namespace = {"supabase": db, "st": ui}
            exec(compile(ast.Module(body=[fn], type_ignores=[]), filename, "exec"), namespace)
            self.assertFalse(namespace["_descargar_pdf_seguro"](data=b"pdf", file_name="test.pdf"))
            ui.download_button.assert_not_called()

    def test_existing_subscription_routes_to_portal(self):
        tree = ast.parse(Path("app.py").read_text(encoding="utf-8"))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "generar_link_pago")
        stripe, db = stripe_mock(), client()
        stripe.billing_portal.Session.create.return_value.url = "https://portal.example.test"
        namespace = {"stripe": stripe, "supabase": db, "authenticated_user": __import__("billing").authenticated_user,
                     "STRIPE_PRICES": {"pro_recurrente": "price_test"},
                     "os": SimpleNamespace(getenv=lambda key, default: default)}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), "app.py", "exec"), namespace)
        result = namespace["generar_link_pago"]("price_test", "a@example.test", "pro_recurrente", "subscription")
        self.assertEqual(result, "https://portal.example.test")
        stripe.checkout.Session.create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
