import ast
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from billing import begin_scan, finish_scan, pending_scan_credit, ScanBusy


class CreditFlowTests(TestCase):
    def pdf_function(self, filename, state, response, clicked=False):
        tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_descargar_pdf_seguro")
        db = Mock()
        db.rpc.return_value.execute.side_effect = [SimpleNamespace(data=r) for r in response]
        ui = SimpleNamespace(session_state=state, button=Mock(return_value=clicked),
                             download_button=Mock(return_value=True), warning=Mock())
        namespace = {"st": ui, "supabase": db}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), filename, "exec"), namespace)
        return namespace["_descargar_pdf_seguro"], ui, db

    def test_rendering_pdf_never_consumes_credit(self):
        for filename in ("app.py", "vulnscan.py"):
            state = {"tokens_pdf": 1, "escaneo_actual_id": "42"}
            fn, ui, db = self.pdf_function(filename, state, [{"authorized": False}])
            self.assertFalse(fn(data=b"pdf", file_name="test.pdf"))
            db.rpc.assert_called_once_with("billing_authorize_pdf", {"p_report": "42", "p_consume": False})
            self.assertEqual(state["tokens_pdf"], 1)
            ui.download_button.assert_not_called()

    def test_pdf_credit_is_consumed_only_after_explicit_click(self):
        for filename in ("app.py", "vulnscan.py"):
            state = {"tokens_pdf": 1, "escaneo_actual_id": "42"}
            fn, ui, db = self.pdf_function(filename, state,
                [{"authorized": False}, {"authorized": True, "remaining": 0}], clicked=True)
            self.assertTrue(fn(data=b"pdf", file_name="test.pdf"))
            self.assertEqual(db.rpc.call_args_list[1].kwargs, {})
            self.assertEqual(db.rpc.call_args_list[1].args,
                ("billing_authorize_pdf", {"p_report": "42", "p_consume": True}))
            self.assertEqual(state["tokens_pdf"], 0)
            ui.download_button.assert_called_once()

    def test_previously_unlocked_pdf_never_consumes_again(self):
        fn, ui, db = self.pdf_function("app.py", {"tokens_pdf": 0, "escaneo_actual_id": "42"},
                                    [{"authorized": True, "remaining": 0}])
        self.assertTrue(fn(data=b"pdf"))
        self.assertEqual(db.rpc.call_count, 1)
        ui.button.assert_not_called()

    def test_failed_explicit_authorization_does_not_serve_pdf(self):
        fn, ui, db = self.pdf_function("app.py", {"tokens_pdf": 1, "escaneo_actual_id": "42"},
                                    [{"authorized": False}, {"authorized": False}], clicked=True)
        self.assertFalse(fn(data=b"pdf"))
        ui.download_button.assert_not_called()
        self.assertEqual(ui.session_state["tokens_pdf"], 1)

    def test_busy_scan_does_not_call_supabase(self):
        state, db = {"escaneo_en_curso": True, "tokens_pro": 1}, Mock()
        with self.assertRaises(ScanBusy):
            begin_scan(state, db, "tokens_pro", "example.invalid", "Pro")
        db.rpc.assert_not_called()
        self.assertEqual(state["tokens_pro"], 1)

    def test_session_claim_precedes_spending(self):
        state = {"email_usuario": "a@example.invalid", "tokens_pro": 1}
        db = Mock()
        def rpc(name, params):
            self.assertTrue(state["escaneo_en_curso"])
            return SimpleNamespace(execute=lambda: SimpleNamespace(data={"remaining": 0}))
        db.rpc.side_effect = rpc
        begin_scan(state, db, "tokens_pro", "example.invalid", "Pro")
        with self.assertRaises(ScanBusy):
            begin_scan(state, db, "tokens_pro", "example.invalid", "Pro")
        self.assertEqual(db.rpc.call_count, 1)
        finish_scan(state, completed=True)
        self.assertFalse(state["escaneo_en_curso"])
        self.assertNotIn("_scan_credit_pending", state)

    def test_uncertain_rpc_retries_same_operation_without_double_debit(self):
        state, db = {"email_usuario": "a@example.invalid", "tokens_pro": 1}, Mock()
        db.rpc.return_value.execute.side_effect = [RuntimeError("lost response"), SimpleNamespace(data={"remaining": 0})]
        with self.assertRaises(RuntimeError):
            begin_scan(state, db, "tokens_pro", "example.invalid", "Pro")
        self.assertFalse(state["escaneo_en_curso"])
        begin_scan(state, db, "tokens_pro", "example.invalid", "Pro")
        self.assertEqual(db.rpc.call_args_list[0], db.rpc.call_args_list[1])
        self.assertEqual(state["tokens_pro"], 0)
        finish_scan(state)  # A motor failure retains the same operation for retry.
        self.assertEqual(pending_scan_credit(state, "example.invalid", "Pro"), "tokens_pro")

    def test_pending_spend_cannot_be_reused_for_different_target(self):
        state, db = {"email_usuario": "a@example.invalid"}, Mock()
        db.rpc.return_value.execute.side_effect = RuntimeError("lost response")
        with self.assertRaises(RuntimeError):
            begin_scan(state, db, "tokens_pro", "example.invalid", "Pro")
        with self.assertRaises(ValueError):
            begin_scan(state, db, "tokens_pro", "other.invalid", "Pro")
        self.assertEqual(db.rpc.call_count, 1)
        self.assertIsNone(pending_scan_credit(state, "other.invalid", "Pro"))

    def test_subscription_scan_does_not_spend_single_purchase(self):
        state, db = {"email_usuario": "a@example.invalid"}, Mock()
        begin_scan(state, db, None, "example.invalid", "Pro")
        db.rpc.assert_not_called()
        finish_scan(state, completed=True)
