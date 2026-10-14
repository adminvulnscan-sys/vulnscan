import ast
from pathlib import Path
from panel_diagnostics import panel_execute, measure_panel
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from billing import begin_scan, finish_scan, pending_scan_credit, ScanBusy


class CreditFlowTests(TestCase):
    def test_dashboard_credit_purchase_and_durable_right_routes(self):
        for filename in ("app.py", "vulnscan.py"):
            tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
            calculate = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                             and n.name == "_calcular_derecho_pdf")
            gate = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "tiene_derecho_pdf" for t in n.targets))
            for credits, server_right, expected in [(1, False, True), (0, False, False), (0, True, True)]:
                state = {"plan_activo": "Basic", "tokens_pdf": credits,
                         "escaneo_actual_id": "42", "reporte_pdf_desbloqueado": "another-report"}
                server = Mock(return_value=server_right)
                ns = {"st": SimpleNamespace(session_state=state), "_pdf_desbloqueado_servidor": server}
                exec(compile(ast.Module(body=[calculate], type_ignores=[]), filename, "exec"), ns)
                state["pdf_descarga_habilitada"] = ns["_calcular_derecho_pdf"]("Rápido (Passive)")
                exec(compile(ast.Module(body=[gate], type_ignores=[]), filename, "exec"), ns)
                self.assertEqual(ns["tiene_derecho_pdf"], expected)
                if credits == 0:
                    server.assert_called_once_with("42")

    def pdf_function(self, filename, state, response, clicked=False):
        tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_descargar_pdf_seguro")
        db = Mock()
        db.rpc.return_value.execute.side_effect = [SimpleNamespace(data=r) for r in response]
        ui = SimpleNamespace(session_state=state, button=Mock(return_value=clicked),
                             download_button=Mock(return_value=True), warning=Mock())
        namespace = {"st": ui, "supabase": db, "panel_execute": panel_execute, "measure_panel": measure_panel}
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

    def test_begin_reserves_on_server_without_spending(self):
        state = {"email_usuario": "a@example.invalid", "tokens_pro": 1}
        db = Mock()
        db.rpc.return_value.execute.return_value = SimpleNamespace(data={"status": "reserved", "remaining": 1})
        begin_scan(state, db, "tokens_pro", "example.invalid", "Profundo (Active)")
        self.assertEqual(db.rpc.call_args.args[0], "billing_scan_claim")
        self.assertEqual(state["tokens_pro"], 1)
        with self.assertRaises(ScanBusy):
            begin_scan(state, db, "tokens_pro", "example.invalid", "Profundo (Active)")
        self.assertEqual(db.rpc.call_count, 1)

    def test_finish_requires_persisted_report_and_server_confirmation(self):
        state = {"email_usuario": "a@example.invalid", "tokens_pro": 1}
        db = Mock()
        db.rpc.return_value.execute.side_effect = [SimpleNamespace(data={"status": "reserved", "remaining": 1}),
            SimpleNamespace(data={"status": "completed", "remaining": 0})]
        begin_scan(state, db, "tokens_pro", "example.invalid", "Profundo (Active)")
        finish_scan(state, db, completed=True, report_id="42")
        self.assertEqual(db.rpc.call_args.args[0], "billing_scan_complete")
        self.assertEqual(state["tokens_pro"], 0)
        self.assertNotIn("_scan_credit_pending", state)
