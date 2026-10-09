from pathlib import Path
import unittest
import ast
from collections import Counter
from streamlit.testing.v1 import AppTest

ROOT=Path(__file__).resolve().parents[1]
PREVIEW=ROOT/'tests/preview_private_panel.py'

class PanelControlsTests(unittest.TestCase):
    def test_all_ten_purchase_routes_preserve_prices_types_and_modes(self):
        import subprocess
        original=subprocess.check_output(['git','show','e83f80dc0c690e6fb485dd004334eeed00611065:app.py'],cwd=ROOT).decode('utf-8')
        old=ast.parse(original)
        new=ast.parse((ROOT/'app.py').read_text(encoding='utf-8'))
        def calls(tree,name):
            return Counter(tuple(ast.dump(arg,include_attributes=False) for arg in node.args[:4])
                for node in ast.walk(tree) if isinstance(node,ast.Call)
                and isinstance(node.func,ast.Name) and node.func.id==name)
        before=calls(old,'generar_link_pago')
        after=calls(new,'_purchase_button')
        self.assertEqual(sum(before.values()),10)
        # Preserve all original routes and add exactly one standalone PDF-credit entry.
        extras = after - before
        self.assertEqual(sum(extras.values()), 1)
        self.assertEqual(before - after, Counter())
        extra_args = next(iter(extras))
        self.assertIn("pdf_unico", extra_args[0])
        self.assertIn("pdf_unico", extra_args[2])
        self.assertIn("payment", extra_args[3])

    def test_render_and_language_do_not_create_checkout(self):
        app=AppTest.from_file(str(PREVIEW),default_timeout=20).run()
        self.assertFalse(app.exception)
        for lang in ('en','es'):
            app.session_state['_vs_lang']=lang
            app.run()
            self.assertFalse(app.exception)
            self.assertEqual(app.session_state['dominio_actual'],'guardado.example.invalid')
        self.assertNotIn('preview_checkouts',app.session_state)
        self.assertFalse(any(button.label in ('ES','EN') for button in app.button))

    def test_explicit_purchase_uses_real_checkout_controller(self):
        app=AppTest.from_file(str(PREVIEW),default_timeout=20).run()
        button=next(b for b in app.button if b.label.strip()=='Comprar Escaneo Único (39€)')
        button.click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state['preview_checkouts'],1)

    def test_standalone_pdf_credit_without_scan_is_explicit_purchase(self):
        app=AppTest.from_file(str(PREVIEW),default_timeout=20).run()
        app.checkbox[0].uncheck().run()
        self.assertFalse(app.exception)
        button=next(b for b in app.button if b.key=='purchase_pdf_credit_standalone')
        self.assertNotIn('preview_checkouts',app.session_state)
        self.assertTrue(any('No incluye un escaneo' in c.value for c in app.caption))
        button.click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state['preview_checkouts'],1)
        app.run()
        self.assertEqual(app.session_state['preview_checkouts'],1)
        app.run()
        self.assertEqual(app.session_state['preview_checkouts'],1)

    def test_missing_schema_safe_error_and_secret_free_log(self):
        app=AppTest.from_file(str(PREVIEW),default_timeout=20).run()
        app.checkbox(key='preview_schema_missing').check().run()
        button=next(b for b in app.button if b.label.strip()=='Comprar Escaneo Único (39€)')
        with self.assertLogs('vulnscan.billing',level='WARNING') as captured:
            button.click().run()
        self.assertFalse(app.exception)
        self.assertNotIn('preview_checkouts',app.session_state)
        messages=' '.join(error.value for error in app.error)
        self.assertNotIn('stripe_customer_id',messages)
        self.assertNotIn('42703',messages)
        self.assertNotIn('private-token-never-log',' '.join(captured.output))
        self.assertIn('42703',' '.join(captured.output))

if __name__=='__main__':unittest.main()
