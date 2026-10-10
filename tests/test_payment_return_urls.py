import ast
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit, parse_qs

from billing import PUBLIC_APP_URL, payment_return_url


class PaymentReturnTests(unittest.TestCase):
    def test_marketing_url_does_not_control_payment_returns(self):
        with patch.dict(os.environ, {'APP_URL':'https://marketing.example.invalid'}, clear=True):
            for lang in ('es','en'):
                success=urlsplit(payment_return_url('exitoso',lang))
                self.assertEqual(success.hostname,urlsplit(PUBLIC_APP_URL).hostname)
                self.assertEqual(success.path,'/')
                self.assertEqual(parse_qs(success.query),{
                    'pago':['exitoso'],'vista':['acceso'],'lang':[lang],
                    'session_id':['{CHECKOUT_SESSION_ID}']})
                self.assertNotIn('session_id',parse_qs(urlsplit(payment_return_url('cancelado',lang)).query))

    def test_explicit_local_override_and_no_double_slash(self):
        for base in ('http://localhost:8519','http://localhost:8519/'):
            with patch.dict(os.environ,{'BILLING_RETURN_URL':base}):
                result=urlsplit(payment_return_url())
                self.assertEqual(result.path,'/')
                self.assertEqual(result.port,8519)
                self.assertNotIn('pago',parse_qs(result.query))

    def test_invalid_configuration_rejected_before_checkout(self):
        for base in ('https://example.invalid/?vista=acceso','https://user:pass@example.invalid',
                     'javascript:alert(1)','http://remote.invalid','https://example.invalid/~/+/',
                     'https://example.invalid/#frag','https://example.invalid:broken',''):
            with self.subTest(base=base),patch.dict(os.environ,{'BILLING_RETURN_URL':base}):
                with self.assertRaises(ValueError):payment_return_url('exitoso')

    def test_return_keeps_access_and_language_and_never_grants(self):
        for filename in ('app.py','vulnscan.py'):
            tree=ast.parse(Path(filename).read_text(encoding='utf-8'))
            branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If)
                        and ast.unparse(n.test)=="pago_param == 'exitoso'")
            ui=SimpleNamespace(session_state={'usuario_autenticado':False,'tokens_pdf':1},
                query_params={'pago':'exitoso','session_id':'unverified','lang':'en'},
                warning=Mock(),info=Mock())
            refresh=Mock()
            exec(compile(ast.Module(body=[branch],type_ignores=[]),filename,'exec'),
                 {'st':ui,'pago_param':'exitoso','_confirmar_compra_pdf_tras_stripe':refresh})
            self.assertEqual(ui.query_params,{'vista':'acceso','lang':'en'})
            self.assertEqual(ui.session_state['tokens_pdf'],1)
            refresh.assert_not_called()
