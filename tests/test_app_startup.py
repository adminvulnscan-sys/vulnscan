"""Run the complete entry point in a fresh process, with remote access blocked."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = r'''
import os, sys, subprocess, types
from pathlib import Path
from unittest.mock import Mock, patch
from contextlib import ExitStack
os.environ['STREAMLIT_BROWSER_GATHER_USAGE_STATS'] = 'false'
from streamlit.testing.v1 import AppTest
import streamlit as st

stale = sys.argv[1] == 'stale'
if stale:
    source = subprocess.check_output(['git', 'show', 'dcc1c0d:billing.py']).decode('utf-8')
    old = types.ModuleType('billing')
    old.__file__ = str(Path('billing.py').resolve())
    exec(compile(source, old.__file__, 'exec'), old.__dict__)
    assert not hasattr(old, 'payment_return_url')
    sys.modules['billing'] = old
    original_exception = old.CheckoutIntentClosed

db = Mock()
db.table.side_effect = AssertionError('Unexpected database operation')
db.rpc.side_effect = AssertionError('Unexpected database operation')
db.auth.get_user.side_effect = AssertionError('Unexpected authentication operation')
with ExitStack() as stack:
    stack.enter_context(patch.dict(os.environ, {
        'SUPABASE_URL':'https://example.invalid', 'SUPABASE_KEY':'sb_publishable_fixture',
        'STRIPE_SECRET_KEY':'sk_test_fixture', 'BILLING_RETURN_URL':'http://localhost:8519',
    }))
    stack.enter_context(patch('dotenv.load_dotenv', return_value=False))
    factory = stack.enter_context(patch('supabase.create_client', return_value=db))
    checkout = stack.enter_context(patch('stripe.checkout.Session.create', side_effect=AssertionError('Unexpected Checkout')))
    stack.enter_context(patch('requests.sessions.Session.request', side_effect=AssertionError('Unexpected HTTP')))
    stack.enter_context(patch('httpx.Client.send', side_effect=AssertionError('Unexpected HTTP')))
    stack.enter_context(patch('socket.socket.connect', side_effect=AssertionError('Unexpected network')))
    app = AppTest.from_file(sys.argv[2], default_timeout=25)
    app.query_params['vista'] = 'acceso'
    app.query_params['lang'] = 'es'
    app.run()
    if app.exception:
        print('STARTUP_EXCEPTION:', '; '.join(str(x.message) for x in app.exception))
        raise SystemExit(1)
    assert any(x.label == 'Email Corporativo' for x in app.text_input)
    assert any(x.label == 'Contraseña' for x in app.text_input)
    checkout.assert_not_called()
    db.table.assert_not_called()
    db.rpc.assert_not_called()
    db.auth.get_user.assert_not_called()
    factory.assert_called_once()
    if stale:
        assert sys.modules['billing'] is old
        assert old.CheckoutIntentClosed is original_exception
    print('FULL_STARTUP_OK: actual login rendered; no remote operations; ' + sys.argv[1])
'''


class AppStartupTests(unittest.TestCase):
    def run_startup(self, mode, entry):
        result = subprocess.run([sys.executable, '-c', SCRIPT, mode, entry], cwd=ROOT,
                                capture_output=True, text=True, encoding='utf-8', timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('FULL_STARTUP_OK', result.stdout)

    def test_complete_app_startup(self):
        self.run_startup('fresh', 'app.py')

    def test_app_with_pre_update_billing_cached(self):
        self.run_startup('stale', 'app.py')

    def test_vulnscan_with_pre_update_billing_cached(self):
        self.run_startup('stale', 'vulnscan.py')
