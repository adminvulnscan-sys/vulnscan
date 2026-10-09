import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import billing
import stripe_navigation as navigation
from test_billing import client, stripe_mock

INTENT = '00000000-0000-4000-8000-000000000099'


class Rerun(BaseException):
    pass


class NavigationTests(unittest.TestCase):
    def action(self, ui, create, errors, scope='account:pdf'):
        return navigation.stripe_action(ui, label='Buy', key='buy', scope=scope,
                                       create=create, on_error=errors)

    def ui(self, clicked=False):
        return SimpleNamespace(session_state={}, button=Mock(return_value=clicked),
                               error=Mock(), rerun=Mock(side_effect=Rerun))

    @patch.object(navigation, 'intent_bridge', return_value=SimpleNamespace(intent=INTENT))
    def test_render_reload_and_language_never_create(self, bridge):
        ui, create, errors = self.ui(), Mock(), Mock()
        for lang in ('es', 'en', 'es'):
            ui.session_state['_vs_lang'] = lang
            self.action(ui, create, errors)
        create.assert_not_called()

    @patch.object(navigation, 'intent_bridge', return_value=SimpleNamespace(intent=INTENT))
    def test_one_click_redirect_and_double_click_reuses_attempt(self, bridge):
        ui, create, errors = self.ui(True), Mock(return_value='https://checkout.stripe.com/test'), Mock()
        for _ in range(2):
            with self.assertRaises(Rerun):
                self.action(ui, create, errors)
        self.assertEqual(create.call_args_list[0], create.call_args_list[1])
        ui.button.return_value = False
        self.action(ui, create, errors)
        self.assertEqual(create.call_count, 2)
        self.assertEqual(bridge.call_args.kwargs['data']['url'], create.return_value)
        errors.assert_not_called()

    @patch.object(navigation, 'intent_bridge', return_value=SimpleNamespace(intent=INTENT))
    def test_error_retry_preserves_attempt_and_rejects_unapproved_url(self, bridge):
        ui, errors = self.ui(True), Mock()
        create = Mock(side_effect=[RuntimeError('private'), 'https://evil.invalid'])
        self.action(ui, create, errors)
        self.action(ui, create, errors)
        self.assertEqual(create.call_args_list[0], create.call_args_list[1])
        self.assertEqual(errors.call_count, 2)
        ui.rerun.assert_not_called()
        self.assertTrue(bridge.call_args.kwargs['data']['failed'])
        self.assertNotIn('_stripe_redirect_buy', ui.session_state)

    @patch.object(navigation, 'intent_bridge', return_value=SimpleNamespace(intent=INTENT))
    def test_completed_attempt_rotates_only_on_explicit_click(self, bridge):
        ui, errors = self.ui(True), Mock()
        create = Mock(side_effect=[billing.CheckoutIntentClosed(), 'https://checkout.stripe.com/new'])
        with self.assertRaises(Rerun):
            self.action(ui, create, errors)
        self.assertNotEqual(create.call_args_list[0], create.call_args_list[1])
        self.assertIn('rotate', ui.session_state['_stripe_redirect_buy'])

    @patch.object(navigation, 'intent_bridge', return_value=SimpleNamespace(intent=None))
    def test_button_waits_for_browser_intent(self, bridge):
        ui, create, errors = self.ui(), Mock(), Mock()
        self.action(ui, create, errors)
        self.assertTrue(ui.button.call_args.kwargs['disabled'])
        create.assert_not_called()

    def test_checkout_idempotency_binds_user_product_and_preserves_contract(self):
        tree = ast.parse(Path('app.py').read_text(encoding='utf-8'))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name=='generar_link_pago')
        db, stripe = client(), stripe_mock()
        db.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [{}]
        stripe.checkout.Session.create.return_value = SimpleNamespace(url='https://checkout.stripe.com/test', status='open')
        ns = dict(stripe=stripe, supabase=db, authenticated_user=billing.authenticated_user,
                  STRIPE_PRICES={'pdf_unico':'price_test'}, os=__import__('os'),
                  stripe_idempotency=billing.stripe_idempotency, CheckoutIntentClosed=billing.CheckoutIntentClosed)
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'app.py', 'exec'), ns)
        for _ in range(2):
            ns['generar_link_pago']('price_test','a@example.test','pdf_unico','payment',INTENT)
        calls = stripe.checkout.Session.create.call_args_list
        self.assertEqual(calls[0],calls[1])
        self.assertNotIn('payment_method_types',calls[0].kwargs)
        self.assertEqual(calls[0].kwargs['metadata']['user_id'],'a')
        self.assertEqual(calls[0].kwargs['line_items'],[{'price':'price_test','quantity':1}])
        self.assertNotEqual(billing.stripe_idempotency('a',INTENT,{}),billing.stripe_idempotency('b',INTENT,{}))
        self.assertNotEqual(billing.stripe_idempotency('a',INTENT,{'price':'a'}),billing.stripe_idempotency('a',INTENT,{'price':'b'}))
        stripe.checkout.Session.create.return_value.status='complete'
        with self.assertRaises(billing.CheckoutIntentClosed):
            ns['generar_link_pago']('price_test','a@example.test','pdf_unico','payment',INTENT)
        db.table.return_value.update.assert_not_called()

    def test_logout_removes_pending_navigation_only(self):
        state={'_stripe_redirect_buy':{'url':'private'},'_vs_lang':'en','theme':'dark'}
        billing.clear_account_state(state)
        self.assertNotIn('_stripe_redirect_buy',state)
        self.assertEqual(state['_vs_lang'],'en')

    def test_portal_idempotent_and_authenticated(self):
        stripe, db = stripe_mock(), client()
        for _ in range(2):
            billing.customer_portal(stripe,db,'a@example.test','https://example.invalid',INTENT)
        calls=stripe.billing_portal.Session.create.call_args_list
        self.assertEqual(calls[0],calls[1])
        with self.assertRaises(ValueError):
            billing.customer_portal(stripe,db,'other@example.test','https://example.invalid',INTENT)
        self.assertEqual(stripe.billing_portal.Session.create.call_count,2)
