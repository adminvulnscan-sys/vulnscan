import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock
from billing_sync import start_wait, poll, monitor
from billing import clear_account_state

NOW = 1800000000


def setup():
    state = {'usuario_autenticado': True, 'email_usuario': 'owner@example.test',
             'plan_activo': 'Basic', 'tokens_pro': 0, 'tokens_ent': 0, 'tokens_pdf': 0}
    profile = {'email': state['email_usuario'], 'plan_activo': 'Basic',
               'billing_status': None, 'billing_period_end': None,
               'fecha_vencimiento': None, 'cancelacion_pendiente': False,
               'tokens_pro': 0, 'tokens_ent': 0, 'tokens_pdf': 0}
    result = {'profile': profile, 'checkout_applied': False}
    client = Mock()
    client.auth.get_user.return_value.user = SimpleNamespace(email=profile['email'], id='test-user')
    def rpc(name, args):
        return SimpleNamespace(execute=lambda: SimpleNamespace(data=(deepcopy(result)
            if name == 'billing_sync_status' else {})))
    client.rpc.side_effect = rpc
    return state, client, result


class BillingSyncTests(unittest.TestCase):
    def test_open_session_fragment_refreshes_whole_app_and_shows_processing(self):
        state, db, server = setup()
        start_wait(state, state['email_usuario'], 'cs_test_fragment')
        ui = SimpleNamespace(session_state=state, rerun=Mock(), success=Mock(), info=Mock())
        ui.fragment = Mock(side_effect=lambda **kwargs: lambda fn: fn)
        monitor(ui, db)
        ui.fragment.assert_called_once_with(run_every='5s')
        ui.rerun.assert_called_once_with(scope='app')
        ui.info.assert_called_once()
        ui.success.assert_not_called()

    def test_return_does_not_grant_and_exact_receipt_confirms_credit_without_increment(self):
        state, db, server = setup()
        start_wait(state, state['email_usuario'], 'cs_test_purchase', NOW)
        poll(state, db, NOW)
        self.assertEqual(state['tokens_pdf'], 0)
        self.assertEqual(state['_billing_sync_status'], 'processing')
        server['profile']['tokens_pdf'] = 1
        poll(state, db, NOW+5)
        self.assertEqual(state['_billing_sync_status'], 'processing')
        server['checkout_applied'] = True
        poll(state, db, NOW+10)
        self.assertEqual(state['_billing_sync_status'], 'confirmed')
        for now in (NOW+15, NOW+45, NOW+80):
            poll(state, db, now)
        self.assertEqual(state['tokens_pdf'], 1)
        db.table.assert_not_called()

    def test_open_session_renewal_and_failed_payment_update_without_checkout(self):
        state, db, server = setup()
        poll(state, db, NOW)
        server['profile'].update(plan_activo='Pro', billing_status='active', billing_period_end=NOW+3600)
        self.assertTrue(poll(state, db, NOW+30))
        self.assertEqual(state['plan_activo'], 'Pro')
        server['profile'].update(billing_status='past_due')
        self.assertTrue(poll(state, db, NOW+60))
        self.assertEqual(state['plan_activo'], 'Basic')

    def test_all_credit_types_and_enterprise_are_copied_from_server(self):
        state, db, server = setup()
        server['profile'].update(tokens_pro=2, tokens_ent=3, tokens_pdf=4,
            plan_activo='Enterprise', billing_status='active', billing_period_end=NOW+1000)
        poll(state, db, NOW)
        self.assertEqual([state[k] for k in ('tokens_pro','tokens_ent','tokens_pdf')], [2,3,4])
        self.assertEqual(state['plan_activo'], 'Enterprise')

    def test_timeout_limits_exact_receipt_polling_and_never_shows_success(self):
        state, db, server = setup()
        start_wait(state, state['email_usuario'], 'cs_test_wait', NOW)
        start_wait(state, state['email_usuario'], 'cs_test_wait', NOW+60)
        self.assertEqual(state['_billing_wait']['deadline'], NOW+120)
        poll(state, db, NOW+121)
        self.assertEqual(state['_billing_sync_status'], 'timeout')
        self.assertNotIn('_billing_wait', state)
        self.assertIsNone(db.rpc.call_args_list[0].args[1]['p_checkout'])

    def test_missing_rpc_or_bad_identity_never_confirms(self):
        for failure in ('rpc', 'identity'):
            state, db, server = setup()
            start_wait(state, state['email_usuario'], 'cs_test_bad', NOW)
            server.update(checkout_applied=True)
            if failure == 'rpc':
                db.rpc.side_effect = RuntimeError('private')
            else:
                server['profile']['email'] = 'other@example.test'
            poll(state, db, NOW)
            self.assertEqual(state['_billing_sync_status'], 'processing')
            self.assertEqual(state['tokens_pdf'], 0)

    def test_confirmed_cancel_and_reactivate_not_overwritten_by_delayed_webhook(self):
        for cancel in (True, False):
            state, db, server = setup()
            server['profile']['cancelacion_pendiente'] = not cancel
            state['_renewal_confirmed'] = {'email':state['email_usuario'],
                'cancelacion_pendiente':cancel,'fecha_vencimiento':'15/11/2026','expires':NOW+120}
            poll(state, db, NOW)
            self.assertIs(state['cancelacion_pendiente'], cancel)
            self.assertEqual(state['fecha_vencimiento'], '15/11/2026')

    def test_logout_clears_all_monitor_state(self):
        state, db, server = setup()
        start_wait(state, state['email_usuario'], 'cs_test_logout', NOW)
        poll(state, db, NOW)
        clear_account_state(state)
        self.assertFalse(any(k.startswith('_billing_') for k in state))
        db.reset_mock()
        poll(state, db, NOW+30)
        db.rpc.assert_not_called()

    def test_new_account_cannot_confirm_previous_accounts_checkout(self):
        state, db, server = setup()
        start_wait(state, 'previous@example.test', 'cs_test_old', NOW)
        poll(state, db, NOW)
        self.assertNotIn('_billing_wait', state)
        self.assertNotEqual(state.get('_billing_sync_status'), 'confirmed')
