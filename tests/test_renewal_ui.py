"""Exercise the actual interface functions without network or account data."""
import ast
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import Mock


def interface(filename, state, change):
    tree = ast.parse(Path(filename).read_text(encoding='utf-8'))
    action = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_cambiar_renovacion')
    profile = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_aplicar_fila_usuario_a_sesion')
    start = next(i for i, n in enumerate(profile.body) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'confirmed' for t in n.targets))
    ui = SimpleNamespace(session_state=state, error=Mock())
    ns = {'st': ui, 'change_subscription': change, 'stripe': Mock(), 'supabase': Mock()}
    exec(compile(ast.Module(body=[action], type_ignores=[]), filename, 'exec'), ns)

    def render(profile_cancel, profile_date, email='owner@example.test'):
        state['cancelacion_pendiente'] = profile_cancel
        state['fecha_vencimiento'] = profile_date
        ns['datos'] = {'email': email, 'cancelacion_pendiente': profile_cancel,
                       'fecha_vencimiento': profile_date}
        exec(compile(ast.Module(body=profile.body[start:start + 2], type_ignores=[]), filename, 'exec'), ns)
    return ns['_cambiar_renovacion'], render, ui


class RenewalUiTests(unittest.TestCase):
    def test_cancel_and_reactivate_survive_stale_profile_without_repeating_operation(self):
        for filename in ('app.py', 'vulnscan.py'):
            for cancel in (True, False):
                state = {'email_usuario': 'owner@example.test', 'plan_activo': 'Pro',
                         'tokens_pdf': 3, 'cancelacion_pendiente': not cancel}
                change = Mock(return_value={'cancelacion_pendiente': cancel, 'fecha_vencimiento': '15/11/2026'})
                action, render, _ = interface(filename, state, change)
                self.assertTrue(action(cancel))
                for _ in range(3):
                    render(not cancel, 'old')
                    self.assertIs(state['cancelacion_pendiente'], cancel)
                    self.assertEqual(state['fecha_vencimiento'], '15/11/2026')
                self.assertEqual(change.call_count, 1)
                self.assertIs(state.pop('_renewal_notice'), cancel)
                self.assertIsNone(state.pop('_renewal_notice', None))
                render(cancel, '15/11/2026')
                self.assertNotIn('_renewal_confirmed', state)
                self.assertEqual((state['plan_activo'], state['tokens_pdf']), ('Pro', 3))

    def test_failed_operation_has_no_success_or_local_change(self):
        for filename in ('app.py', 'vulnscan.py'):
            for cancel in (True, False):
                state = {'email_usuario': 'owner@example.test', 'cancelacion_pendiente': not cancel}
                before = dict(state)
                action, _, ui = interface(filename, state, Mock(side_effect=RuntimeError('fake')))
                self.assertFalse(action(cancel))
                self.assertEqual(state, before)
                ui.error.assert_called_once()

    def test_confirmation_is_scoped_and_expires(self):
        for filename in ('app.py', 'vulnscan.py'):
            for stale in ('expired', 'other_account'):
                state = {'email_usuario': 'owner@example.test'}
                action, render, _ = interface(filename, state, Mock(return_value={
                    'cancelacion_pendiente': True, 'fecha_vencimiento': '15/11/2026'}))
                action(True)
                if stale == 'expired':
                    state['_renewal_confirmed']['expires'] = time.time() - 1
                else:
                    state['_renewal_confirmed']['email'] = 'other@example.test'
                render(False, 'server date')
                self.assertFalse(state['cancelacion_pendiente'])
                self.assertNotIn('_renewal_confirmed', state)
