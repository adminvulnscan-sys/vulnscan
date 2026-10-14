import unittest
from unittest.mock import Mock

from billing import clear_account_state
from panel_diagnostics import cached_pdf


class PrivatePdfCacheTests(unittest.TestCase):
    def test_repeat_reuses_bytes_but_changed_content_is_regenerated(self):
        state = {}
        make = Mock(return_value=b'%PDF fixture')
        cached_pdf(state, 'a', ['report', 'old', 'es'], make)
        cached_pdf(state, 'a', ['report', 'old', 'es'], make)
        self.assertEqual(make.call_count, 1)
        cached_pdf(state, 'a', ['report', 'new', 'es'], make)
        cached_pdf(state, 'a', ['report', 'new', 'en'], make)
        self.assertEqual(make.call_count, 3)

    def test_account_switch_and_logout_discard_private_bytes(self):
        state = {}
        make = Mock(return_value=b'%PDF fixture')
        cached_pdf(state, 'a', ['report'], make)
        cached_pdf(state, 'b', ['report'], make)
        self.assertEqual(make.call_count, 2)
        clear_account_state(state)
        self.assertNotIn('_panel_pdf_cache', state)

    def test_cache_is_bounded_and_failed_generation_is_not_cached(self):
        state = {}
        for i in range(40):
            cached_pdf(state, 'a', [i], lambda: b'PDF')
        self.assertEqual(len(state['_panel_pdf_cache']['items']), 32)
        make = Mock(side_effect=RuntimeError('fixture'))
        for _ in range(2):
            with self.assertRaises(RuntimeError):
                cached_pdf(state, 'a', ['broken'], make)
        self.assertEqual(make.call_count, 2)


class EagerNavigationTests(unittest.TestCase):
    def test_main_and_history_tabs_are_client_only_and_have_no_lazy_gates(self):
        import ast
        from pathlib import Path
        for filename in ('app.py', 'vulnscan.py'):
            tree = ast.parse(Path(filename).read_text(encoding='utf-8'))
            for name in ('menu_dashboard', 'sub_tab_recientes'):
                node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                            and isinstance(n.targets[0], ast.Tuple)
                            and isinstance(n.targets[0].elts[0], ast.Name)
                            and n.targets[0].elts[0].id == name)
                options = {k.arg: k.value for k in node.value.keywords}
                self.assertEqual(ast.literal_eval(options['on_change']), 'ignore')
                self.assertNotIn('key', options)
            lazy = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                    and n.attr == 'open' and isinstance(n.value, ast.Name)
                    and (n.value.id.startswith('menu_') or n.value.id.startswith('sub_tab_'))]
            self.assertFalse(lazy)
