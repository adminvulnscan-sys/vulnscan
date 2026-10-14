import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import panel_diagnostics as diagnostics


class PanelTraceTests(unittest.TestCase):
    def tearDown(self):
        diagnostics._trace.set(None)

    def test_summary_attributes_query_time_and_excludes_payloads(self):
        diagnostics.begin_panel_trace()
        private = Mock()
        private.execute.return_value = {'private': 'SECRET email@example.invalid'}
        with diagnostics.measure_panel('reports'):
            self.assertIs(diagnostics.panel_execute(private, 'supabase.billing_authorize_pdf'),
                          private.execute.return_value)
        diagnostics.panel_count('history_reports', 25)
        with self.assertLogs('vulnscan.panel') as logs:
            result = diagnostics.finish_panel_trace()
        self.assertEqual(result['phases']['supabase.billing_authorize_pdf']['calls'], 1)
        self.assertEqual(result['counts']['history_reports'], 25)
        self.assertIn('operation=panel_profile_summary', logs.output[0])
        self.assertNotIn('SECRET', logs.output[0])
        self.assertNotIn('email@example.invalid', logs.output[0])
        json.dumps(result)

    def test_query_failure_still_measured_and_preserved(self):
        diagnostics.begin_panel_trace()
        error = RuntimeError('private fixture')
        query = Mock()
        query.execute.side_effect = error
        with self.assertRaises(RuntimeError) as raised:
            diagnostics.panel_execute(query, 'supabase.query')
        self.assertIs(raised.exception, error)
        self.assertEqual(diagnostics.finish_panel_trace()['phases']['supabase.query']['calls'], 1)

    def test_parallel_sessions_have_independent_traces(self):
        def session(count):
            diagnostics.begin_panel_trace()
            diagnostics.panel_count('history_reports', count)
            return diagnostics.finish_panel_trace()
        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = list(pool.map(session, [2, 50]))
        self.assertNotEqual(first['run'], second['run'])
        self.assertEqual([first['counts']['history_reports'], second['counts']['history_reports']], [2, 50])
