import time
import unittest
from concurrent.futures import Future
from types import SimpleNamespace
from threading import Lock
from unittest.mock import Mock, patch

import panel_diagnostics as diagnostics
from panel_read_pipeline import PdfReadBatch, PublicFeed


class ReadPipelineTests(unittest.TestCase):
    def tearDown(self):
        diagnostics.finish_panel_trace()

    def test_reads_parallel_bounded_deduplicated_without_consumption(self):
        lock=Lock()
        active=peak=0
        def execute():
            nonlocal active, peak
            with lock:
                active+=1; peak=max(peak,active)
            time.sleep(.04)
            with lock:
                active-=1
            return SimpleNamespace(data={'authorized':True})
        client=Mock()
        client.rpc.return_value.execute.side_effect=execute
        batch=PdfReadBatch(client, lambda query, phase: query.execute())
        try:
            batch.prefetch(list(range(12))+list(range(5)))
            self.assertTrue(all(batch.read(i)['authorized'] for i in range(12)))
            self.assertEqual(client.rpc.call_count,12)
            self.assertGreater(peak,1)
            self.assertLessEqual(peak,4)
            self.assertTrue(all(c.args[1]['p_consume'] is False for c in client.rpc.call_args_list))
        finally:
            batch.close()

    def test_no_permission_survives_render_or_client_switch(self):
        first=Mock(); second=Mock()
        first.rpc.return_value.execute.return_value=SimpleNamespace(data={'authorized':True})
        second.rpc.return_value.execute.return_value=SimpleNamespace(data={'authorized':False})
        diagnostics.begin_panel_trace()
        self.assertTrue(diagnostics.pdf_read(first,'1')['authorized'])
        self.assertFalse(diagnostics.pdf_read(second,'1')['authorized'])
        diagnostics.finish_panel_trace()
        first.rpc.return_value.execute.return_value=SimpleNamespace(data={'authorized':False})
        diagnostics.begin_panel_trace()
        self.assertFalse(diagnostics.pdf_read(first,'1')['authorized'])
        self.assertEqual(first.rpc.call_count,2)

    def test_explicit_unlock_invalidates_snapshot_and_failure_is_not_authorized(self):
        client=Mock()
        client.rpc.return_value.execute.side_effect=[SimpleNamespace(data={'authorized':False}),
                                                    SimpleNamespace(data={'authorized':True}),RuntimeError('fixture')]
        diagnostics.begin_panel_trace()
        self.assertFalse(diagnostics.pdf_read(client,'1')['authorized'])
        diagnostics.invalidate_pdf_read(client,'1')
        self.assertTrue(diagnostics.pdf_read(client,'1')['authorized'])
        with self.assertRaises(RuntimeError):
            diagnostics.pdf_read(client,'2')

    def test_public_feed_reuses_only_public_data_and_retains_timeout(self):
        feed=PublicFeed()
        try:
            with patch('panel_read_pipeline.requests.get', return_value=SimpleNamespace(
                    status_code=200,json=lambda:[{'id':'public fixture'}])) as request:
                one=feed.start();self.assertEqual(one.result(),[{'id':'public fixture'}])
                self.assertIs(feed.start(),one)
                self.assertEqual(request.call_count,1)
                self.assertEqual(request.call_args.kwargs['timeout'],(3,8))
                self.assertNotIn('Authorization',request.call_args.kwargs['headers'])
        finally:
            feed.pool.shutdown()

    def test_builder_failure_is_report_local_and_does_not_authorize(self):
        client=Mock()
        client.rpc.side_effect=RuntimeError('fixture')
        batch=PdfReadBatch(client, lambda query, phase: query.execute())
        try:
            batch.prefetch(['1', '2'])
            with self.assertRaises(RuntimeError):
                batch.read('1')
            self.assertEqual(client.rpc.call_count,2)
        finally:
            batch.close()

    def test_real_postgrest_sdk_with_mock_transport_keeps_clients_isolated(self):
        import json
        import httpx
        from postgrest import SyncPostgrestClient
        requests=[]
        def endpoint(request):
            payload=json.loads(request.content)
            self.assertIs(payload['p_consume'],False)
            self.assertTrue(str(request.url).endswith('/rpc/billing_authorize_pdf'))
            owner=request.headers['Authorization']
            requests.append((owner,payload['p_report']))
            return httpx.Response(200,json={'authorized':owner=='Bearer fixture_a'})
        clients=[]
        batches=[]
        try:
            for owner in ('fixture_a','fixture_b'):
                http=httpx.Client(transport=httpx.MockTransport(endpoint),
                                  headers={'Authorization':'Bearer '+owner})
                clients.append(http)
                sdk=SyncPostgrestClient('https://example.invalid/rest/v1',http_client=http)
                batches.append(PdfReadBatch(sdk, lambda query, phase: query.execute()))
                batches[-1].prefetch(['1','2'])
            self.assertTrue(batches[0].read('1')['authorized'])
            self.assertFalse(batches[1].read('1')['authorized'])
            for batch in batches:
                batch.read('2')
            self.assertEqual(len(requests),4)
        finally:
            for batch in batches:batch.close()
            for client in clients:client.close()
