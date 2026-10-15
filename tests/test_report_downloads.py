import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from report_downloads import deferred_report


class DeferredReportTests(unittest.TestCase):
    def client(self, email='owner@example.invalid', authorized=True):
        client=Mock()
        client.auth.get_user.return_value.user=SimpleNamespace(email=email,id='fixture')
        client.rpc.return_value.execute.return_value=SimpleNamespace(data={'authorized':authorized})
        client.table.return_value.select.return_value.eq.return_value.eq.return_value.limit.return_value.execute.return_value=SimpleNamespace(data=[{'id':7,'email_cliente':email}])
        return client

    def test_register_429_reports_does_not_query_or_generate_documents(self):
        client=self.client(); factory=Mock(return_value=b'%PDF fixture')
        actions=[deferred_report(client,'owner@example.invalid',{'id':i},factory) for i in range(429)]
        client.rpc.assert_not_called(); client.auth.get_user.assert_not_called()
        factory.assert_not_called()
        client.table.return_value.select.return_value.eq.return_value.eq.return_value.limit.return_value.execute.return_value=SimpleNamespace(data=[{'id':428,'email_cliente':'owner@example.invalid'}])
        self.assertEqual(actions[428](),b'%PDF fixture')
        self.assertEqual(client.rpc.call_args.args[1],{'p_report':'428','p_consume':False})
        self.assertEqual(factory.call_args.args[0]['id'],428)

    def test_repeated_download_always_checks_server_without_consuming(self):
        client=self.client();factory=Mock(return_value=b'%PDF fixture')
        download=deferred_report(client,'owner@example.invalid',{'id':7},factory)
        download();download()
        self.assertEqual(client.rpc.call_count,2)
        client.rpc.return_value.execute.return_value=SimpleNamespace(data={'authorized':False})
        with self.assertRaises(RuntimeError):download()
        self.assertEqual(factory.call_count,2)

    def test_wrong_account_or_server_failure_never_generates_pdf(self):
        for client in (self.client(email='other@example.invalid'),self.client(authorized=False)):
            factory=Mock()
            with self.assertRaises(RuntimeError):
                deferred_report(client,'owner@example.invalid',{'id':7},factory)()
            factory.assert_not_called()

    def test_error_message_does_not_expose_server_details(self):
        client=self.client();client.rpc.side_effect=RuntimeError('PRIVATE_SENTINEL')
        with self.assertRaises(RuntimeError) as error:
            deferred_report(client,'owner@example.invalid',{'id':7},Mock())()
        self.assertNotIn('PRIVATE_SENTINEL',str(error.exception))

    def test_loaded_row_must_match_both_report_and_owner(self):
        for row in ({'id':8,'email_cliente':'owner@example.invalid'},
                    {'id':7,'email_cliente':'other@example.invalid'}):
            client=self.client();factory=Mock()
            client.table.return_value.select.return_value.eq.return_value.eq.return_value.limit.return_value.execute.return_value=SimpleNamespace(data=[row])
            with self.assertRaises(RuntimeError):
                deferred_report(client,'owner@example.invalid',{'id':7},factory)()
            factory.assert_not_called()
