import ast
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
from scan_reservation import service_scan_client, ScanBusy


class SchedulerReservationTests(TestCase):
    def test_adapter_uses_only_service_dispatcher_and_no_paid_credit(self):
        db=Mock()
        job=service_scan_client(db,'owner@example.invalid')
        job.rpc('billing_scan_claim',{'p_operation':'fixture','p_credit':None,
                                     'p_target':'example.invalid','p_engine':'Profundo (Active)'})
        self.assertEqual(db.rpc.call_args.args[0],'billing_scan_job')
        self.assertEqual(db.rpc.call_args.args[1]['p_action'],'claim')
        with self.assertRaises(ValueError):
            job.rpc('billing_scan_claim',{'p_operation':'fixture','p_credit':'tokens_pro'})

    def helper(self):
        tree=ast.parse(Path('scheduler.py').read_text(encoding='utf-8'))
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='ejecutar_escaneo_reservado')
        namespace={name:Mock() for name in ('supabase','service_scan_client','begin_scan',
                                          'finish_scan','run_reserved_scan','guardar_escaneo_supabase')}
        namespace['ScanBusy']=ScanBusy
        namespace['print']=Mock()
        exec(compile(ast.Module(body=[fn],type_ignores=[]),'scheduler.py','exec'),namespace)
        return namespace

    def test_busy_account_never_starts_scheduled_motor(self):
        ns=self.helper()
        ns['begin_scan'].side_effect=ScanBusy('busy')
        ns['ejecutar_escaneo_reservado']('owner@example.invalid','example.invalid','Profundo (Active)',Mock())
        ns['run_reserved_scan'].assert_not_called()
        ns['guardar_escaneo_supabase'].assert_not_called()

    def test_persistence_failure_never_confirms_consumption(self):
        ns=self.helper()
        ns['guardar_escaneo_supabase'].side_effect=RuntimeError('save failed')
        ns['ejecutar_escaneo_reservado']('owner@example.invalid','example.invalid','Profundo (Active)',Mock())
        self.assertEqual(ns['finish_scan'].call_count,1)
        self.assertNotIn('completed',ns['finish_scan'].call_args.kwargs)

    def test_scheduled_result_uses_atomic_store_helper(self):
        ns=self.helper()
        ns['guardar_escaneo_supabase'].return_value='report-fixture'
        ns['ejecutar_escaneo_reservado']('owner@example.invalid','example.invalid','Profundo (Active)',Mock())
        self.assertEqual(ns['guardar_escaneo_supabase'].call_args.args[0:3],
                         ('owner@example.invalid','example.invalid','Profundo (Active)'))
        self.assertEqual(len(ns['guardar_escaneo_supabase'].call_args.args),6)
        self.assertEqual(ns['finish_scan'].call_count,1)
