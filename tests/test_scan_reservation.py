"""Simulation of the RPC contract, not a PostgreSQL execution test."""
from concurrent.futures import ThreadPoolExecutor
from threading import RLock, Barrier
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
import time

from scan_reservation import begin_scan, finish_scan, heartbeat, run_reserved_scan, store_scan, ScanBusy
from copy import deepcopy


class Server:
    def __init__(self):
        self.lock = RLock()
        self.now = 0
        self.balances = {'a': 2, 'b': 2}
        self.pdf_balances = {'a': 1, 'b': 1}
        self.runs = {}
        self.reports = {}
        self.debits = set()
        self.calls = []
        self.lost = None
        self.fail_save = False
        self.fail_complete = False

    def client(self, user='a'):
        def rpc(name, params):
            return SimpleNamespace(execute=lambda: SimpleNamespace(data=self.execute(user, name, params)))
        return SimpleNamespace(rpc=rpc)

    def execute(self, user, name, p):
        with self.lock:
            self.calls.append(name)
            op = p['p_operation']
            key = (user, op)
            r = self.runs.get(key)
            if name == 'billing_spend':
                balance = self.pdf_balances if p['p_credit']=='tokens_pdf' else self.balances
                held = sum(1 for (owner, _), row in self.runs.items() if owner==user
                           and row['state']=='reserved' and row['until']>self.now and row['credit']==p['p_credit'])
                if key not in self.debits:
                    if balance[user]-held<=0: raise ValueError('Insufficient available credits')
                    balance[user]-=1
                    self.debits.add(key)
                return {'remaining': balance[user]}
            if name == 'billing_scan_claim':
                for (owner, _), row in self.runs.items():
                    if owner == user and row['state'] == 'reserved' and row['until'] <= self.now:
                        row['state'] = 'expired'
                if any(owner == user and other != op and row['state'] == 'reserved'
                       for (owner, other), row in self.runs.items()):
                    return {'status': 'busy'}
                if r and r['state'] == 'completed':
                    return {'status': 'completed'}
                if p['p_credit'] and self.balances[user] < 1:
                    raise ValueError('Insufficient credits')
                if r and r['target'] != p['p_target']:
                    raise ValueError('Operation conflict')
                hard=r['hard'] if r and r['state']=='reserved' else self.now+3600
                self.runs[key] = {'state': 'reserved', 'until': min(self.now+300,hard),'hard':hard,
                                  'target': p['p_target'], 'credit': p['p_credit']}
                result = {'status': 'reserved', 'remaining': self.balances[user]}
            elif name == 'billing_scan_heartbeat':
                if not r or r['state'] != 'reserved' or r['until'] <= self.now:
                    return {'status': 'expired'}
                r['until'] = min(self.now+300,r['hard'])
                result = {'status': 'reserved'}
            elif name == 'billing_scan_abort':
                if not r:
                    return {'status': 'missing'}
                if r['state'] == 'reserved':
                    r['state'] = 'failed'
                result = {'status': r['state'], 'remaining': self.balances[user]}
            elif name == 'billing_scan_store':
                if r and r['state']=='completed':
                    return {'status':'completed','report_id':r['report'],'remaining':self.balances[user]}
                if not r or r['state']!='reserved' or r['until']<=self.now:
                    return {'status':'expired'}
                snapshot=deepcopy((self.runs,self.reports,self.balances,self.debits))
                report='report-'+str(len(self.reports)+1)
                try:
                    if self.fail_save: raise RuntimeError('Persistence failed')
                    self.reports[report]=user
                    result=self.execute(user,'billing_scan_complete',{'p_operation':op,'p_report':report})
                    result['report_id']=report
                except Exception:
                    self.runs,self.reports,self.balances,self.debits=snapshot
                    raise
            elif name == 'billing_scan_complete':
                if self.fail_complete: raise RuntimeError('Completion failed')
                if not r or self.reports.get(p['p_report']) != user:
                    raise ValueError('Persisted own report required')
                if r['state'] == 'completed':
                    if r['report'] != p['p_report']:
                        raise ValueError('Report conflict')
                else:
                    if r['state'] not in ('reserved', 'expired') or any(
                        owner == user and other != op and row['state'] == 'reserved'
                        for (owner, other), row in self.runs.items()):
                        raise ValueError('Reservation superseded')
                    if r['credit'] and key not in self.debits:
                        if self.balances[user] <= 0:
                            raise ValueError('Insufficient credits')
                        self.balances[user] -= 1
                        self.debits.add(key)
                    r.update(state='completed', report=p['p_report'])
                result = {'status': 'completed', 'remaining': self.balances[user]}
            else:
                raise AssertionError(name)
            if self.lost == name:
                self.lost = None
                raise ConnectionError('Simulated lost response')
            return result


class ScanReservationTests(TestCase):
    def setUp(self):
        self.server = Server()
        self.db = self.server.client()
        self.state = {'email_usuario': 'a@example.invalid', 'tokens_pro': 2}

    def start(self, state=None, db=None, credit='tokens_pro'):
        begin_scan(self.state if state is None else state, db or self.db,
                   credit, 'example.invalid', 'Profundo (Active)')

    def complete(self, report='report', state=None):
        self.server.reports[report] = 'a'
        finish_scan(self.state if state is None else state, self.db, completed=True, report_id=report)

    def test_two_sessions_racing_only_one_is_admitted_before_any_debit(self):
        barrier = Barrier(2)
        def start():
            state = dict(self.state)
            barrier.wait()
            try:
                self.start(state)
                return 'reserved'
            except ScanBusy:
                return 'busy'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: start(), range(2)))
        self.assertCountEqual(results, ['reserved', 'busy'])
        self.assertEqual(self.server.balances['a'], 2)
        self.assertFalse(self.server.debits)

    def test_local_busy_does_not_call_rpc(self):
        self.state['escaneo_en_curso'] = True
        with self.assertRaises(ScanBusy): self.start()
        self.assertFalse(self.server.calls)

    def test_failure_releases_hold_and_keeps_balance(self):
        self.start()
        finish_scan(self.state, self.db)
        self.assertEqual(self.server.balances['a'], 2)
        self.assertNotIn('_scan_credit_pending', self.state)
        self.start()

    def test_lost_claim_response_reuses_operation_without_debit(self):
        self.server.lost = 'billing_scan_claim'
        with self.assertRaises(ConnectionError): self.start()
        op = self.state['_scan_credit_pending']['operation']
        self.start()
        self.assertEqual(self.state['_scan_credit_pending']['operation'], op)
        self.assertEqual(len(self.server.runs), 1)
        self.assertEqual(self.server.balances['a'], 2)

    def test_lost_completion_response_retry_charges_exactly_once(self):
        self.start()
        self.server.lost = 'billing_scan_complete'
        with self.assertRaises(ConnectionError): self.complete()
        finish_scan(self.state, self.db)  # finally must not abort an uncertain completion.
        self.assertEqual(self.server.balances['a'], 1)
        self.complete()
        self.assertEqual(self.server.balances['a'], 1)
        self.assertEqual(len(self.server.debits), 1)

    def test_recover_completion_before_starting_another_engine(self):
        self.start()
        self.server.lost = 'billing_scan_complete'
        with self.assertRaises(ConnectionError): self.complete()
        with self.assertRaises(ScanBusy): self.start()
        self.assertEqual(self.server.balances['a'], 1)
        self.assertNotIn('_scan_credit_pending', self.state)

    def test_expired_hold_allows_new_session_stale_worker_is_fenced(self):
        self.start()
        self.server.now = 301
        newer = dict(email_usuario='a@example.invalid', tokens_pro=2)
        self.start(newer)
        with self.assertRaises(ValueError): heartbeat(self.state, self.db)
        with self.assertRaises(ValueError): self.complete()
        self.assertEqual(self.server.balances['a'], 2)
        self.complete('newer-report', newer)
        self.assertEqual(self.server.balances['a'], 1)

    def test_heartbeat_extends_live_hold(self):
        self.start()
        self.server.now = 200
        heartbeat(self.state, self.db)
        self.server.now = 350
        with self.assertRaises(ScanBusy): self.start(dict(email_usuario='a@example.invalid'))

    def test_other_account_is_independent_and_cannot_complete_our_report(self):
        self.start()
        other = dict(email_usuario='b@example.invalid')
        self.start(other, self.server.client('b'))
        self.server.reports['report'] = 'a'
        with self.assertRaises(ValueError):
            finish_scan(other, self.server.client('b'), completed=True, report_id='report')
        self.assertEqual(self.server.balances, {'a': 2, 'b': 2})

    def test_subscription_or_passive_scan_does_not_consume_credit(self):
        self.start(credit=None)
        self.complete()
        self.assertFalse(self.server.debits)

    def test_missing_saved_report_does_not_consume(self):
        self.start()
        with self.assertRaises(ValueError): finish_scan(self.state, self.db, completed=True)
        finish_scan(self.state, self.db)
        self.assertEqual(self.server.balances['a'], 2)

    def test_engine_failure_is_not_a_successful_completion(self):
        self.start()
        with self.assertRaises(RuntimeError):
            run_reserved_scan(self.state, self.db, Mock(side_effect=RuntimeError('engine failed')))
        finish_scan(self.state, self.db)
        self.assertEqual(self.server.balances['a'], 2)

    def test_long_engine_keeps_reservation_alive_and_returns_result(self):
        self.start()
        def engine():
            time.sleep(.03)
            return ['local fixture']
        self.assertEqual(run_reserved_scan(self.state, self.db, engine, heartbeat_seconds=.005), ['local fixture'])
        self.assertGreater(self.server.calls.count('billing_scan_heartbeat'), 2)

    def test_legacy_pending_spend_is_not_silently_charged_again(self):
        self.state['_scan_credit_pending'] = {'identity': ('a@example.invalid','tokens_pro','example.invalid','Profundo (Active)'), 'operation':'legacy'}
        with self.assertRaises(ValueError): self.start()
        self.assertFalse(self.server.calls)

    def test_direct_spend_cannot_take_the_last_held_credit(self):
        self.server.balances['a']=1
        self.start()
        with self.assertRaises(ValueError):
            self.db.rpc('billing_spend',{'p_credit':'tokens_pro','p_operation':'other-operation'}).execute()
        self.complete()
        self.assertEqual(self.server.balances['a'],0)

    def test_pdf_spend_is_independent_of_the_scan_hold(self):
        self.start()
        result=self.db.rpc('billing_spend',{'p_credit':'tokens_pdf','p_operation':'pdf:report'}).execute().data
        self.assertEqual(result['remaining'],0)
        self.assertEqual(self.server.balances['a'],2)

    def test_zero_credit_rejects_claim_without_any_debit(self):
        self.server.balances['a']=0
        with self.assertRaises(ValueError): self.start()
        self.assertFalse(self.server.runs)
        self.assertFalse(self.server.debits)

    def test_engine_result_is_rejected_after_losing_the_lease(self):
        self.start()
        def engine():
            self.server.now=301
            return ['stale result']
        with self.assertRaises(ValueError): run_reserved_scan(self.state,self.db,engine)
        self.assertFalse(self.server.reports)
        self.assertFalse(self.server.debits)

    def payload(self):
        return {'dominio':'example.invalid','tipo':'Profundo (Active)',
                'riesgo':'Moderado','resultados_json':'["local fixture"]'}

    def test_atomic_store_failure_does_not_debit_or_create_report(self):
        self.start()
        self.server.fail_save=True
        with self.assertRaises(RuntimeError): store_scan(self.state,self.db,self.payload())
        self.assertFalse(self.server.reports)
        self.assertEqual(self.server.balances['a'],2)

    def test_atomic_store_rolls_back_report_if_completion_fails(self):
        self.start()
        self.server.fail_complete=True
        with self.assertRaises(RuntimeError): store_scan(self.state,self.db,self.payload())
        self.assertFalse(self.server.reports)
        self.assertFalse(self.server.debits)
        self.assertEqual(self.server.balances['a'],2)

    def test_lost_atomic_store_response_recovers_without_second_report_or_debit(self):
        self.start()
        self.server.lost='billing_scan_store'
        with self.assertRaises(ConnectionError): store_scan(self.state,self.db,self.payload())
        finish_scan(self.state,self.db)
        with self.assertRaises(ScanBusy): self.start()
        self.assertEqual(len(self.server.reports),1)
        self.assertEqual(self.server.balances['a'],1)
        self.assertEqual(self.state['escaneo_actual_id'],'report-1')

    def test_expired_unsaved_payload_does_not_leave_session_stuck(self):
        self.start()
        self.server.now=301
        with self.assertRaises(ValueError): store_scan(self.state,self.db,self.payload())
        self.assertNotIn('_scan_credit_pending',self.state)
        self.start()
        self.assertEqual(self.server.balances['a'],2)

    def test_heartbeats_cannot_keep_a_stuck_scan_reserved_forever(self):
        self.start()
        for tick in range(1,18):
            self.server.now=tick*200
            heartbeat(self.state,self.db)
        self.server.now=3601
        with self.assertRaises(ValueError): heartbeat(self.state,self.db)
        self.start(dict(email_usuario='a@example.invalid'))
        self.assertEqual(self.server.balances['a'],2)

    def test_local_timeout_stops_renewing_a_stuck_motor(self):
        self.start()
        with self.assertRaises(TimeoutError):
            run_reserved_scan(self.state,self.db,lambda:time.sleep(.04),
                              heartbeat_seconds=.005,max_scan_seconds=.005)
        finish_scan(self.state,self.db)
        self.assertEqual(self.server.balances['a'],2)
