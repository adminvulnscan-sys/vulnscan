"""Bounded parallel reads. No Stripe, writes, credit consumption or UI calls."""
from concurrent.futures import Future, ThreadPoolExecutor
from contextvars import copy_context
from threading import Lock
from time import monotonic

import requests


class PdfReadBatch:
    """One full render only; never shared between accounts or persisted in session."""
    def __init__(self, client, execute):
        self.client = client
        self.execute = execute
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='pdf-read')
        self.jobs = {}

    def prefetch(self, reports):
        for report in dict.fromkeys(map(str, reports)):
            if report not in self.jobs:
                # Build on the script thread; workers only execute read RPCs.
                try:
                    query = self.client.rpc('billing_authorize_pdf',
                                            {'p_report': report, 'p_consume': False})
                    self.jobs[report] = self.pool.submit(
                        copy_context().run, self.execute, query, 'supabase.billing_authorize_pdf')
                except Exception as error:
                    # Let the existing per-report fail-closed UI handle errors.
                    failed = Future()
                    failed.set_exception(error)
                    self.jobs[report] = failed

    def read(self, report):
        self.prefetch([report])
        return self.jobs[str(report)].result().data

    def invalidate(self, report):
        self.jobs.pop(str(report), None)

    def close(self):
        self.pool.shutdown(wait=False, cancel_futures=True)


class PublicFeed:
    """Process-wide cache of public CVEs only. Contains no client or identity."""
    def __init__(self):
        self.lock = Lock()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='public-feed')
        self.job = None
        self.started = 0

    def start(self):
        with self.lock:
            if self.job is None or (self.job.done() and monotonic()-self.started >= 3600):
                self.started = monotonic()
                # Never copy the private render context into a shared cache.
                self.job = self.pool.submit(self.fetch)
            return self.job

    @staticmethod
    def fetch():
        # Fixed public endpoint, identical timeout. No account information sent.
        from panel_diagnostics import measure_panel
        with measure_panel('threat_feed_read'):
            response = requests.get('https://cve.circl.lu/api/last',
                                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                                    timeout=(3, 8))
        if response.status_code != 200:
            return None
        with measure_panel('threat_feed_decode'):
            data = response.json()
            return data[:6] if isinstance(data, list) else None


PUBLIC_FEED = PublicFeed()
