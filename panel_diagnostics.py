"""Safe UI failure coordinates: no account data, exception messages or locals."""
import logging
from pathlib import Path

REVISION='panel-parallel-v5'
logging.getLogger('vulnscan.panel').warning('operation=panel_module_loaded revision=%s',REVISION)


def section_loaded(section):
    logging.getLogger('vulnscan.panel').warning('operation=panel_section_loaded section=%s revision=%s',section,REVISION)


def feed_item(item):
    """Malformed public feed fields must not stop unrelated Streamlit tabs."""
    if not isinstance(item,dict):
        return None
    try:
        score=float(item['cvss'])
        if not 0<=score<=10:
            score=None
    except (KeyError,TypeError,ValueError):
        score=None
    severity='Sin clasificar' if score is None else ('CRITICA' if score>=8 else ('ALTA' if score>=5 else 'MEDIA'))
    return {'Identificador CVE':str(item.get('id') or 'N/A'),
            'Severidad CVSS':f"{'No disponible' if score is None else score} - {severity}",
            'Descripción Técnica del Riesgo':str(item.get('summary') or 'Sin descripción')[:150]+'...'}


def log_panel_failure(section,error):
    filename,function,line='unknown','unknown',0
    frame=error.__traceback__
    while frame:
        code=frame.tb_frame.f_code
        base=Path(code.co_filename).name
        if base in ('app.py','vulnscan.py') and code.co_name.isidentifier():
            filename,function,line=base,code.co_name,frame.tb_lineno
        frame=frame.tb_next
    logging.getLogger('vulnscan.panel').warning(
        'operation=panel_render section=%s error_type=%s file=%s function=%s line=%s revision=%s',
        section,type(error).__name__,filename,function,line,REVISION)


from contextlib import contextmanager
from time import perf_counter
from contextvars import ContextVar
from uuid import uuid4
import json
from threading import Lock

_trace = ContextVar('panel_trace', default=None)


def begin_panel_trace(start=None):
    previous = _trace.get()
    if previous is not None and previous.get('pdf_reads') is not None:
        previous.pop('pdf_reads').close()
    trace = {'run': uuid4().hex[:12], 'start': perf_counter() if start is None else start,
             'phases': {}, 'counts': {}, 'lock': Lock()}
    if start is not None:
        elapsed = round((perf_counter()-start)*1000)
        trace['phases']['imports'] = {'calls': 1, 'ms': elapsed, 'max_ms': elapsed,
                                      'start_ms': 0, 'end_ms': elapsed}
    _trace.set(trace)
    return trace


def panel_count(name, amount):
    trace = _trace.get()
    if trace is not None:
        trace['counts'][name] = int(amount)


def finish_panel_trace():
    trace = _trace.get()
    if trace is None:
        return
    if trace.get('pdf_reads') is not None:
        trace.pop('pdf_reads').close()
    payload = {'revision': REVISION, 'run': trace['run'],
               'total_ms': round((perf_counter()-trace['start'])*1000),
               'nested_timings': True, 'counts': trace['counts'], 'phases': trace['phases']}
    logging.getLogger('vulnscan.panel').warning(
        'operation=panel_profile_summary %s', json.dumps(payload, separators=(',', ':')))
    logger = logging.getLogger('vulnscan.panel')
    for phase, stats in sorted(trace['phases'].items(), key=lambda item: item[1]['start_ms']):
        logger.warning('operation=panel_profile_timing run=%s phase=%s calls=%d elapsed_ms=%d max_ms=%d from_ms=%d to_ms=%d',
                       trace['run'], phase, stats['calls'], stats['ms'], stats['max_ms'],
                       stats['start_ms'], stats['end_ms'])
    logger.warning('operation=panel_profile_timing run=%s phase=TOTAL elapsed_ms=%d reports=%d structured=%d nested=true',
                   trace['run'], payload['total_ms'], trace['counts'].get('history_reports', 0),
                   trace['counts'].get('history_structured_reports', 0))
    _trace.set(None)
    return payload


def panel_execute(query, phase):
    """Measure execution/response decoding; never inspect query arguments or responses."""
    with measure_panel(phase):
        return query.execute()


def pdf_read(client, report):
    trace = _trace.get()
    if trace is None:
        return panel_execute(client.rpc('billing_authorize_pdf',
                             {'p_report': str(report), 'p_consume': False}),
                             'supabase.billing_authorize_pdf').data
    from panel_read_pipeline import PdfReadBatch
    batch = trace.get('pdf_reads')
    if batch is None or batch.client is not client:
        if batch is not None:
            batch.close()
        batch = trace['pdf_reads'] = PdfReadBatch(client, panel_execute)
    return batch.read(report)


def prefetch_pdf_reads(client, reports):
    trace = _trace.get()
    if trace is None:
        return
    from panel_read_pipeline import PdfReadBatch
    batch = trace.get('pdf_reads')
    if batch is None or batch.client is not client:
        if batch is not None:
            batch.close()
        batch = trace['pdf_reads'] = PdfReadBatch(client, panel_execute)
    batch.prefetch(reports)


def invalidate_pdf_read(client, report):
    trace = _trace.get()
    batch = trace.get('pdf_reads') if trace else None
    if batch is not None and batch.client is client:
        batch.invalidate(report)

@contextmanager
def measure_panel(operation):
    start = perf_counter()
    trace = _trace.get()
    try:
        yield
    finally:
        elapsed = round((perf_counter()-start)*1000)
        if trace is not None:
            with trace['lock']:
                stats = trace['phases'].setdefault(operation, {
                    'calls': 0, 'ms': 0, 'max_ms': 0,
                    'start_ms': round((start-trace['start'])*1000), 'end_ms': 0})
                stats['calls'] += 1
                stats['ms'] += elapsed
                stats['max_ms'] = max(stats['max_ms'], elapsed)
                stats['end_ms'] = max(stats['end_ms'], round((perf_counter()-trace['start'])*1000))
        logging.getLogger('vulnscan.panel').warning(
            'operation=panel_timing phase=%s elapsed_ms=%d revision=%s',
            operation, round((perf_counter()-start)*1000), REVISION)


def cached_pdf(state, owner, payload, factory):
    """Private, bounded byte cache. Never caches authorization or credit balances."""
    import hashlib
    import json
    key = hashlib.sha256(json.dumps(payload, ensure_ascii=False, default=str).encode()).hexdigest()
    cache = state.get('_panel_pdf_cache')
    if not isinstance(cache, dict) or cache.get('owner') != owner:
        cache = {'owner': owner, 'items': {}}
        state['_panel_pdf_cache'] = cache
    items = cache['items']
    if key not in items:
        with measure_panel('pdf_generate'):
            value = factory()
        # A single unusually large report is served but not retained.
        if len(value) > 8*1024*1024:
            return value
        while items and (len(items) >= 32 or sum(map(len,items.values()))+len(value)>8*1024*1024):
            items.pop(next(iter(items)))
        items[key] = value
    return items[key]
