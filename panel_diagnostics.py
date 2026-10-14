"""Safe UI failure coordinates: no account data, exception messages or locals."""
import logging
from pathlib import Path

REVISION='panel-eager-v3'
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

@contextmanager
def measure_panel(operation):
    start = perf_counter()
    try:
        yield
    finally:
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
