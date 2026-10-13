"""Safe UI failure coordinates: no account data, exception messages or locals."""
import logging
from pathlib import Path

REVISION='panel-tabs-v1'
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
