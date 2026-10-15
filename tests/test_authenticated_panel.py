"""Render and interact with actual authenticated sections, not only login."""
from pathlib import Path
import subprocess,sys,unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=r'''
import os,sys,logging,io
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import Mock,patch
from types import SimpleNamespace
os.environ['STREAMLIT_BROWSER_GATHER_USAGE_STATS']='false'
sys.path.insert(0,str(Path.cwd()))
exec(Path('tests/panel_test_services.py').read_text(encoding='utf-8'))
from streamlit.testing.v1 import AppTest
logs=io.StringIO()
handler=logging.StreamHandler(logs)
logging.getLogger('vulnscan.panel').addHandler(handler)
with ExitStack() as stack:
    stack.enter_context(patch.dict(os.environ,{'SUPABASE_URL':'https://example.invalid',
        'SUPABASE_KEY':'sb_publishable_fixture','STRIPE_SECRET_KEY':'sk_test_fixture'}))
    stack.enter_context(patch('dotenv.load_dotenv',return_value=False))
    stack.enter_context(patch('supabase.create_client',return_value=db))
    checkout=stack.enter_context(patch('stripe.checkout.Session.create',side_effect=AssertionError('No purchases')))
    modify=stack.enter_context(patch('stripe.Subscription.modify',side_effect=AssertionError('No writes')))
    stack.enter_context(patch('requests.get',return_value=SimpleNamespace(status_code=200,json=lambda:feed)))
    stack.enter_context(patch('requests.post',side_effect=AssertionError('No HTTP writes')))
    stack.enter_context(patch('socket.socket.connect',side_effect=AssertionError('No network')))
    import motores
    engines=[stack.enter_context(patch.object(motores,name,side_effect=AssertionError('No engines')))
             for name in ('_motor_basic_pasivo','_motor_pro_activo','_motor_enterprise_owasp')]
    if mode=='pdf_failure':
        import panel_diagnostics
        original_cached=panel_diagnostics.cached_pdf
        calls=[]
        def failed_pdf(state,owner,payload,factory):
            calls.append(True)
            if len(calls)>1:
                raise RuntimeError('PRIVATE_SENTINEL')
            return original_cached(state,owner,payload,factory)
        stack.enter_context(patch('panel_diagnostics.cached_pdf',side_effect=failed_pdf))
    app=AppTest.from_file(sys.argv[2],default_timeout=40)
    app.query_params['vista']='acceso'
    app.session_state['usuario_autenticado']=True
    app.session_state['email_usuario']=profile['email']
    app.run()
    assert not app.exception,[str(e.message) for e in app.exception]
    # All sections and both history lists must exist on the first render.
    labels=['Reportes','Amenazas','Configuraci\u00f3n']
    for label in labels:
        tab=next(t for t in app.tabs if t.label==label)
        assert tab.children,label+' empty at initial load'
    if mode not in ('empty','feed','basic'):
        assert all(t.children for t in app.tabs if 'Historial Completo' in t.label or 'Resultados Filtrados' in t.label)
    if mode!='pdf_failure':
        before={key:app.session_state[key] for key in ('plan_activo','tokens_pro','tokens_ent','tokens_pdf')}
        search=next(x for x in app.text_input if x.placeholder.startswith('Buscar amenaza'))
        search.set_value('Ransomware').run()
        assert not app.exception
        assert before=={key:app.session_state[key] for key in before}
    if mode=='pdf_failure':
        assert 'operation=panel_render section=reports_pdf error_type=RuntimeError' in logs.getvalue()
        assert 'PRIVATE_SENTINEL' not in logs.getvalue()
    if mode=='basic':
        assert app.session_state['plan_activo']=='Basic'
        assert any(b.disabled and 'Generar Key' in b.label for b in app.button)
    for section in ('reports','threats','settings'):
        assert 'operation=panel_section_loaded section='+section in logs.getvalue()
    if mode=='volume429':
        assert '"history_reports":429' in logs.getvalue()
        # Two renders (initial + search): only the visible Dashboard PDF reads.
        assert sum(n=='billing_authorize_pdf' for n,p in rpc_calls)<=2
    assert not writes
    assert all(call[0] not in ('billing_spend','billing_scan_claim','billing_scan_store') and call[1].get('p_consume') is not True for call in rpc_calls)
    checkout.assert_not_called();modify.assert_not_called()
    for engine in engines:engine.assert_not_called()
print('AUTHENTICATED_SECTIONS_OK',mode)
'''


class AuthenticatedPanelTests(unittest.TestCase):
    def check_mode(self,mode,entry='app.py'):
        result=subprocess.run([sys.executable,'-c',SCRIPT,mode,entry],cwd=ROOT,
                              capture_output=True,text=True,encoding='utf-8',timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('AUTHENTICATED_SECTIONS_OK',result.stdout)

    def test_structured_report_and_search_rerun_keep_both_sections(self):self.check_mode('structured')
    def test_legacy_string_report(self):self.check_mode('legacy')
    def test_enveloped_json_report(self):self.check_mode('envelope')
    def test_empty_history(self):self.check_mode('empty')
    def test_malformed_public_feed_does_not_abort_settings(self):self.check_mode('feed')
    def test_pdf_failure_is_local_and_logs_no_payload(self):self.check_mode('pdf_failure')
    def test_basic_api_restrictions_are_preserved(self):self.check_mode('basic')
    def test_second_entry_point(self):self.check_mode('structured','vulnscan.py')

    def test_all_sections_preloaded_with_429_structured_reports_without_archive_rpc_fanout(self):
        self.check_mode('volume429')
