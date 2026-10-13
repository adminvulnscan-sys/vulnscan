"""Fictitious authenticated panel dependencies; no network or account writes."""
import os,sys
from types import SimpleNamespace

mode=sys.argv[1] if len(sys.argv)>1 else 'structured'
profile={'email':'admin@example.invalid','plan_activo':'Basic','tokens_pro':0,'tokens_ent':0,
         'tokens_pdf':0,'billing_status':None,'billing_period_end':None,'escaneos_realizados':1,
         'fecha_vencimiento':None,'cancelacion_pendiente':False}
raw={'structured':[{'descripcion':'[MEDIO] local finding'},None,42],
     'legacy':'["[MEDIO] local finding","[OK] local setting"]',
     'envelope':{'resultados':[{'mensaje':'[MEDIO] local finding'}]},
     'plain':['[MEDIO] local finding','[OK] local setting']}.get(mode,[{'descripcion':'[MEDIO] local finding'}])
report={'id':42,'email_cliente':profile['email'],'dominio':'example.invalid',
        'tipo':'Rápido (Passive)','fecha':'01/01/2026','riesgo':'Moderado','resultados_json':raw}
writes=[]
rpc_calls=[]
class Query:
    def __init__(self,table):self.table=table
    def __getattr__(self,name):
        if name in ('insert','update','delete','upsert'):
            writes.append(name)
            raise AssertionError('Unexpected write')
        return lambda *args,**kwargs:self
    def execute(self):
        rows=[] if mode in ('empty','feed','basic') else [report]
        return SimpleNamespace(data={'usuarios':[profile],'escaneos':rows,'activos_verificados':[]}.get(self.table,[]),count=0)
db=SimpleNamespace(table=lambda name:Query(name),
    auth=SimpleNamespace(get_user=lambda:SimpleNamespace(user=SimpleNamespace(email=profile['email'],id='fixture'))))
def rpc(name,params):
    rpc_calls.append((name,params))
    values={'billing_internal_access':{} if mode=='basic' else {'plan':'Enterprise','source':'internal_test','expires_at':None},
            'billing_authorize_pdf':{'authorized':mode!='basic'},'billing_sync_status':{'profile':profile}}
    if name not in values or params.get('p_consume') is True:
        raise AssertionError('Unexpected billing write')
    return SimpleNamespace(execute=lambda:SimpleNamespace(data=values[name]))
db.rpc=rpc
feed=[{'id':'CVE-local','cvss':{'unsupported':'shape'},'summary':None},None] if mode=='feed' else [{'id':'CVE-local','cvss':5,'summary':'local fixture'}]
