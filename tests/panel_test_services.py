"""Fictitious authenticated panel dependencies; no network or account writes."""
import os,sys
from types import SimpleNamespace

mode=sys.argv[1] if len(sys.argv)>1 else 'structured'
profile={'email':'admin@example.invalid','plan_activo':'Basic','tokens_pro':0,'tokens_ent':0,
         'tokens_pdf':0,'billing_status':None,'billing_period_end':None,'escaneos_realizados':1,
         'fecha_vencimiento':None,'cancelacion_pendiente':False}
if mode=='pdf_failure':profile['tokens_pdf']=1
raw={'structured':[{'descripcion':'[MEDIO] local finding'},None,42],
     'legacy':'["[MEDIO] local finding","[OK] local setting"]',
     'envelope':{'resultados':[{'mensaje':'[MEDIO] local finding'}]},
     'plain':['[MEDIO] local finding','[OK] local setting']}.get(mode,[{'descripcion':'[MEDIO] local finding'}])
report={'id':42,'email_cliente':profile['email'],'dominio':'example.invalid',
        'tipo':'Rápido (Passive)','fecha':'01/01/2026','riesgo':'Moderado','resultados_json':raw}
writes=[]
rpc_calls=[]
class Query:
    def __init__(self,table):self.table=table;self.fields="*";self.report_id=None;self.row_limit=None
    def __getattr__(self,name):
        if name in ('insert','update','delete','upsert'):
            writes.append(name)
            raise AssertionError('Unexpected write')
        def method(*args,**kwargs):
            if name=='select':self.fields=args[0]
            if name=='eq' and args[0]=='id':self.report_id=str(args[1])
            if name=='limit':self.row_limit=args[0]
            return self
        return method
    def execute(self):
        rows=[] if mode in ('empty','feed','basic') else [report]
        if mode=='volume429' and self.table=='escaneos':
            rows=[dict(report,id=i,dominio='fixture-'+str(i)+'.invalid',
                       resultados_json=[{'descripcion':'[MEDIO] Fictitious finding '+str(j)} for j in range(150)])
                  for i in range(429)]
        data={'usuarios':[profile],'escaneos':rows,'activos_verificados':[]}.get(self.table,[])
        if self.report_id is not None:data=[r for r in data if str(r.get('id'))==self.report_id]
        if self.row_limit is not None:data=data[:self.row_limit]
        if self.fields!='*':data=[{k:r.get(k) for k in self.fields.split(',')} for r in data]
        return SimpleNamespace(data=data,count=0)
db=SimpleNamespace(table=lambda name:Query(name),
    auth=SimpleNamespace(get_user=lambda:SimpleNamespace(user=SimpleNamespace(email=profile['email'],id='fixture'))))
def rpc(name,params):
    rpc_calls.append((name,params))
    values={'billing_internal_access':{} if mode in ('basic','pdf_failure') else {'plan':'Enterprise','source':'internal_test','expires_at':None},
            'billing_authorize_pdf':{'authorized':mode!='basic'},'billing_sync_status':{'profile':profile}}
    if name not in values or params.get('p_consume') is True:
        raise AssertionError('Unexpected billing write')
    return SimpleNamespace(execute=lambda:SimpleNamespace(data=values[name]))
db.rpc=rpc
feed=[{'id':'CVE-local','cvss':{'unsupported':'shape'},'summary':None},None] if mode=='feed' else [{'id':'CVE-local','cvss':5,'summary':'local fixture'}]
