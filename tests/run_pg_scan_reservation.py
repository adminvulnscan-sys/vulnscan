"""Real PostgreSQL validation on an explicitly isolated portable cluster.

Uses stdlib + psql. Never loads project credentials or connects to Supabase.
Run with --root pointing outside the project to the extracted PostgreSQL folder.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import sys
from types import SimpleNamespace
from uuid import uuid4

PROJECT = Path(__file__).resolve().parents[1]
USERS = {name: f'00000000-0000-4000-8000-{i:012d}'
         for i, name in enumerate(('a', 'b', 'admin', 'pro'), 1)}


def baseline_sql():
    package = (PROJECT/'supabase/updates/original_billing_compatible.sql').read_text(encoding='utf-8')
    def function(name):
        found = re.findall(r'create function public\.'+name+r'\([\s\S]*?\$\$;', package)
        if len(found) != 1:
            raise RuntimeError('Expected exact compatible function: '+name)
        return found[0]
    sql = """
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon NOLOGIN; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
END $$;
CREATE SCHEMA auth;
CREATE TABLE auth.users(id uuid PRIMARY KEY,email text);
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb;
$$;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$
 SELECT coalesce(nullif(current_setting('request.jwt.claim.sub',true),''),auth.jwt()->>'sub')::uuid;
$$;
CREATE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$
 SELECT coalesce(nullif(current_setting('request.jwt.claim.role',true),''),auth.jwt()->>'role');
$$;
GRANT USAGE ON SCHEMA public,auth TO anon,authenticated,service_role;
CREATE TABLE public.usuarios(
 email text PRIMARY KEY,plan_activo text DEFAULT 'Basic',tokens_pro integer DEFAULT 0,
 tokens_ent integer DEFAULT 0,tokens_pdf integer DEFAULT 0,fecha_vencimiento text,
 fecha_inicio_trial text,trial_pro_usada boolean DEFAULT false,cancelacion_pendiente boolean DEFAULT false,
 reporte_pdf_desbloqueado text,stripe_customer_id text,stripe_subscription_id text,
 billing_user_id uuid UNIQUE REFERENCES auth.users(id),billing_status text,billing_period_end bigint
);
CREATE TABLE public.escaneos(id serial PRIMARY KEY,email_cliente text,dominio text NOT NULL,
 tipo text NOT NULL,fecha text NOT NULL,riesgo text,resultados_json jsonb);
CREATE TABLE public.billing_spends(user_id uuid NOT NULL REFERENCES auth.users(id),
 operation_id text NOT NULL,credit text NOT NULL CHECK(credit IN ('tokens_pro','tokens_ent','tokens_pdf')),
 PRIMARY KEY(user_id,operation_id));
CREATE TABLE public.billing_legacy_pdf_rights(profile_email text,report_id integer);
CREATE TABLE public.billing_internal_entitlements(
 user_id uuid PRIMARY KEY REFERENCES auth.users(id),profile_email text UNIQUE NOT NULL REFERENCES public.usuarios(email),
 plan text NOT NULL DEFAULT 'Enterprise',source text NOT NULL DEFAULT 'internal_test',
 granted_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz,revoked_at timestamptz,reason text NOT NULL);
ALTER TABLE public.billing_spends ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.billing_legacy_pdf_rights ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.billing_internal_entitlements ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.billing_spends,public.billing_legacy_pdf_rights,public.billing_internal_entitlements
 FROM public,anon,authenticated,service_role;
GRANT ALL ON public.billing_spends TO service_role;
"""
    sql += '\n'.join(function(name) for name in ('billing_spend','billing_internal_access',
                                                 'billing_authorize_pdf','billing_protect_profile'))
    sql += """
REVOKE ALL ON FUNCTION public.billing_spend(text,text),public.billing_internal_access(),
 public.billing_authorize_pdf(text,boolean) FROM public,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.billing_spend(text,text),public.billing_internal_access(),
 public.billing_authorize_pdf(text,boolean) TO authenticated;
GRANT EXECUTE ON FUNCTION public.billing_spend(text,text),public.billing_authorize_pdf(text,boolean) TO service_role;
CREATE TRIGGER billing_protect_profile BEFORE INSERT OR UPDATE ON public.usuarios
 FOR EACH ROW EXECUTE FUNCTION public.billing_protect_profile();
ALTER TABLE public.usuarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.escaneos ENABLE ROW LEVEL SECURITY;
GRANT SELECT,INSERT,UPDATE ON public.usuarios TO authenticated;
GRANT SELECT,INSERT ON public.escaneos TO authenticated;
GRANT USAGE ON SEQUENCE public.escaneos_id_seq TO authenticated;
CREATE POLICY owner_boundary ON public.usuarios AS RESTRICTIVE TO authenticated
 USING(billing_user_id=auth.uid() OR (billing_user_id IS NULL AND email COLLATE "C"=(auth.jwt()->>'email') COLLATE "C"))
 WITH CHECK(billing_user_id=auth.uid() OR (billing_user_id IS NULL AND email COLLATE "C"=(auth.jwt()->>'email') COLLATE "C"));
CREATE POLICY owner_allow ON public.usuarios TO authenticated
 USING(billing_user_id=auth.uid() OR (billing_user_id IS NULL AND email COLLATE "C"=(auth.jwt()->>'email') COLLATE "C"))
 WITH CHECK(billing_user_id=auth.uid() OR (billing_user_id IS NULL AND email COLLATE "C"=(auth.jwt()->>'email') COLLATE "C"));
CREATE POLICY scan_owner ON public.escaneos TO authenticated
 USING(email_cliente COLLATE "C"=(auth.jwt()->>'email') COLLATE "C")
 WITH CHECK(email_cliente COLLATE "C"=(auth.jwt()->>'email') COLLATE "C");
"""
    for name, uid in USERS.items():
        sql += f"INSERT INTO auth.users VALUES('{uid}','{name}@example.invalid');\n"
        sql += f"INSERT INTO public.usuarios(email,billing_user_id,tokens_pro,tokens_ent,tokens_pdf) VALUES('{name}@example.invalid','{uid}',2,1,2);\n"
    sql += f"""
INSERT INTO public.billing_internal_entitlements(user_id,profile_email,reason)
 VALUES('{USERS['admin']}','admin@example.invalid','Fictitious isolated fixture');
UPDATE public.usuarios SET plan_activo='Pro',billing_status='active',
 billing_period_end=extract(epoch FROM now()+interval '1 month')::bigint WHERE email='pro@example.invalid';
INSERT INTO public.escaneos(email_cliente,dominio,tipo,fecha,riesgo,resultados_json)
 VALUES('a@example.invalid','history.example.invalid','Rápido (Passive)','01/01/2026','Moderado','[]'),
       ('b@example.invalid','history.example.invalid','Rápido (Passive)','01/01/2026','Moderado','[]');
INSERT INTO public.billing_legacy_pdf_rights VALUES('a@example.invalid',1),('b@example.invalid',2);
"""
    return sql


class Validation:
    def __init__(self, root):
        self.root = root.resolve()
        if self.root.is_relative_to(PROJECT.resolve()):
            raise RuntimeError('Cluster must be outside the project')
        self.bin = self.root/'pgsql/bin'
        self.data = self.root/'validation-data'
        self.port = '55439'
        self.database = 'vulnscan_validation_'+uuid4().hex[:10]
        self.env = {k:v for k,v in os.environ.items() if not k.startswith('PG')}
        self.env.update(PGCLIENTENCODING='UTF8', PGAPPNAME='vulnscan-isolated-validation')
        self.passed = []
        self.children = []
        self.started = False

    def command(self, executable, *args):
        if executable == 'pg_ctl.exe':
            # A Windows daemon can retain inherited pipe handles after pg_ctl exits.
            # A file avoids waiting for those handles in subprocess.communicate().
            with (self.root/'control-commands.log').open('a',encoding='utf-8') as output:
                result=subprocess.run([str(self.bin/executable),*map(str,args)],env=self.env,
                                      stdout=output,stderr=subprocess.STDOUT,timeout=90)
            if result.returncode:
                raise RuntimeError('pg_ctl failed; inspect private control-commands.log')
            return ''
        result = subprocess.run([str(self.bin/executable), *map(str,args)], env=self.env,
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
        if result.returncode:
            raise RuntimeError(executable+': '+result.stderr[-1800:]+result.stdout[-800:])
        return result.stdout

    def psql_args(self, database=None):
        return [str(self.bin/'psql.exe'), '-X','-q','-A','-t','-w','-v','ON_ERROR_STOP=1',
                '-h','127.0.0.1','-p',self.port,'-U','postgres','-d',database or self.database]

    def sql(self, sql, *, expect_error=None, database=None):
        result = subprocess.run(self.psql_args(database), input=sql, env=self.env,
                                capture_output=True, text=True, encoding='utf-8', timeout=20)
        if expect_error:
            assert result.returncode != 0 and expect_error in result.stderr, result.stderr
            return None
        if result.returncode:
            raise RuntimeError(result.stderr[-2500:])
        return result.stdout.strip()

    def session(self, query, user='a', role='authenticated', *, tail='COMMIT;'):
        claims={'sub':USERS[user], 'email':user+'@example.invalid', 'role':role}
        return ("BEGIN; SET LOCAL statement_timeout='8s'; SET LOCAL lock_timeout='5s'; "
                f"SET LOCAL ROLE {role}; DO $$ BEGIN PERFORM set_config('request.jwt.claims',"
                "'"+json.dumps(claims)+"',true); END $$; "+query+'; '+tail)

    def rpc(self, name, *args, user='a', role='authenticated', error=None):
        literals=[]
        for value in args:
            if value is None: literals.append('NULL')
            elif isinstance(value,dict): literals.append("'"+json.dumps(value).replace("'","''")+"'::jsonb")
            else: literals.append("'"+str(value).replace("'","''")+"'")
        out=self.sql(self.session(f"SELECT public.{name}({','.join(literals)})",user,role),expect_error=error)
        return json.loads(out) if out else None

    def check(self, name, condition):
        assert condition, name
        self.passed.append(name)
        print('PASS '+name,flush=True)

    def reset(self):
        self.sql("TRUNCATE public.billing_scan_runs,public.billing_spends; UPDATE public.usuarios SET tokens_pro=2,tokens_ent=1,tokens_pdf=2;")

    def balance(self,user='a'):
        return int(self.sql(f"SELECT tokens_pro FROM public.usuarios WHERE email='{user}@example.invalid';"))

    def claim(self,op,user='a',credit='tokens_pro',engine='Profundo (Active)'):
        return self.rpc('billing_scan_claim',op,credit,'example.invalid',engine,user=user)

    def store(self,op,user='a',payload=None,error=None):
        return self.rpc('billing_scan_store',op,payload or {'dominio':'example.invalid','riesgo':'Moderado',
                       'resultados_json':'["fictitious local finding"]'},user=user,error=error)

    def race(self):
        self.reset()
        op1,op2=str(uuid4()),str(uuid4())
        query=f"SELECT jsonb_build_object('pid',pg_backend_pid(),'result',public.billing_scan_claim('{op1}','tokens_pro','example.invalid','Profundo (Active)')); SELECT pg_sleep(1.5)"
        a=subprocess.Popen(self.psql_args(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           text=True,encoding='utf-8',env={**self.env,'PGAPPNAME':'vs-reserve-A'})
        self.children.append(a)
        a.stdin.write(self.session(query)); a.stdin.close()
        first=json.loads(a.stdout.readline())
        query=f"SELECT jsonb_build_object('pid',pg_backend_pid(),'result',public.billing_scan_claim('{op2}','tokens_pro','example.invalid','Profundo (Active)'))"
        b=subprocess.Popen(self.psql_args(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           text=True,encoding='utf-8',env={**self.env,'PGAPPNAME':'vs-reserve-B'})
        self.children.append(b)
        b.stdin.write(self.session(query)); b.stdin.close()
        blocked=False
        for _ in range(30):
            if self.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='vs-reserve-B' AND wait_event_type='Lock');")=='t':
                blocked=True; break
            time.sleep(.02)
        second=json.loads(b.stdout.readline())
        a.wait(timeout=10); b.wait(timeout=10)
        assert a.returncode==0 and b.returncode==0, a.stderr.read()+b.stderr.read()
        self.check('two_backend_pids_and_real_lock_wait',blocked and first['pid']!=second['pid'])
        self.check('second_claim_busy_before_any_debit',first['result']['status']=='reserved' and
                   second['result']['status']=='busy' and self.balance()==2 and
                   self.sql('SELECT count(*) FROM public.billing_spends;')=='0')
        self.check('single_active_account_reservation',self.sql("SELECT count(*) FROM public.billing_scan_runs WHERE state='reserved';")=='1')
        # Another account is independent while the first account remains reserved.
        self.check('other_account_independent',self.claim(str(uuid4()),user='b')['status']=='reserved')

    def tests(self):
        self.race()
        self.reset()
        op=str(uuid4()); self.claim(op)
        before=self.sql('SELECT count(*) FROM public.escaneos;')
        saved=self.store(op)
        again=self.store(op)
        self.check('atomic_save_one_debit_and_retry_one_report',saved==again and self.balance()==1 and
                   int(self.sql('SELECT count(*) FROM public.escaneos;'))==int(before)+1 and
                   self.sql('SELECT count(*) FROM public.billing_spends;')=='1')
        self.check('results_persist_as_jsonb_array',self.sql(f"SELECT jsonb_typeof(resultados_json) FROM public.escaneos WHERE id={int(saved['report_id'])};")=='array')
        self.reset(); op=str(uuid4()); self.claim(op)
        self.rpc('billing_scan_abort',op)
        self.check('abort_preserves_balance',self.balance()==2 and self.claim(str(uuid4()))['status']=='reserved')
        self.reset(); op=str(uuid4()); self.claim(op)
        self.sql("UPDATE public.billing_scan_runs SET lease_until=clock_timestamp()-interval '1 second';")
        newer=str(uuid4()); self.claim(newer)
        self.check('expired_reservation_replaced_without_debit',self.balance()==2)
        self.check('stale_worker_cannot_heartbeat_or_store',self.rpc('billing_scan_heartbeat',op)['status']=='expired' and self.store(op)['status']=='expired')
        self.store(newer)
        self.check('new_holder_alone_can_commit',self.balance()==1)
        self.reset(); op=str(uuid4()); self.claim(op)
        self.sql("UPDATE public.billing_scan_runs SET hard_until=clock_timestamp()+interval '1 second';")
        self.rpc('billing_scan_heartbeat',op)
        self.check('heartbeat_never_extends_hard_deadline',self.sql('SELECT bool_and(lease_until<=hard_until) FROM public.billing_scan_runs;')=='t')
        self.sql("UPDATE public.billing_scan_runs SET hard_until=clock_timestamp()-interval '1 second',lease_until=clock_timestamp()-interval '1 second';")
        self.check('stuck_scan_expires_despite_renewals',self.rpc('billing_scan_heartbeat',op)['status']=='expired' and self.claim(str(uuid4()))['status']=='reserved' and self.balance()==2)
        self.reset(); self.sql("UPDATE public.usuarios SET tokens_pro=1 WHERE email='a@example.invalid';")
        op=str(uuid4()); self.claim(op)
        self.rpc('billing_spend','tokens_pro','direct-extra',error='Insufficient available credits')
        self.check('held_last_credit_protected_from_direct_spend',self.balance()==1)
        self.rpc('billing_spend','tokens_pdf','pdf:isolated-test')
        self.check('pdf_credit_remains_independent',self.balance()==1 and self.sql("SELECT tokens_pdf FROM public.usuarios WHERE email='a@example.invalid';")=='1')
        self.store(op); self.check('held_last_credit_consumed_once',self.balance()==0)
        self.reset(); op=str(uuid4()); self.claim(op)
        self.store(op,user='b',error='query returned no rows')
        self.rpc('billing_scan_claim',str(uuid4()),None,'example.invalid','Profundo (Active)',user='b',error='Plan does not include engine')
        self.check('no_cross_account_completion_or_free_premium',self.balance()==2 and self.balance('b')==2)
        self.reset()
        op=str(uuid4()); self.claim(op,user='pro',credit=None); self.store(op,user='pro')
        op=str(uuid4()); self.claim(op,user='admin',credit=None,engine='Auditoría Completa (OWASP)'); self.store(op,user='admin')
        self.check('paid_plan_and_internal_enterprise_do_not_spend_tokens',self.balance('pro')==2 and self.balance('admin')==2)
        self.reset(); op=str(uuid4()); self.claim(op)
        count=self.sql('SELECT count(*) FROM public.escaneos;')
        self.store(op,payload={'dominio':'other.invalid','resultados_json':'[]'},error='Invalid scan payload')
        self.check('failed_save_no_report_or_debit',self.balance()==2 and self.sql('SELECT count(*) FROM public.escaneos;')==count)
        # Force a failure AFTER INSERT, exercising real statement rollback.
        self.sql("""CREATE FUNCTION public.test_reject_spend() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN RAISE EXCEPTION 'isolated forced debit failure'; END $$;
 CREATE TRIGGER test_reject_spend BEFORE INSERT ON public.billing_spends
 FOR EACH ROW EXECUTE FUNCTION public.test_reject_spend();""")
        self.store(op,error='isolated forced debit failure')
        self.check('post_insert_debit_failure_rolls_back_report_balance_and_state',self.balance()==2 and
                   self.sql('SELECT count(*) FROM public.escaneos;')==count and
                   self.sql("SELECT state FROM public.billing_scan_runs;")=='reserved')
        self.sql('DROP TRIGGER test_reject_spend ON public.billing_spends; DROP FUNCTION public.test_reject_spend();')
        self.store(op)
        self.check('retry_after_real_transaction_rollback_succeeds_once',self.balance()==1)
        self.reset()
        self.rpc('billing_scan_claim',str(uuid4()),'tokens_pro','example.invalid','Profundo (Active)',role='anon',error='permission denied')
        self.rpc('billing_scan_profile',error='permission denied')
        self.sql(self.session('SELECT * FROM public.billing_scan_runs'),expect_error='permission denied')
        self.rpc('billing_scan_job','admin@example.invalid','claim',str(uuid4()),'example.invalid','Auditoría Completa (OWASP)',None,None,error='permission denied')
        self.check('private_table_helper_and_service_dispatcher_denied_to_clients',True)
        op=str(uuid4())
        service=self.rpc('billing_scan_job','admin@example.invalid','claim',op,'example.invalid','Auditoría Completa (OWASP)',None,None,role='service_role')
        self.check('trusted_scheduler_uses_same_reservation',service['status']=='reserved' and
                   self.claim(str(uuid4()),user='admin',credit=None,engine='Auditoría Completa (OWASP)')['status']=='busy')
        self.rpc('billing_scan_job','b@example.invalid','claim',str(uuid4()),'example.invalid','Auditoría Completa (OWASP)',None,None,role='service_role',error='Plan does not include engine')
        self.check('scheduler_cannot_grant_stored_or_unpaid_premium',True)
        # Dispatcher must restore the caller identity inside the SAME connection/transaction.
        query=f"""SELECT public.billing_scan_job('admin@example.invalid','heartbeat','{op}');
 SELECT jsonb_build_object('uid',auth.uid(),'role',auth.role());"""
        lines=self.sql(self.session(query,user='b',role='service_role')).splitlines()
        restored=json.loads(lines[-1])
        self.check('scheduler_restores_identity_in_same_transaction',restored=={'uid':USERS['b'],'role':'service_role'})
        self.check('legacy_pdf_right_survives_without_debit',self.rpc('billing_authorize_pdf','1','false')['authorized'] and
                   self.sql("SELECT tokens_pdf FROM public.usuarios WHERE email='a@example.invalid';")=='2')
        self.python_integration()

    def python_integration(self):
        sys.path.insert(0,str(PROJECT))
        from scan_reservation import begin_scan,finish_scan,store_scan,run_reserved_scan,ScanBusy
        validation=self
        class Client:
            lose_store_response=False
            def rpc(self,name,params):
                order={'billing_scan_claim':('p_operation','p_credit','p_target','p_engine'),
                       'billing_scan_heartbeat':('p_operation',),'billing_scan_abort':('p_operation',),
                       'billing_scan_store':('p_operation','p_payload')}
                def execute():
                    result=validation.rpc(name,*(params[k] for k in order[name]))
                    if name=='billing_scan_store' and self.lose_store_response:
                        self.lose_store_response=False
                        raise ConnectionError('Fictitious lost response after real commit')
                    return SimpleNamespace(data=result)
                return SimpleNamespace(execute=execute)
        self.reset()
        client=Client()
        state={'email_usuario':'a@example.invalid','tokens_pro':2}
        begin_scan(state,client,'tokens_pro','example.invalid','Profundo (Active)')
        other={'email_usuario':'a@example.invalid','tokens_pro':2}
        try:
            begin_scan(other,client,'tokens_pro','example.invalid','Profundo (Active)')
            raise AssertionError('Second Python session admitted')
        except ScanBusy:
            pass
        findings=run_reserved_scan(state,client,lambda:['local fixture, no network'])
        report=store_scan(state,client,{'dominio':'example.invalid','riesgo':'Moderado',
                                      'resultados_json':json.dumps(findings)})
        finish_scan(state,client)
        self.check('actual_python_rpc_contract_and_busy_session_on_real_postgres',
                   state['tokens_pro']==1 and self.balance()==1 and state['escaneo_actual_id']==report)
        self.reset()
        state={'email_usuario':'a@example.invalid','tokens_pro':2}
        before=int(self.sql('SELECT count(*) FROM public.escaneos;'))
        begin_scan(state,client,'tokens_pro','example.invalid','Profundo (Active)')
        client.lose_store_response=True
        try:
            store_scan(state,client,{'dominio':'example.invalid','riesgo':'Moderado','resultados_json':'[]'})
            raise AssertionError('Expected lost response')
        except ConnectionError:
            pass
        finish_scan(state,client)
        try:
            begin_scan(state,client,'tokens_pro','example.invalid','Profundo (Active)')
            raise AssertionError('Recovery should not start another engine')
        except ScanBusy:
            pass
        self.check('python_recovers_lost_real_commit_without_second_debit_or_report',
                   state['tokens_pro']==1 and self.balance()==1 and
                   int(self.sql('SELECT count(*) FROM public.escaneos;'))==before+1)

    def run(self):
        report={'postgres_version':None,'passed':self.passed,'database':self.database,
                'remote_connections':0,'server_stopped':False}
        report['migration_sha256']=hashlib.sha256((PROJECT/'supabase/updates/billing_scan_reservation.sql').read_bytes()).hexdigest()
        try:
            report['postgres_version']=self.command('postgres.exe','--version').strip()
            if not self.data.exists():
                self.command('initdb.exe','-D',self.data,'-U','postgres','-A','trust','--encoding=UTF8','--locale=C')
            # Start only this private cluster, bound to IPv4 loopback, no Windows service.
            self.command('pg_ctl.exe','-D',self.data,'-l',self.root/'postgres-validation.log',
                         '-o',f'-h 127.0.0.1 -p {self.port}','-w','start')
            self.started=True
            self.sql('CREATE DATABASE '+self.database+';',database='postgres')
            self.sql(baseline_sql())
            before=self.sql('SELECT jsonb_agg(to_jsonb(u) ORDER BY email) FROM public.usuarios u;')
            self.sql((PROJECT/'supabase/updates/billing_scan_reservation.sql').read_text(encoding='utf-8'))
            self.check('exact_migration_installs_and_preserves_existing_balances_profiles',before==
                       self.sql('SELECT jsonb_agg(to_jsonb(u) ORDER BY email) FROM public.usuarios u;'))
            self.tests()
            report['postcheck']=json.loads(self.sql((PROJECT/'supabase/tests/billing_scan_reservation_postcheck.sql').read_text(encoding='utf-8')))
            report['success']=True
        except Exception as error:
            report['success']=False
            report['error']=str(error)
            print('VALIDATION FAILED: '+str(error),flush=True)
        finally:
            for child in self.children:
                if child.poll() is None:
                    child.terminate(); child.wait(timeout=10)
            if self.started or (self.data/'postmaster.pid').exists():
                self.command('pg_ctl.exe','-D',self.data,'-m','fast','-w','stop')
                report['server_stopped']=True
            (self.root/'validation-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps({k:report[k] for k in ('success','server_stopped')},ensure_ascii=True),flush=True)
        return report['success']


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args()
    raise SystemExit(0 if Validation(args.root).run() else 1)
