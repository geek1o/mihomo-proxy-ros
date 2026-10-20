import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from agent.client import AgentError, RestClient, validate_connection
from agent.control import command, guard_request
from agent.model import SCHEMA, OWNER, desired_state, entity, validate_env
from agent.reconcile import Reconciler, digest, owned, plan
from agent.state import Store


class MockRouter:
    def __init__(self):
        self.data={p:[] for p in SCHEMA}; self.counter=0; self.calls=[]; self.fail=None; self.after_fail=False
    def preflight(self): return {'version':'7.23.8','policies':['read','write','rest-api']}
    def rows(self,path): return copy.deepcopy(self.data[path])
    def request(self,method,path,body=None):
        self.calls.append((method,path,copy.deepcopy(body)))
        fail=self.fail and self.fail(method,path,body)
        if fail and not self.after_fail: raise AgentError('Mock API unavailable')
        resource=path.rsplit('/',1)[0] if path.rsplit('/',1)[-1].startswith('*') else path
        rows=self.data[resource]
        if method=='PUT':
            self.counter+=1; row={'.id':'*'+str(self.counter),**body}; anchor=row.pop('place-before',None)
            index=next((i for i,r in enumerate(rows) if r['.id']==anchor),len(rows)); rows.insert(index,row)
            result=copy.deepcopy(row)
        elif method=='PATCH':
            row=next(r for r in rows if r['.id']==path.rsplit('/',1)[-1]); row.update(body); result=copy.deepcopy(row)
        elif method=='DELETE':
            rows[:]=[r for r in rows if r['.id']!=path.rsplit('/',1)[-1]]; result=None
        if fail: raise AgentError('Mock connection lost after write')
        return result


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.store=Store(self.tmp.name); self.router=MockRouter()
        self.agent=Reconciler(self.router,self.store)
        self.env={'GROUP':'test','TEST_SUFFIX':'example.org','TEST_IPCIDR':'203.0.113.0/24'}
        self.network={'profile':'existing','container_ip':'172.18.0.5'}
        self.desired=desired_state(self.env,self.network)
    def tearDown(self): self.tmp.cleanup()
    def apply(self,objects=None): return self.agent.apply(self.agent.preview(objects if objects is not None else self.desired))
    def test_apply_success(self):
        self.assertEqual(self.apply()['status'],'applied'); self.assertFalse(self.agent.preview(self.desired)['actions'])
    def test_second_apply_is_noop(self):
        self.apply(); n=len(self.router.calls); self.assertEqual(self.apply()['status'],'unchanged'); self.assertEqual(n,len(self.router.calls))
    def test_update_owned_only(self):
        self.apply(); desired=desired_state(self.env,{**self.network,'container_ip':'172.18.0.6'})
        self.apply(desired); self.assertEqual(self.router.calls[-1][0],'PATCH')
    def test_stale_managed_rules_removed(self):
        self.apply(); self.apply(desired_state({},self.network)); self.assertEqual(len(self.router.data['ip/dns/static']),0)
    def test_user_rules_preserved(self):
        user={'.id':'*user','chain':'forward','action':'drop','comment':'mine'}
        self.router.data['ip/firewall/filter']=[user.copy()]; self.apply(); self.apply([])
        self.assertEqual(self.router.data['ip/firewall/filter'],[user])
    def test_partial_failure_rolls_back(self):
        self.router.fail=lambda method,path,body: method=='PUT' and path=='ip/dns/static'
        with self.assertRaises(AgentError): self.apply()
        self.assertEqual(self.store.read('transaction.json')['status'],'rolled-back')
        self.assertFalse(any(self.router.data.values()))
    def test_unknown_create_outcome_no_duplicate(self):
        self.router.after_fail=True
        self.router.fail=lambda method,path,body: method=='PUT' and path=='ip/dns/static'
        with self.assertRaises(AgentError): self.apply()
        self.assertFalse(any(self.router.data.values()))
    def test_stale_preview(self):
        preview=self.agent.preview(self.desired)
        self.router.data['ip/firewall/filter'].append({'.id':'*user','comment':'new'})
        with self.assertRaises(AgentError): self.agent.apply(preview)
        self.assertFalse(self.router.calls)
    def test_expired_preview(self):
        preview=self.agent.preview(self.desired); preview['created']-=301
        with self.assertRaises(AgentError): self.agent.apply(preview)
    def test_manual_restore(self):
        self.apply(); self.assertEqual(self.agent.rollback()['status'],'rolled-back'); self.assertFalse(any(self.router.data.values()))
    def test_rollback_preserves_concurrent_edit(self):
        self.apply(); self.router.data['ip/firewall/address-list'][0]['address']='203.0.114.0/24'
        self.assertEqual(self.agent.rollback()['status'],'rollback-incomplete')
        self.assertEqual(self.router.data['ip/firewall/address-list'][0]['address'],'203.0.114.0/24')
    def test_duplicate_identifiers_fail_closed(self):
        self.apply(); self.router.data['ip/dns/static'].append(dict(self.router.data['ip/dns/static'][0], **{'.id':'*dup'}))
        with self.assertRaises(AgentError): self.agent.preview(self.desired)
    def test_unowned_name_conflict(self):
        self.router.data['ip/dns/static']=[{'.id':'*user','name':'example.org','type':'A','address':'192.0.2.1'}]
        with self.assertRaises(AgentError): self.agent.preview(self.desired)
    def test_dynamic_entries_never_deleted(self):
        row={'.id':'*dynamic','comment':OWNER+'test','dynamic':'true','list':'x','address':'192.0.2.1'}
        self.router.data['ip/firewall/address-list']=[row]; self.apply([])
        self.assertEqual(self.router.data['ip/firewall/address-list'],[row])
    def test_selective_profile(self):
        items=desired_state(self.env,{**self.network,'profile':'selective','client_subnet':'192.168.88.100/32','dns_capture':True})
        self.apply(items); self.assertFalse(self.agent.preview(items)['actions'])
        self.assertEqual(len(self.router.data['ip/firewall/nat']),4)
        self.assertTrue(all(x['src-address']=='!172.18.0.5' for x in self.router.data['ip/firewall/mangle']))
    def test_order_before_user_rules(self):
        self.router.data['ip/firewall/mangle']=[{'.id':'*user','comment':'user','chain':'prerouting','action':'drop'}]
        items=desired_state(self.env,{**self.network,'profile':'selective','client_subnet':'192.168.88.100/32'})
        self.apply(items); self.assertEqual(self.router.data['ip/firewall/mangle'][-1]['.id'],'*user')
    def test_shadowed_managed_rules_fail(self):
        items=desired_state(self.env,{**self.network,'profile':'selective','client_subnet':'192.168.88.100/32'})
        self.apply(items); self.router.data['ip/firewall/mangle'].insert(0,{'.id':'*user','chain':'prerouting'})
        with self.assertRaises(AgentError): self.agent.preview(items)
    def test_readonly_runtime_fields_not_replayed(self):
        self.apply(); row=self.router.data['ip/firewall/address-list'][0]
        row['creation-time']='today'; row['bytes']='999'; self.agent.rollback()
        self.assertFalse(any('bytes' in (call[2] or {}) for call in self.router.calls))
    def test_pending_journal_recovery_after_reboot(self):
        self.apply(); tx=self.store.read('transaction.json'); tx['status']='applying'; tx['actions'][-1]['state']='pending'
        self.store.write('transaction.json',tx)
        restarted=Reconciler(self.router,Store(self.tmp.name)); self.assertEqual(restarted.rollback()['status'],'rolled-back')
    def test_state_upgrade_preserves_files(self):
        self.store.write('env.json',{'LINK1':'secret'}); self.store.write('connection.json',{'password':'secret'})
        reopened=Store(self.tmp.name); self.assertEqual(reopened.read('env.json'),{'LINK1':'secret'})
        self.assertEqual(os.stat(Path(self.tmp.name)/'connection.json').st_mode & 0o777,0o600)
    def test_inflight_job_rejects_new_apply(self):
        self.store.write('job.json',{'status':'applying'})
        with self.assertRaises(AgentError): command(self.store,{'action':'preview'})
    def test_preview_hides_proxy_secret_values(self):
        self.store.write('connection.json',{'url':'https://10.0.0.1','username':'test','password':'password'})
        result=command(self.store,{'action':'preview','changes':{'LINK1':'secret-link'},'network':self.network},lambda c:self.router)
        self.assertNotIn('secret-link',json.dumps(result)); self.assertIn('LINK1',result['application_variables'])
    def test_status_hides_credentials(self):
        self.store.write('connection.json',{'password':'never-expose','username':'user'})
        result=command(self.store,{'action':'status'}); self.assertNotIn('never-expose',json.dumps(result))
    def test_store_excludes_parallel_writer(self):
        with self.store.lock():
            with self.assertRaises(AgentError):
                with self.store.lock(): pass


class ValidationTests(unittest.TestCase):
    def test_invalid_env_names(self):
        for key in ['PATH','LD_PRELOAD','A;id','HTTPD_CONF','RUNTIME_DIR','ORIGINAL_ENV_FILE']:
            with self.subTest(key=key),self.assertRaises(AgentError): validate_env({key:'bad'})
    def test_dpi_injection_rejected(self):
        for value in ['--x; id','$(id)','`id`','x\ny']:
            with self.subTest(value=value),self.assertRaises(AgentError): validate_env({'ZAPRET_CMD1':value})
    def test_invalid_network(self):
        for network in [{'profile':'oops'},{'profile':'existing','container_ip':'::1'},{'profile':'selective','container_ip':'172.18.0.5','client_subnet':'0.0.0.0/0'}]:
            with self.subTest(network=network),self.assertRaises(AgentError): desired_state({},network)
    def test_domain_and_ipv4_validation(self):
        for env in [{'GROUP':'x','X_DOMAIN':'example.org;exec'}, {'GROUP':'x','X_IPCIDR':'123.999.0.1'}]:
            with self.assertRaises(AgentError): desired_state(env,{'profile':'existing','container_ip':'172.18.0.5'})
    def test_direct_rule_excluded(self):
        state=desired_state({'RULES1':'DOMAIN,example.org,DIRECT;DOMAIN-SUFFIX,example.net,PROXY'}, {'profile':'existing','container_ip':'172.18.0.5'})
        self.assertEqual([o['fields']['name'] for o in state if o['path']=='ip/dns/static'],['example.net'])
    def test_connection_url_validation(self):
        for url in ['http://10.0.0.1','https://u:p@10.0.0.1','https://10.0.0.1/path','https://10.0.0.1/?secret=1']:
            with self.subTest(url=url),self.assertRaises(AgentError): validate_connection({'url':url,'username':'u','password':'p'})
    def test_forbidden_targets(self):
        for host in ['127.0.0.1','169.254.169.254','8.8.8.8']:
            with self.subTest(host=host),self.assertRaises(AgentError): validate_connection({'url':'https://'+host,'username':'u','password':'p'})
    def test_csrf_and_auth(self):
        env={'REMOTE_USER':'admin','REQUEST_METHOD':'POST','HTTP_HOST':'app:8088','HTTP_REFERER':'https://app:8088/index.html','BASIC_AUTH_HASH':'$6$changedhash'}
        guard_request(env,{'csrf':'token'},'token')
        for changes in [{'REMOTE_USER':''},{'HTTP_REFERER':'https://evil/'},{'REQUEST_METHOD':'GET'},{'BASIC_AUTH_HASH':'$1$mihomors$BipEGg3TOdgaQSFfGtisO1'}]:
            with self.subTest(changes=changes),self.assertRaises(AgentError): guard_request({**env,**changes},{'csrf':'token'},'token')
        with self.assertRaises(AgentError): guard_request(env,{'csrf':'wrong'},'token')
    def test_invalid_ca_rejected(self):
        with self.assertRaises(AgentError): RestClient({'url':'https://10.0.0.1','username':'u','password':'p','ca_pem':'invalid'})
    def test_manual_mode_generator_remains(self):
        source=Path('www/ui.js').read_text(); self.assertIn('function generateCommands()',source)
        self.assertIn('/container/envs/add',source); self.assertIn('/container/start',source)
    def test_shell_and_javascript_parse(self):
        for file in ['entrypoint.sh','www/cgi-bin/index.sh','www/cgi-bin/env-state']:
            subprocess.run(['sh','-n',file],check=True)
        subprocess.run(['node','--check','www/routeros.js'],check=True)
        subprocess.run(['node','--check','www/ui.js'],check=True)


if __name__=='__main__': unittest.main()
