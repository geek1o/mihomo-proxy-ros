"""PID 1 owns the proxy worker. RouterOS writes survive a worker restart."""
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import time
import urllib.request
from .client import AgentError, RestClient
from .control import BUSY, effective_env, state_store
from .model import env_allowed
from .reconcile import Reconciler, digest

ENTRYPOINT = '/entrypoint.sh'


def proxy_env(store):
    env = dict(os.environ)
    env.pop('MP_UI_PASSWORD',None)
    for k,v in store.read('env.json',{}).items():
        if v: env[k]=v
        else: env.pop(k,None)
    return env


def mihomo_request(store, method='GET', body=None):
    env = proxy_env(store)
    req = urllib.request.Request('http://127.0.0.1:9090/configs',method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Authorization':'Bearer '+env.get('UI_SECRET',''),'Content-Type':'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req,timeout=3) as response:
        return json.loads(response.read()) if method=='GET' else None


def validate_candidate(store, changes):
    env = proxy_env(store)
    for key,value in changes.items():
        if value: env[key]=value
        else: env.pop(key,None)
    # Generate into a separate tmpfs tree. Do not touch live config or networking.
    with tempfile.TemporaryDirectory(prefix='mpr-check-',dir='/dev/shm') as tmp:
        config_copy=tmp+'/config'
        shutil.copytree('/root/.config/mihomo',config_copy,ignore=shutil.ignore_patterns('ui','cache.db'),dirs_exist_ok=True)
        env.update(MP_GENERATE_ONLY='1',CONFIG_DIR=config_copy,HS5T_DIR=tmp+'/hs5t',RUNTIME_DIR=tmp,
                   ORIGINAL_ENV_FILE=tmp+'/original-envs')
        try:
            result = subprocess.run(['/bin/sh',ENTRYPOINT],env=env,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
        except (OSError,subprocess.TimeoutExpired):
            raise AgentError('Proxy configuration validation failed or timed out') from None
        if result.returncode:
            raise AgentError('Mihomo rejected the generated configuration; inspect YAML in Manual Mode')


def history(store,job):
    entries=store.read('history.json',[])
    entries.append({k:v for k,v in job.items() if k in {'id','status','error','started','finished','strategy','result'}})
    store.write('history.json',entries[-30:])


class Supervisor:
    def __init__(self,store):
        self.store=store; self.worker=None; self.stopping=False

    def stop_worker(self):
        if self.worker:
            try: os.killpg(self.worker.pid,signal.SIGTERM)
            except ProcessLookupError: pass
            try: self.worker.wait(timeout=12)
            except subprocess.TimeoutExpired:
                try: os.killpg(self.worker.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                self.worker.wait()
            self.worker=None

    def start_worker(self):
        self.worker=subprocess.Popen(['/bin/sh',ENTRYPOINT],env=proxy_env(self.store),start_new_session=True,
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    def ready(self,timeout=80):
        end=time.monotonic()+timeout
        while time.monotonic()<end and not self.stopping:
            if self.worker and self.worker.poll() is not None: return False
            try:
                mihomo_request(self.store)
                # BusyBox must be up too (it starts after static rendering).
                import socket
                with socket.create_connection(('127.0.0.1',80),timeout=1): return True
            except Exception: time.sleep(1)
        return False

    def run_job(self,job):
        store=self.store
        with store.lock():
            conn=store.read('connection.json')
            if digest(conn)!=job['connection']: raise AgentError('Connection changed')
            client=RestClient(conn); client.preflight()
            reconciler=Reconciler(client,store)
            if job['action']=='recover':
                job['status']='recovering'; store.write('job.json',job)
                result=reconciler.rollback()
                if result['status']!='rolled-back': raise AgentError('RouterOS recovery incomplete; retry after restoring API access')
                saved=store.read('local-recovery.json')
                if saved:
                    store.write('env.json',saved['env']); store.write('network.json',saved['network'])
                    self.stop_worker(); self.start_worker()
                    if not self.ready(): raise AgentError('RouterOS restored, but proxy worker did not recover')
                job['result']=result
            else:
                preview=job['preview']; changes=preview['changes']
                job['status']='validating'; store.write('job.json',job)
                validate_candidate(store,changes)
                store.write('local-recovery.json',{'env':preview['previous_env'],'network':preview['previous_network']})
                job['status']='applying'; store.write('job.json',job)
                result=reconciler.apply(preview)
                old=store.read('env.json',{})
                new={**old,**changes}
                store.write('env.json',new); store.write('network.json',preview['network'])
                changed={k for k,v in changes.items() if effective_env_from(old,k)!=effective_env_from(new,k)}
                job['strategy']='none'
                if changed and changed<={'LOG_LEVEL'}:
                    try:
                        mihomo_request(store,'PATCH',{'log-level':effective_env(store).get('LOG_LEVEL','error')})
                        if mihomo_request(store).get('log-level')!=effective_env(store).get('LOG_LEVEL','error'):
                            raise AgentError('Mihomo hot reload verification failed')
                        # CGI/static env is refreshed on next worker restart. The
                        # browser re-bases its draft after a successful operation.
                        job['strategy']='mihomo-hot-reload'
                        subprocess.run(['/bin/sh','/www/render_static.sh'],env={**proxy_env(store),'WWW_DIR':'/dev/shm/web'},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
                    except Exception:
                        store.write('env.json',old)
                        reconciler.rollback()
                        raise AgentError('Mihomo hot reload failed; previous settings restored') from None
                elif changed or job['preview'].get('restart_files'):
                    job['strategy']='proxy-worker-restart'; job['status']='restarting'; store.write('job.json',job)
                    # Give the CGI accepting the job time to flush its response.
                    time.sleep(1)
                    self.stop_worker(); self.start_worker()
                    if not self.ready():
                        store.write('env.json',old)
                        recovery=reconciler.rollback()
                        self.stop_worker(); self.start_worker()
                        recovered=self.ready()
                        raise AgentError('Proxy worker restart failed; router '+recovery['status']+
                                         '; old worker '+('recovered' if recovered else 'unavailable'))
                job['result']=result
            job['status']='succeeded'; job['finished']=time.time()
            store.write('job.json',job); history(store,job)

    def run(self):
        def stop(*_): self.stopping=True
        signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
        existing=self.store.read('job.json',{})
        if existing.get('status') in BUSY:
            existing.update(status='interrupted',error='Supervisor restarted; inspect journal and recover explicitly')
            self.store.write('job.json',existing)
        self.start_worker()
        while not self.stopping:
            job=self.store.read('job.json',{})
            if job.get('status')=='queued':
                try: self.run_job(job)
                except AgentError as e:
                    job.update(status='failed',error=str(e),finished=time.time())
                    self.store.write('job.json',job); history(self.store,job)
                except Exception:
                    job.update(status='failed',error='Controller operation failed; inspect recovery status',finished=time.time())
                    self.store.write('job.json',job); history(self.store,job)
            if self.worker and self.worker.poll() is not None:
                # Bounded backoff; no change to router configuration on boot.
                time.sleep(3)
                if not self.stopping: self.start_worker()
            time.sleep(.5)
        self.stop_worker()


def effective_env_from(overrides,key):
    return overrides.get(key,os.environ.get(key,''))


def main():
    store=state_store()
    password=os.environ.get('MP_UI_PASSWORD')
    if password:
        result=subprocess.run(['openssl','passwd','-6','-stdin'],input=password+'\n',text=True,capture_output=True,check=True)
        os.environ['BASIC_AUTH_HASH']=result.stdout.strip()
    elif not os.environ.get('BASIC_AUTH_HASH'):
        # Regular-container installations must provide a non-default WebUI hash.
        # Preserve Manual Mode defaults; the automatic endpoint refuses admin/admin.
        pass
    if not os.environ.get('UI_SECRET'):
        import secrets
        secret=store.read('mihomo-secret.json') or secrets.token_urlsafe(32)
        store.write('mihomo-secret.json',secret); os.environ['UI_SECRET']=secret
    store.write('base-env.json',{k:v for k,v in os.environ.items() if env_allowed(k)})
    Supervisor(store).run()


if __name__=='__main__': main()
