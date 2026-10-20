"""Authenticated CGI operations; every router write runs in the supervisor."""
import hashlib
import hmac
import os
import secrets
import time
from urllib.parse import urlsplit
from .client import AgentError, RestClient
from .model import desired_state, validate_env
from .reconcile import Reconciler, digest
from .state import Store

BUSY = {'queued','validating','applying','restarting','recovering'}


def state_store():
    return Store(os.environ.get('MP_STATE_DIR','/data/agent'))


def assert_idle(store):
    if store.read('job.json',{}).get('status') in BUSY:
        raise AgentError('An operation is already running')


def csrf(store):
    token = store.read('csrf.json')
    if not token:
        token = secrets.token_urlsafe(32); store.write('csrf.json',token)
    return token


def guard_request(env, body, token):
    # BusyBox httpd exports REMOTE_USER after Basic Auth. The unauthenticated
    # subscription helper never copies this CGI into its document root.
    if not env.get('REMOTE_USER'):
        raise AgentError('WebUI authentication is required')
    if env.get('REQUEST_METHOD') != 'POST':
        raise AgentError('POST required')
    referer, host = env.get('HTTP_REFERER',''), env.get('HTTP_HOST','')
    parsed = urlsplit(referer)
    if parsed.scheme not in ('http','https') or parsed.netloc != host or not host:
        raise AgentError('Same-origin Referer required')
    supplied = body.get('csrf','')
    if not isinstance(supplied,str) or not hmac.compare_digest(supplied,token):
        raise AgentError('Invalid CSRF token')
    default = '$1$mihomors$BipEGg3TOdgaQSFfGtisO1'
    if env.get('BASIC_AUTH_HASH',default) == default:
        raise AgentError('Change the default WebUI password before enabling Automatic Mode')


def effective_env(store, changes=None):
    result = dict(store.read('base-env.json',{}))
    for key,value in {**store.read('env.json',{}), **(changes or {})}.items():
        if value == '': result.pop(key,None)
        else: result[key] = value
    return result


def public_status(store):
    conn = store.read('connection.json',{})
    job = store.read('job.json',{})
    tx = store.read('transaction.json',{})
    return {'ok':True,'csrf':csrf(store),'connection':{k:v for k,v in conn.items() if k != 'password'},
            'has_password':bool(conn.get('password')), 'network':store.read('network.json',{
                'profile':'existing','container_ip':os.environ.get('MP_CONTAINER_IP','')}),
            'job':{k:v for k,v in job.items() if k in {'id','status','error','started','finished','result','strategy'}},
            'transaction':{'id':tx.get('id'),'status':tx.get('status'),
                           'actions':len(tx.get('actions',[]))},
            'history':store.read('history.json',[])}


def command(store, body, client_factory=RestClient):
    action = body.get('action')
    if action == 'status': return public_status(store)
    assert_idle(store)
    if action == 'connect':
        previous = store.read('connection.json',{})
        conn = body.get('connection',{})
        if not isinstance(conn,dict) or set(conn)-{'url','username','password','ca_pem'}:
            raise AgentError('Invalid connection parameters')
        conn = dict(conn)
        if not conn.get('password') and conn.get('url')==previous.get('url') and conn.get('username')==previous.get('username'):
            conn['password'] = previous.get('password','')
        if store.read('transaction.json',{}).get('status') in {'applying','interrupted','rollback-incomplete'}:
            raise AgentError('Recover the interrupted transaction before changing connection')
        result = client_factory(conn).preflight()
        store.write('connection.json',conn)
        return {'ok':True,'capabilities':result}
    conn = store.read('connection.json')
    if not conn: raise AgentError('Connect RouterOS first')
    if action == 'preview':
        changes = validate_env(body.get('changes',{}))
        network = body.get('network',store.read('network.json',{}))
        if len(str(network)) > 4096: raise AgentError('Network settings exceed limit')
        env = effective_env(store,changes)
        desired = desired_state(env,network)
        client = client_factory(conn)
        capabilities = client.preflight()
        # Confirm LAN list and router/container separation before proposing PBR.
        if network.get('profile') == 'selective':
            if not any(r.get('name')==network.get('lan_list','LAN') for r in client.rows('interface/list')):
                raise AgentError('LAN interface list does not exist')
            if network['container_ip'] == urlsplit(conn['url']).hostname:
                raise AgentError('Container IP must differ from RouterOS management IP')
        preview = Reconciler(client,store).preview(desired)
        preview.update(changes=changes, network=network, connection=digest(conn),
                       restart_files=bool(body.get('restart_files',False)),
                       previous_env=store.read('env.json',{}), previous_network=store.read('network.json',{}))
        # Bind every setting, including local changes, to the reviewed plan.
        preview['token'] = digest(preview)
        store.write('preview.json',preview)
        return {'ok':True,'token':preview['token'],'capabilities':capabilities,
                'changes':[{'kind':a['kind'],'path':a['path'],'fields':a['after'] or a['before']} for a in preview['actions']],
                'application_variables':sorted(changes),
                'warnings':['RouterOS REST is not transactional; compensation can fail when API is unavailable.',
                            'Selective routing is IPv4 only. Client DoH, IPv6 and pre-existing connections need separate checks.',
                            'Proxy settings are validated before RouterOS changes. Some settings require a proxy worker restart.']}
    if action in ('apply','recover'):
        if action == 'apply':
            preview = store.read('preview.json',{})
            if not hmac.compare_digest(str(body.get('token','')),str(preview.get('token','!'))):
                raise AgentError('Generate and review a preview first')
            if time.time()-preview.get('created',0)>300 or preview.get('connection') != digest(conn):
                raise AgentError('Preview expired or connection changed')
        elif store.read('transaction.json',{}).get('status') == 'rolled-back':
            raise AgentError('Configuration is already restored')
        job = {'id':secrets.token_hex(12),'action':action,'status':'queued','started':time.time(),
               'connection':digest(conn)}
        if action == 'apply': job['preview'] = preview
        store.write('job.json',job)
        return {'ok':True,'job':{'id':job['id'],'status':'queued'}}
    raise AgentError('Unsupported operation')
