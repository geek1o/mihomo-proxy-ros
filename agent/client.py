"""Small, bounded REST transport. No insecure TLS switch, redirects or CLI execution."""
import base64
import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request


class AgentError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AgentError('RouterOS redirects are forbidden')


def validate_connection(config):
    url = config.get('url', '')
    p = urllib.parse.urlsplit(url)
    if (p.scheme != 'https' or not p.hostname or p.username or p.password
            or p.query or p.fragment or p.path not in ('', '/', '/rest', '/rest/')):
        raise AgentError('Use https://router:port without credentials, query or extra path')
    try:
        port = p.port or 443
    except ValueError:
        raise AgentError('Invalid port') from None
    if not 1 <= port <= 65535:
        raise AgentError('Invalid port')
    if not isinstance(config.get('username'), str) or not config['username'] or ':' in config['username']:
        raise AgentError('Invalid RouterOS username')
    if not isinstance(config.get('password'), str) or not config['password']:
        raise AgentError('RouterOS password is required')
    # This controller is for routers on private management networks. Block metadata,
    # localhost and public services even if somebody supplies their name in the UI.
    try:
        addresses = socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
    except OSError:
        raise AgentError('RouterOS hostname cannot be resolved') from None
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise AgentError('RouterOS must resolve to a private management address')
    return url.rstrip('/').removesuffix('/rest') + '/rest'


class RestClient:
    def __init__(self, config):
        self.base = validate_connection(config)
        try:
            context = ssl.create_default_context(cadata=config.get('ca_pem') or None)
        except (ValueError, ssl.SSLError):
            raise AgentError('Invalid CA certificate PEM') from None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        raw = (config['username'] + ':' + config['password']).encode()
        self.auth = 'Basic ' + base64.b64encode(raw).decode()

    def request(self, method, path, body=None):
        if not path or any(x in path for x in ('..', '?', '#', '://')):
            raise AgentError('Invalid REST path')
        req = urllib.request.Request(self.base + '/' + path,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Authorization': self.auth, 'Content-Type': 'application/json'},
                                     method=method)
        try:
            with self.opener.open(req, timeout=10) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise AgentError('RouterOS response exceeds limit')
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raise AgentError('RouterOS HTTP ' + str(e.code)) from None
        except (OSError, ValueError, urllib.error.URLError):
            raise AgentError('RouterOS unavailable, invalid response or TLS verification failed') from None

    def rows(self, path):
        data = self.request('GET', path)
        if not isinstance(data, list):
            raise AgentError('Expected RouterOS object list: ' + path)
        return data

    def preflight(self):
        resource = self.request('GET', 'system/resource')
        if isinstance(resource, list):
            resource = resource[0]
        version = resource.get('version', '')
        import re
        m = re.match(r'7\.(\d+)', version)
        if not m or int(m[1]) < 21:
            raise AgentError('RouterOS 7.21+ required for DNS forwarders and this agent')
        # Never probe write access by creating a disposable object on a real router.
        # Read the effective login policy instead. Fail closed if it is not visible.
        active = self.rows('user/active')
        username = base64.b64decode(self.auth[6:]).decode().split(':', 1)[0]
        policies = []
        for row in active:
            if row.get('name') == username and row.get('via') in ('rest-api', 'web', 'api'):
                policies += str(row.get('policy', '')).split(',')
        if not any(policies):
            users = self.rows('user')
            groups = self.rows('user/group')
            group_names = {x.get('group') for x in users if x.get('name') == username}
            policies = [p for x in groups if x.get('name') in group_names
                        for p in str(x.get('policy', '')).split(',')]
        if not {'read', 'write', 'rest-api'} <= set(policies):
            raise AgentError('Cannot verify effective policies read,write,rest-api; no writes performed')
        return {'version': version, 'architecture': resource.get('architecture-name'),
                'policies': sorted(set(policies)), 'tls_verified': True}
