"""Typed desired state. Object names are isolated from legacy/user-owned objects."""
import hashlib
import ipaddress
import os
import re
from .client import AgentError

OWNER = 'managed-by=mihomo-proxy-ros;instance=geek1o;id='
# Only these writable properties are ever sent back to RouterOS. Runtime fields,
# flags, counters and secrets from snapshots are never replayed.
SCHEMA = {
    'interface/veth': 'name address gateway disabled',
    'ip/address': 'address interface disabled',
    'ip/dns/forwarders': 'name dns-servers',
    'ip/dns/static': 'name type forward-to address-list match-subdomain disabled',
    'routing/table': 'name fib disabled',
    'ip/route': 'dst-address gateway routing-table distance blackhole disabled',
    'routing/rule': 'action src-address dst-address interface table disabled',
    'ip/firewall/address-list': 'list address disabled',
    'ip/firewall/filter': 'chain action connection-mark connection-state in-interface-list src-address dst-address protocol dst-port disabled',
    'ip/firewall/nat': 'chain action in-interface-list src-address-list src-address dst-address protocol dst-port to-addresses to-ports disabled',
    'ip/firewall/mangle': 'chain action in-interface-list src-address-list src-address dst-address dst-address-list dst-address-type connection-state connection-mark new-connection-mark new-routing-mark passthrough disabled',
}
SCHEMA = {k: set(v.split()) | {'comment'} for k, v in SCHEMA.items()}
ORDERED = {'ip/firewall/filter', 'ip/firewall/nat', 'ip/firewall/mangle', 'routing/rule'}
# Names actually referenced by the original entrypoint; generated in source control.
from .env_names import ENV_NAMES
SUFFIXES = set('GEOSITE GEOIP AS PRIORITY KEYWORD DOMAIN SUFFIX PROCESS SRCIPCIDR IPCIDR DSTPORT DSCP USE PROXIES HIDDEN TYPE URL INTERVAL TOLERANCE STRATEGY FILTER EXCLUDE HEADERS PROXY DIALER_PROXY AMNEZIA_COUNTRY PACKETS CMD BASE64 GATEWAY'.split())


def env_allowed(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,100}', name):
        return False
    if name in {'HTTPD_CONF','ORIGINAL_ENV_FILE','RUNTIME_DIR','WEB_API_PORT','AMNEZIA_PREMIUM_PUBLIC_KEY_FILE'}:
        return False
    return (name in ENV_NAMES or bool(re.fullmatch(
        r'(LINK|SUB_LINK|SOCKS|MIXED_IN_USER|RULE_SET|RULES|FAKE_IP_FILTER|ZAPRET_CMD|ZAPRET2_CMD|BYEDPI_CMD)[0-9]+(?:_[A-Z_]+)?', name))
        or name.rsplit('_', 1)[-1] in SUFFIXES)


def validate_env(env):
    if not isinstance(env, dict) or len(env) > 1500:
        raise AgentError('Invalid application environment')
    for name, value in env.items():
        if not env_allowed(name) or not isinstance(value, str) or len(value) > 65536 or '\x00' in value:
            raise AgentError('Invalid application variable: ' + str(name)[:100])
        if name == 'BASIC_AUTH_HASH' and value and not re.fullmatch(r'\$[156]\$[^\s:]{8,200}', value):
            raise AgentError('WebUI requires a crypt password hash')
        if name == 'BASIC_AUTH_USER' and not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value):
            raise AgentError('Invalid WebUI username')
        if name in ('BYEDPI_CMD', 'ZAPRET_CMD', 'ZAPRET2_CMD') or re.fullmatch(r'(BYEDPI|ZAPRET|ZAPRET2)_CMD\d+', name):
            # The legacy scripts parse these as program arguments. Do not accept
            # shell syntax in newly supplied strategies.
            if any(c in value for c in ('\n', '\r', '`', '$(', ';', '|', '&&', '>','<')):
                raise AgentError('Shell syntax is forbidden in DPI arguments')
    return env


def owner_prefix():
    instance=os.environ.get('MP_INSTANCE_ID','geek1o')
    if not re.fullmatch(r'[a-z0-9]{1,20}',instance): raise AgentError('Invalid installation ID')
    return OWNER.replace('instance=geek1o;','instance='+instance+';')


def tag(key):
    return owner_prefix() + hashlib.sha256(key.encode()).hexdigest()[:24]


def entity(path, key, **fields):
    if path not in SCHEMA or set(fields) - SCHEMA[path]:
        raise AgentError('Unsupported object fields')
    return {'path': path, 'key': key, 'fields': dict(fields, comment=tag(path + ':' + key))}


def ipv4(value, network=False):
    try:
        parsed = ipaddress.ip_network(value, strict=False) if network else ipaddress.ip_address(value)
        if parsed.version != 4:
            raise ValueError()
        return str(parsed)
    except ValueError:
        raise AgentError('Invalid IPv4 address or network') from None


def domain(value):
    try:
        value = value.rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, AttributeError):
        raise AgentError('Invalid domain') from None
    if len(value) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or '..' in value:
        raise AgentError('Invalid domain')
    return value


def router_items(env):
    domains, ips = {}, set()
    for group in env.get('GROUP', '').split(','):
        group = group.strip()
        if not group:
            continue
        prefix = re.sub(r'[^A-Z0-9_]', '_', group.upper())
        for suffix, exact in (('SUFFIX', False), ('DOMAIN', True)):
            for item in env.get(prefix + '_' + suffix, '').split(','):
                if item.strip():
                    name = domain(item.strip())
                    domains[name] = domains.get(name, True) and exact
        ips.update(ipv4(v.strip(), True) for v in env.get(prefix + '_IPCIDR', '').split(',') if v.strip())
    for name, value in env.items():
        if not re.fullmatch(r'RULES[0-9]+', name):
            continue
        for line in value.split(';'):
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 3 or parts[2].upper() == 'DIRECT':
                continue
            if parts[0] in ('DOMAIN', 'DOMAIN-SUFFIX'):
                d = domain(parts[1]); domains[d] = domains.get(d, True) and parts[0] == 'DOMAIN'
            elif parts[0] == 'IP-CIDR':
                ips.add(ipv4(parts[1], True))
    return domains, ips


def desired_state(env, network):
    validate_env(env)
    if not isinstance(network, dict) or set(network) - {'profile','container_ip','lan_list','client_subnet','dns_capture','veth','veth_address','veth_gateway'}:
        raise AgentError('Unknown network parameters')
    profile = network.get('profile', 'existing')
    if profile not in ('existing', 'selective', 'disabled'):
        raise AgentError('Invalid network profile')
    if profile == 'disabled':
        return []
    container_ip = ipv4(network.get('container_ip', ''))
    name = 'mpr-'+os.environ.get('MP_INSTANCE_ID','geek1o')
    domains, ips = router_items(env)
    objects = [entity('ip/dns/forwarders', 'dns', name=name, **{'dns-servers': container_ip})]
    for d, exact in sorted(domains.items()):
        objects.append(entity('ip/dns/static', d, name=d, type='FWD', **{
            'forward-to': name, 'address-list': name, 'match-subdomain': 'false' if exact else 'true', 'disabled':'false'}))
    for ip in sorted(ips):
        objects.append(entity('ip/firewall/address-list', ip, list=name, address=ip, disabled='false'))
    if profile == 'existing':
        return objects
    lan = network.get('lan_list', 'LAN')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', lan):
        raise AgentError('Invalid LAN interface list')
    clients = ipv4(network.get('client_subnet', ''), True)
    if ipaddress.ip_network(clients).prefixlen < 8:
        raise AgentError('Select a bounded client subnet (at least /8)')
    veth = network.get('veth', '')
    if veth:
        if not re.fullmatch(r'mpr-[A-Za-z0-9_.-]{1,48}', veth):
            raise AgentError('New VETH names must start with mpr-')
        addr = network.get('veth_address', '')
        if str(ipaddress.ip_interface(addr).ip) != container_ip:
            raise AgentError('VETH address must match container IP')
        objects.insert(0, entity('interface/veth','veth',name=veth,address=addr,gateway=ipv4(network.get('veth_gateway',''))))
        gateway = ipv4(network.get('veth_gateway',''))
        objects.insert(1,entity('ip/address','veth-gateway',address=gateway+'/'+addr.split('/')[1],interface=veth))
    objects += [entity('routing/table','table',name=name,fib='true'),
                entity('ip/route','default', **{'dst-address':'0.0.0.0/0','gateway':container_ip+'@main','routing-table':name,'distance':'1','disabled':'false'})]
    # Protect all local destinations, not only the router's own addresses.
    # These routes stay inside our table and never touch main.
    for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4'):
        objects.append(entity('ip/route','block-'+net, **{'dst-address':net,'routing-table':name,'blackhole':'true','distance':'254'}))
    objects.append(entity('ip/firewall/address-list','clients',list=name+'-clients',address=clients,disabled='false'))
    match = {'chain':'prerouting','in-interface-list':lan,'src-address-list':name+'-clients','src-address':'!'+container_ip,'dst-address-type':'!local'}
    for destkey, dest in (('dst-address-list',name), ('dst-address',ipv4(env.get('FAKE_IP_RANGE','198.18.0.0/15'),True))):
        objects.append(entity('ip/firewall/mangle','mark-'+destkey, **match, **{destkey:dest}, action='mark-connection',
                              **{'connection-mark':'no-mark','new-connection-mark':name,'passthrough':'true'}))
    objects.append(entity('ip/firewall/mangle','route', **match, action='mark-routing',
                          **{'connection-mark':name,'new-routing-mark':name,'passthrough':'false'}))
    # Existing FastTrack rules are never rewritten. Only established marked
    # connections are accepted ahead of them; new flows retain the user's policy.
    objects.append(entity('ip/firewall/filter','no-fasttrack',chain='forward',action='accept',
                          **{'connection-mark':name,'connection-state':'established,related'}))
    if network.get('dns_capture'):
        for proto in ('tcp','udp'):
            objects.append(entity('ip/firewall/nat','dns-'+proto,chain='dstnat',action='dst-nat',protocol=proto,
                                  **{'in-interface-list':lan,'src-address-list':name+'-clients','src-address':'!'+container_ip,'dst-port':'53',
                                     'to-addresses':container_ip,'to-ports':'53'}))
        # Hairpin LAN clients need replies to go back through conntrack.
        objects.append(entity('ip/firewall/nat','dns-hairpin',chain='srcnat',action='masquerade',
                              **{'src-address':clients,'dst-address':container_ip,'dst-port':'53','protocol':'udp'}))
        objects.append(entity('ip/firewall/nat','dns-hairpin-tcp',chain='srcnat',action='masquerade',
                              **{'src-address':clients,'dst-address':container_ip,'dst-port':'53','protocol':'tcp'}))
    rank = {p:i for i,p in enumerate(SCHEMA)}
    return sorted(objects,key=lambda o:rank[o['path']])
