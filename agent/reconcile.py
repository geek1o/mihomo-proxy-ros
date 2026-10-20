"""Reconciliation with durable write-ahead journal and conservative compensation.

RouterOS has no REST transactions. Unknown write outcomes are resolved by reading
back the owned comment, never by blindly retrying PUT or deleting by name.
"""
import hashlib
import json
import time
import uuid
from .client import AgentError
from .model import OWNER, ORDERED, SCHEMA


def clean(path, row):
    return {k: str(v) for k, v in row.items() if k in SCHEMA[path]}


def owned(row):
    return str(row.get('comment','')).startswith(OWNER) and row.get('dynamic') != 'true'


def same(actual, expected):
    def norm(v):
        return {'yes':'true','no':'false'}.get(str(v), str(v))
    return all(norm(actual.get(k,'')) == norm(v) for k,v in expected.items())


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',',':')).encode()).hexdigest()


def snapshot(client, paths):
    result = {}
    for path in sorted(paths):
        rows = client.rows(path)
        result[path] = [{'.id':r['.id'], **clean(path,r)} for r in rows
                        if r.get('dynamic') != 'true']
        tags = [r.get('comment') for r in result[path] if owned(r)]
        if len(tags) != len(set(tags)):
            raise AgentError('Duplicate ownership identifiers: ' + path)
    return result


def plan(desired, actual):
    actions, targets = [], {}
    for obj in desired:
        path, fields = obj['path'], obj['fields']
        marker = fields['comment']
        targets.setdefault(path, set()).add(marker)
        rows = actual.get(path, [])
        found = next((r for r in rows if r.get('comment') == marker), None)
        # Never adopt somebody else's named resource or silently shadow DNS.
        for row in rows:
            if owned(row): continue
            conflict = ('name' in fields and row.get('name') == fields['name'])
            if path == 'ip/dns/static':
                conflict = row.get('name') == fields['name']
            if conflict:
                raise AgentError('User-owned object conflicts with desired state: ' + path)
        anchor = next((r['.id'] for r in rows if not owned(r)), None) if path in ORDERED else None
        if not found:
            if path in ORDERED:
                following = [o['fields']['comment'] for o in desired[desired.index(obj)+1:] if o['path']==path]
                anchor = next((r['.id'] for marker in following for r in rows if r.get('comment')==marker), anchor)
            actions.append({'kind':'create','path':path,'before':None,'after':fields,'anchor':anchor})
        elif not same(found, fields):
            actions.append({'kind':'update','path':path,'before':found,'after':fields})
    # Remove consumers before providers (reverse schema order), after additions.
    for path in reversed(list(SCHEMA)):
        for row in actual.get(path, []):
            if owned(row) and row['comment'] not in targets.get(path,set()):
                next_id = None
                rows = actual[path]
                index = rows.index(row)
                if path in ORDERED and index + 1 < len(rows): next_id = rows[index+1]['.id']
                actions.append({'kind':'delete','path':path,'before':row,'after':None,'anchor':next_id})
    # Existing managed firewall rules must remain ahead of unowned rules and in
    # desired order. Do not silently move rules under a concurrent administrator.
    for path in ORDERED:
        target_order = [o['fields']['comment'] for o in desired if o['path'] == path]
        rows = actual.get(path,[])
        existing = [r['comment'] for r in rows if owned(r) and r['comment'] in target_order]
        wanted = [x for x in target_order if x in existing]
        if existing != wanted:
            raise AgentError('Managed rule order changed; restore order before applying: ' + path)
        first_user = next((i for i,r in enumerate(rows) if not owned(r)),len(rows))
        if any(owned(r) and r['comment'] in target_order for r in rows[first_user:]):
            raise AgentError('Managed rules are shadowed by user rules: ' + path)
    return actions


class Reconciler:
    def __init__(self, client, store):
        self.client, self.store = client, store

    def preview(self, desired):
        # Include all paths so stale rules can be removed after disabling a profile.
        actual = snapshot(self.client, SCHEMA)
        actions = plan(desired, actual)
        result = {'desired':desired,'actual':actual,'actions':actions,'created':time.time()}
        result['token'] = digest(result)
        return result

    def _find(self, path, marker):
        rows = [r for r in self.client.rows(path) if r.get('comment') == marker and owned(r)]
        if len(rows) > 1: raise AgentError('Ambiguous owned object')
        return rows[0] if rows else None

    def apply(self, preview):
        if time.time() - preview['created'] > 300:
            raise AgentError('Preview expired; generate a new preview')
        current = snapshot(self.client, SCHEMA)
        if digest(current) != digest(preview['actual']):
            raise AgentError('RouterOS configuration changed after preview')
        if not preview['actions']:
            return {'status':'unchanged','id':None}
        previous = self.store.read('transaction.json',{})
        if previous.get('status') in ('applying','rollback-incomplete','interrupted'):
            raise AgentError('An interrupted transaction requires recovery first')
        tx = {'id':str(uuid.uuid4()),'status':'applying','time':time.time(),
              'actions':[], 'before':preview['actual']}
        self.store.write('transaction.json',tx)
        try:
            for action in preview['actions']:
                record = dict(action, state='pending')
                tx['actions'].append(record)
                self.store.write('transaction.json',tx)
                path = action['path']
                marker = (action['after'] or action['before'])['comment']
                actual = self._find(path, marker)
                if action['before']:
                    if not actual or not same(actual, clean(path,action['before'])):
                        raise AgentError('Managed object changed during apply')
                elif actual:
                    raise AgentError('Owned object appeared during apply')
                if action['kind'] == 'create':
                    fields = dict(action['after'])
                    if action.get('anchor'): fields['place-before'] = action['anchor']
                    self.client.request('PUT',path,fields)
                elif action['kind'] == 'update':
                    delta = {k:v for k,v in action['after'].items() if not same(actual,{k:v})}
                    self.client.request('PATCH',path+'/'+actual['.id'],delta)
                else:
                    self.client.request('DELETE',path+'/'+actual['.id'])
                actual = self._find(path,marker)
                if action['after']:
                    if not actual or not same(actual,action['after']):
                        raise AgentError('Read-back verification failed')
                elif actual:
                    raise AgentError('Deleted object still exists')
                record['state'] = 'done'
                self.store.write('transaction.json',tx)
            remaining = plan(preview['desired'],snapshot(self.client,SCHEMA))
            if remaining: raise AgentError('Reconciliation verification failed')
            tx['status'] = 'applied'
            tx['after'] = snapshot(self.client,SCHEMA)
            self.store.write('transaction.json',tx)
            return {'id':tx['id'],'status':'applied'}
        except Exception:
            # Do not log API bodies or exceptions that could contain secret values.
            tx['status'] = 'failed'
            self.store.write('transaction.json',tx)
            result = self.rollback(tx)
            raise AgentError('Apply failed; '+result['status']+'; see operation journal') from None

    def rollback(self, tx=None):
        tx = tx or self.store.read('transaction.json',{})
        if not tx.get('actions'): raise AgentError('No transaction to restore')
        failures = 0
        for action in reversed(tx['actions']):
            if action.get('state') == 'restored': continue
            path = action['path']
            marker = (action['after'] or action['before'])['comment']
            try:
                actual = self._find(path,marker)
                before = clean(path,action['before']) if action['before'] else None
                after = action['after']
                if before is None:
                    if actual:
                        if not same(actual,after): raise AgentError('Owned object drifted')
                        self.client.request('DELETE',path+'/'+actual['.id'])
                elif after is None:
                    if actual:
                        if not same(actual,before): raise AgentError('Owned object drifted')
                    else:
                        body = dict(before)
                        if action.get('anchor') and any(r['.id']==action['anchor'] for r in self.client.rows(path)):
                            body['place-before'] = action['anchor']
                        self.client.request('PUT',path,body)
                else:
                    if not actual: raise AgentError('Owned object disappeared')
                    # Only restore fields touched by this action, preserve all others.
                    touched = {k:v for k,v in after.items() if not same(action['before'],{k:v})}
                    if not same(actual,touched) and not same(actual,{k:before.get(k,'') for k in touched}):
                        raise AgentError('Owned object drifted')
                    self.client.request('PATCH',path+'/'+actual['.id'],{k:before.get(k,'') for k in touched})
                restored = self._find(path,marker)
                if (before is None and restored) or (before is not None and (not restored or not same(restored,before))):
                    raise AgentError('Rollback verification failed')
                action['state'] = 'restored'
                self.store.write('transaction.json',tx)
            except Exception:
                failures += 1
                # Keep dependency providers if a dependent consumer could not be restored.
                break
        tx['status'] = 'rollback-incomplete' if failures else 'rolled-back'
        self.store.write('transaction.json',tx)
        return {'status':tx['status'],'id':tx['id']}
