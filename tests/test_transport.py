"""Integration tests against a real HTTPS mock server, including TLS rejection."""
import base64
import http.server
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from agent.client import RestClient,AgentError
from agent.model import SCHEMA,entity
from agent.reconcile import Reconciler
from agent.state import Store
from test_agent import MockRouter


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); p=Path(cls.tmp.name)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(p/'key'),'-out',str(p/'cert'),
            '-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cls.router=MockRouter()
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def handle_request(self):
                if self.headers.get('Authorization')!='Basic '+base64.b64encode(b'user:password').decode():
                    self.send_response(401);self.end_headers();return
                path=self.path.removeprefix('/rest/')
                if path=='redirect':
                    self.send_response(302);self.send_header('Location','https://example.com/');self.end_headers();return
                if path=='broken':
                    self.send_response(200);self.end_headers();self.wfile.write(b'broken');return
                try:
                    if self.command=='GET':
                        if path=='system/resource': result={'version':'7.23.8','architecture-name':'arm64'}
                        elif path=='user/active': result=[{'name':'user','via':'rest-api'}]
                        elif path=='user': result=[{'name':'user','group':'test'}]
                        elif path=='user/group': result=[{'name':'test','policy':'read,write,rest-api'}]
                        else: result=cls.router.rows(path)
                    else:
                        body=json.loads(self.rfile.read(int(self.headers['Content-Length']))) if self.headers.get('Content-Length') else None
                        result=cls.router.request(self.command,path,body)
                    self.send_response(200);self.end_headers();self.wfile.write(json.dumps(result).encode())
                except Exception:
                    self.send_response(503);self.end_headers()
            do_GET=handle_request;do_PUT=handle_request;do_PATCH=handle_request;do_DELETE=handle_request
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(p/'cert'),str(p/'key'))
        cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url='https://localhost:'+str(cls.server.server_port)+'/rest'
        cls.pem=(p/'cert').read_text()
    @classmethod
    def tearDownClass(cls): cls.server.shutdown();cls.server.server_close();cls.tmp.cleanup()
    def client(self,**changes):
        with patch('agent.client.validate_connection',return_value=self.url):
            return RestClient({'url':self.url,'username':'user','password':'password','ca_pem':self.pem,**changes})
    def test_verified_tls_crud(self):
        self.router.data={p:[] for p in SCHEMA}
        c=self.client(); self.assertTrue(c.preflight()['tls_verified'])
        with tempfile.TemporaryDirectory() as tmp:
            r=Reconciler(c,Store(tmp)); desired=[entity('ip/firewall/address-list','transport',list='mpr-test',address='192.0.2.1')]
            self.assertEqual(r.apply(r.preview(desired))['status'],'applied')
            self.assertEqual(r.apply(r.preview(desired))['status'],'unchanged')
            self.assertEqual(r.rollback()['status'],'rolled-back')
    def test_auth_error_is_sanitized(self):
        with self.assertRaisesRegex(AgentError,'HTTP 401'): self.client(password='wrong-secret').rows('routing/table')
    def test_untrusted_certificate_fails(self):
        with self.assertRaisesRegex(AgentError,'TLS verification failed'): self.client(ca_pem='').rows('routing/table')
    def test_redirect_cannot_leak_auth(self):
        with self.assertRaisesRegex(AgentError,'redirects are forbidden'): self.client().request('GET','redirect')
    def test_invalid_response(self):
        with self.assertRaises(AgentError): self.client().request('GET','broken')
    def test_connection_refused(self):
        with patch('agent.client.validate_connection',return_value='https://localhost:1/rest'):
            c=RestClient({'url':self.url,'username':'u','password':'p','ca_pem':self.pem})
        with self.assertRaises(AgentError): c.rows('routing/table')
