import tempfile
import unittest
from unittest.mock import patch,MagicMock
from agent.client import AgentError
from agent.control import command
from agent.model import SCHEMA,entity
from agent.reconcile import Reconciler,digest,same
from agent.state import Store
from agent.supervisor import Supervisor
from test_agent import MockRouter


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(self.tmp.name);self.router=MockRouter()
        self.conn={'url':'https://10.0.0.1','username':'u','password':'p'};self.store.write('connection.json',self.conn)
        self.store.write('base-env.json',{'LOG_LEVEL':'error'})
        self.sup=Supervisor(self.store);self.sup.stop_worker=MagicMock();self.sup.start_worker=MagicMock()
    def tearDown(self): self.tmp.cleanup()
    def job(self,changes):
        preview=Reconciler(self.router,self.store).preview([])
        preview.update(changes=changes,network={'profile':'disabled'},previous_env={},previous_network={},connection=digest(self.conn))
        return {'id':'test','action':'apply','connection':digest(self.conn),'preview':preview,'started':0}
    @patch('agent.supervisor.validate_candidate')
    @patch('agent.supervisor.RestClient')
    def test_log_level_hot_reload_without_worker_restart(self,client,validate):
        client.return_value=self.router
        with patch('agent.supervisor.mihomo_request',side_effect=[None,{'log-level':'info'}]),patch('agent.supervisor.subprocess.run'):
            self.sup.run_job(self.job({'LOG_LEVEL':'info'}))
        self.sup.stop_worker.assert_not_called();self.assertEqual(self.store.read('job.json')['strategy'],'mihomo-hot-reload')
        self.assertEqual(self.store.read('transaction.json')['status'],'applied')
    @patch('agent.supervisor.validate_candidate')
    @patch('agent.supervisor.RestClient')
    def test_worker_restart_failure_restores_local_environment(self,client,validate):
        client.return_value=self.router;self.sup.ready=MagicMock(side_effect=[False,True])
        with patch('agent.supervisor.time.sleep'),self.assertRaisesRegex(AgentError,'restart failed'):
            self.sup.run_job(self.job({'TPROXY':'false'}))
        self.assertEqual(self.store.read('env.json'),{});self.assertEqual(self.store.read('transaction.json')['status'],'rolled-back')
    @patch('agent.supervisor.RestClient')
    def test_invalid_proxy_rejected_before_router_writes(self,client):
        client.return_value=self.router
        with patch('agent.supervisor.validate_candidate',side_effect=AgentError('invalid')),self.assertRaises(AgentError):
            self.sup.run_job(self.job({'TPROXY':'false'}))
        self.assertFalse(self.router.calls);self.assertIsNone(self.store.read('env.json'))
    @patch('agent.supervisor.RestClient')
    def test_recovery_cannot_target_different_router(self,client):
        client.return_value=self.router
        self.store.write('transaction.json',{'id':'x','status':'applied','actions':[],'connection':'other'})
        with self.assertRaisesRegex(AgentError,'different RouterOS'):
            self.sup.run_job({'id':'r','action':'recover','connection':digest(self.conn)})
    def test_switch_and_default_normalization(self):
        self.assertTrue(same({'fib':''},{'fib':'true'}))
        self.assertTrue(same({'blackhole':''},{'blackhole':'true'}))
        self.assertTrue(same({}, {'match-subdomain':'false'}))
        self.assertTrue(same({'address':'192.0.2.1'},{'address':'192.0.2.1/32'}))
