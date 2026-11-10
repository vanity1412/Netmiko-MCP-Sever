import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mcp'))
import collector_backend as b
from result_status import normalize_result

class StatusCredentials(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
    def settings(self,profile,device=None):
        c=b.Collector({'defaults':{'output_dir':self.tmp.name,'session_sweep_seconds':0,
             'username':'global-fixture','password':'global-password'},'profiles':{'site':profile},
             'devices':{'edge':{'host':'192.0.2.1','profile':'site',**(device or {})}}},connect_factory=lambda **k:None)
        self.addCleanup(c.shutdown)
        return c._get_settings('edge',None,None)
    def test_normalization_clears_previous_aggregate_flags(self):
        r=normalize_result({'ok':False,'results':[{'ok':False,'awaiting_input':True}]})
        r.update(ok=True,results=[{'ok':True}]);normalize_result(r)
        self.assertEqual(r['status'],'SUCCESS');self.assertFalse(r['awaiting_input'])
        self.assertEqual(r['awaiting_task_ids'],[]);self.assertEqual(r['status_counts'],{'SUCCESS':1})
        self.assertEqual(normalize_result(dict(r)),r)
    def test_pending_anywhere_and_duplicate_targets(self):
        r=normalize_result({'ok':False,'results':[{'ok':False,'awaiting_input':True,'target':'edge'},
             {'ok':True,'target':'edge'},{'ok':False,'awaiting_input':True,'target':'edge','task_id':'stable'}]})
        self.assertEqual(r['awaiting_task_ids'],[0,'stable'])
        self.assertEqual([t['index'] for t in r['awaiting_tasks']],[0,2])
        self.assertEqual(r['status_counts'],{'AWAITING_INPUT':2,'SUCCESS':1})
    def test_success_clears_old_error_metadata(self):
        r=normalize_result({'ok':True,'output_complete':True,'awaiting_input':True,
                           'error_category':'cli_error','error':'old','message':'old'})
        self.assertEqual(r['status'],'SUCCESS');self.assertFalse(r['awaiting_input'])
        self.assertNotIn('error_category',r);self.assertNotIn('message',r)
    def test_incomplete_response_cannot_be_success(self):
        r=normalize_result({'ok':True,'output_complete':False,'output':'partial'})
        self.assertFalse(r['ok']);self.assertEqual(r['status'],'PARTIAL')
    def test_mixed_batch_retains_uncertainty_and_pending_list(self):
        r=normalize_result({'ok':True,'results':[{'ok':True},
            {'ok':False,'error_category':'cli_error','output_complete':True},
            {'ok':False,'error_category':'connection_lost','command_sent':True,'replay_safe':False},
            {'ok':False,'awaiting_input':True,'task_id':'question'}, {'ok':True}]})
        self.assertFalse(r['ok']);self.assertEqual(r['status'],'UNKNOWN')
        self.assertEqual(r['awaiting_task_ids'],['question'])
        self.assertEqual(sum(r['status_counts'].values()),5)
    def test_resolved_interaction_does_not_advertise_previous_question(self):
        r=normalize_result({'ok':True,'steps':[{'ok':False,'awaiting_input':True},{'ok':True}]})
        self.assertEqual(r['status'],'SUCCESS');self.assertEqual(r['awaiting_tasks'],[])
    def test_complete_profile_and_device_precedence(self):
        r=self.settings({'username':'site','password':'site-pass'})
        self.assertEqual((r['username'],r['password']),('site','site-pass'))
        r=self.settings({'username':'site','password':'site-pass'},{'username':'device','password':'device-pass'})
        self.assertEqual((r['username'],r['password']),('device','device-pass'))
    def test_partial_profile_requires_explicit_inheritance(self):
        for profile in [{'username':'site'},{'password':'site-pass'},{'username':'site','password':''}]:
            with self.subTest(profile=profile),self.assertRaisesRegex(ValueError,'Incomplete SSH credential'):
                self.settings(profile)
    def test_timing_only_profile_inherits_whole_global_pair(self):
        r=self.settings({'auth_timeout':60})
        self.assertEqual((r['username'],r['password']),('global-fixture','global-password'))
    def test_key_and_agent_do_not_inherit_global_password(self):
        for auth in [{'key_file':'fixture.key'},{'use_keys':True},{'allow_agent':True}]:
            r=self.settings({'username':'site',**auth})
            self.assertEqual(r['username'],'site');self.assertEqual(r['password'],'')
    def test_explicit_inheritance_at_profile_and_device(self):
        r=self.settings({'username':'site','inherit_credentials':True})
        self.assertEqual((r['username'],r['password']),('site','global-password'))
        r=self.settings({'username':'site','password':'site-pass'},
                        {'username':'device','inherit_credentials':True})
        self.assertEqual((r['username'],r['password']),('device','site-pass'))
