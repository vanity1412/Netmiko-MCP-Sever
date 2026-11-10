"""Client-independent credential loading; mock/localhost only, no production SSH."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mcp'))
import collector_backend as b

class CredentialsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.config=self.root/'devices.json'
        self.write(self.config,{'defaults':{'output_dir':str(self.root/'output'),'session_sweep_seconds':0},'profiles':{}})
        self.env=patch.dict(os.environ,{'NETWORK_MCP_CREDENTIALS_FILE':''});self.env.start();self.addCleanup(self.env.stop)
    def write(self,path,data):path.write_text(json.dumps(data),encoding='utf-8-sig')
    def private(self,path=None,**profiles):
        path=path or self.root/'credentials.json';self.write(path,{'profiles':profiles});return path
    def settings(self,config,profile=None):
        c=b.Collector(config,connect_factory=lambda **kw:None);self.addCleanup(c.shutdown)
        return c._get_settings('192.0.2.1','cisco_ios',profile)
    def test_sibling_discovery_and_multiple_profiles(self):
        self.private(default={'username':'first','password':'fixture-one'},site={'username':'second','password':'fixture-two'})
        config=b.load_config(str(self.config))
        self.assertEqual(self.settings(config)['username'],'first')
        self.assertEqual(self.settings(config,'site')['password'],'fixture-two')
    def test_legacy_config_without_credential_file(self):
        config=b.load_config(str(self.config))
        with patch.dict(os.environ,NETWORK_SSH_USER='legacy',NETWORK_SSH_PASSWORD='fixture'):
            self.assertEqual(self.settings(config)['username'],'legacy')
    def test_external_auth_replaces_inline_bundle_preserves_connection(self):
        self.write(self.config,{'defaults':{'password':'old-global','secret':'old-enable'},'profiles':{'site':{'username':'old','password':'old-password','secret':'old-secret','use_keys':True,'conn_timeout':22,'inherit_credentials':True}}})
        self.private(site={'username':'new','key_file':'keys/site.key'})
        settings=self.settings(b.load_config(str(self.config)),'site')
        self.assertEqual(settings['username'],'new');self.assertEqual(settings['password'],'')
        self.assertEqual(settings['secret'],'');self.assertEqual(settings['conn_timeout'],22)
        self.assertNotIn('use_keys',settings)
        self.assertEqual(settings['key_file'],str((self.root/'keys/site.key').resolve()))
    def test_incomplete_external_profile_does_not_borrow_global_password(self):
        self.private(site={'username':'different'})
        with patch.dict(os.environ,NETWORK_SSH_PASSWORD='global-fixture'):
            with self.assertRaisesRegex(ValueError,'Incomplete credential profile site'):b.load_config(str(self.config))
    def test_cli_environment_config_path_precedence(self):
        self.private(default={'username':'sibling','password':'fixture'})
        paths=[]
        for label in ['config','env','cli']:
            path=self.private(self.root/(label+'.json'),default={'username':label,'password':'fixture'});paths.append(path)
        self.write(self.config,{'credentials_file':'config.json'})
        self.assertEqual(self.settings(b.load_config(str(self.config)))['username'],'config')
        with patch.dict(os.environ,NETWORK_MCP_CREDENTIALS_FILE=str(paths[1])):
            self.assertEqual(self.settings(b.load_config(str(self.config)))['username'],'env')
            self.assertEqual(self.settings(b.load_config(str(self.config),str(paths[2])))['username'],'cli')
    def test_explicit_missing_file_never_falls_back(self):
        with self.assertRaises(FileNotFoundError):b.load_config(str(self.config),'missing.json')
    def test_literal_password_and_environment_reference(self):
        self.private(default={'username':'user','password':'literal$VAR;[x]'},site={'username':'${TEST_USER}','password':'${TEST_PASS}'})
        with patch.dict(os.environ,TEST_USER='site',TEST_PASS='fixture-value'):
            config=b.load_config(str(self.config))
        self.assertEqual(self.settings(config)['password'],'literal$VAR;[x]')
        self.assertEqual(self.settings(config,'site')['password'],'fixture-value')
    def test_invalid_schema_and_field_types(self):
        for data in [[],{'defaults':{}},{'profiles':[]},{'profiles':{'bad':{'username':'user','password':123}}},{'profiles':{'bad':{'username':'user','password':'fixture','device_type':'linux'}}}]:
            with self.subTest(data=data):
                self.write(self.root/'credentials.json',data)
                with self.assertRaises(ValueError):b.load_config(str(self.config))
    def test_corrupt_json_does_not_echo_secret(self):
        (self.root/'credentials.json').write_text('{"password": "fixture-must-not-appear" BROKEN',encoding='utf-8')
        with self.assertRaises(ValueError) as caught:b.load_config(str(self.config))
        self.assertNotIn('fixture-must-not-appear',str(caught.exception))
    def test_password_key_and_agent_profiles(self):
        self.private(key={'username':'key-user','key_file':'site.key','passphrase':'fixture'},agent={'username':'agent-user','allow_agent':True})
        config=b.load_config(str(self.config));self.assertTrue(self.settings(config,'agent')['allow_agent'])
        self.assertEqual(self.settings(config,'key')['passphrase'],'fixture')
    def test_same_file_from_different_client_working_directories(self):
        self.private(default={'username':'shared','password':'fixture'})
        self.write(self.config,{'credentials_file':'credentials.json'})
        old=Path.cwd()
        try:
            os.chdir(self.root.parent)
            self.assertEqual(self.settings(b.load_config(str(self.config)))['username'],'shared')
        finally:os.chdir(old)
    def test_bootstrap_check_uses_file_without_network_or_client_secrets(self):
        self.private(default={'username':'one','password':'fixture-one'},site={'username':'two','password':'fixture-two'})
        csv=self.root/'device.csv';csv.write_text('name,ip,netmiko_device_type,profile\nA,192.0.2.1,cisco_ios,default\nB,192.0.2.2,huawei,site\n',encoding='utf-8')
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run([sys.executable,str(root/'mcp/bootstrap.py'),'--config',str(self.config),'--inventory-csv',str(csv),'--credentials-file','credentials.json','--check'],capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        status=json.loads(result.stdout);self.assertTrue(status['credentials_available']);self.assertEqual(status['devices'],2)
        self.assertNotIn('fixture-one',result.stdout+result.stderr)
        self.assertNotIn('fixture-two',result.stdout+result.stderr)

    def test_localhost_auth_from_file_and_session_reuse(self):
        import paramiko
        from test_ssh_reliability import LocalSSHServer
        server=LocalSSHServer(paramiko.RSAKey.generate(2048));self.addCleanup(server.close)
        self.private(site={'username':'tester','password':'loopback-only'})
        self.write(self.config,{'defaults':{'output_dir':str(self.root/'output'),
            'session_sweep_seconds':0,'alt_key_file':str(self.root/'known_hosts'),
            'autodetect_cache_file':str(self.root/'cache.sqlite3')},
            'devices':{'local':{'host':'127.0.0.1','port':server.port,'device_type':'linux','profile':'site'}}})
        with patch.dict(os.environ,NETWORK_SSH_USER='wrong-global',NETWORK_SSH_PASSWORD='wrong-global'):
            c=b.Collector(b.load_config(str(self.config)));self.addCleanup(c.shutdown)
            first=c.execute('local','uname -s',read_timeout=3)
            second=c.execute('local','uptime',read_timeout=3)
        self.assertTrue(first['ok']);self.assertTrue(second['ok'])
        self.assertEqual(server.auth_attempts,1)
        self.assertEqual(c.status()['connections_opened'],1)
        self.assertNotIn('loopback-only',json.dumps([first,second,c.status()]))

if __name__=='__main__':unittest.main()
