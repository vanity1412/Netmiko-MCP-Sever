"""Bootstrap/fallback contracts without inventory credentials or device SSH."""
from pathlib import Path
import sys,copy,importlib.util,unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
root=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(root/'mcp'))
import readonly_client as rc
spec=importlib.util.spec_from_file_location('tested_bootstrap',root/'mcp/bootstrap.py')
bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)
class Contract(unittest.TestCase):
 def test_missing_driver_rejected_before_collector(self):
  with patch.object(rc,'Collector') as factory:
   with self.assertRaises(TypeError):rc.ReadOnlyConnection(host='MOCK')
   factory.assert_not_called()
 def test_invalid_driver_rejected_before_collector(self):
  for value in [None,'',' ',42,'juniper junos','cisco_ios;write']:
   with self.subTest(value=value),patch.object(rc,'Collector') as factory:
    with self.assertRaises(ValueError):rc.ReadOnlyConnection(host='MOCK',device_type=value)
    factory.assert_not_called()
 def test_all_inventory_drivers_forwarded_exactly(self):
  types={'juniper_junos','huawei','cisco_ios','linux','generic_termserver','autodetect'}
  for dtype in types:
   with self.subTest(dtype=dtype),patch.object(rc,'Collector') as factory:
    rc.ReadOnlyConnection(host='MOCK',device_type=dtype)
    self.assertEqual(factory.call_args.args[0]['defaults']['device_type'],dtype)
 def test_wrapper_strict_and_private_keyfile(self):
  with patch.object(rc,'Collector') as factory:
   rc.ReadOnlyConnection(host='MOCK',device_type='juniper_junos',ssh_strict=False,alt_host_keys=False)
   d=factory.call_args.args[0]['defaults']
   self.assertTrue(d['ssh_strict']);self.assertTrue(d['alt_host_keys'])
   self.assertEqual(Path(d['alt_key_file']),root/'mcp/ssh/known_hosts')
 def bootstrap_case(self,defaults):
  config={'defaults':copy.deepcopy(defaults),'profiles':{}}
  backend=SimpleNamespace(load_config=lambda path:config,load_inventory_csv=lambda c,path:c,Collector=Mock(),run_stdio=Mock())
  with patch.object(bootstrap.importlib.util,'spec_from_file_location'),patch.object(bootstrap.importlib.util,'module_from_spec',return_value=backend),patch.dict('os.environ',{'NETWORK_SSH_USER':'MOCK','NETWORK_SSH_PASSWORD':'MOCK'}),patch.object(sys,'argv',['bootstrap.py','--config','MOCK.json','--inventory-csv','MOCK.csv']):
   bootstrap.main()
  result=backend.Collector.call_args.args[0]['defaults']
  self.assertTrue(result['alt_host_keys'])
  self.assertEqual(Path(result['alt_key_file']),root/'mcp/ssh/known_hosts')
  self.assertEqual(result['system_host_keys'],defaults['system_host_keys'])
  backend.run_stdio.assert_called_once()
 def test_bootstrap_missing_alt_flag(self):self.bootstrap_case({'system_host_keys':False})
 def test_bootstrap_false_alt_flag(self):self.bootstrap_case({'system_host_keys':True,'alt_host_keys':False})
 def test_bootstrap_existing_alt_flag(self):self.bootstrap_case({'system_host_keys':False,'alt_host_keys':True})
