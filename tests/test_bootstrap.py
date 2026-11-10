"""Bootstrap/fallback contracts without inventory credentials or device SSH."""
from pathlib import Path
import sys,copy,importlib.util,unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
root=Path(__file__).resolve().parents[1]
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
   self.assertFalse(d['ssh_strict']);self.assertFalse(d['alt_host_keys'])
   self.assertEqual(Path(d['alt_key_file']),root/'mcp/ssh/known_hosts')
 def bootstrap_case(self,defaults,inventory=True):
  devices={'configured':{'host':'192.0.2.1','device_type':'linux'}}
  config={'defaults':copy.deepcopy(defaults),'profiles':{},'devices':copy.deepcopy(devices)}
  backend=SimpleNamespace(load_config=lambda path,**kw:config,load_inventory_csv=Mock(side_effect=lambda c,path:c),Collector=Mock(),run_stdio=Mock())
  argv=['bootstrap.py','--config','MOCK.json']
  if inventory:argv+=['--inventory-csv','MOCK.csv']
  with patch.object(bootstrap.importlib.util,'spec_from_file_location'),patch.object(bootstrap.importlib.util,'module_from_spec',return_value=backend),patch.dict('os.environ',{'NETWORK_SSH_USER':'MOCK','NETWORK_SSH_PASSWORD':'MOCK'}),patch.object(sys,'argv',argv):
   bootstrap.main()
  result=backend.Collector.call_args.args[0]['defaults']
  self.assertEqual(result['alt_host_keys'],defaults.get('alt_host_keys',True))
  self.assertEqual(Path(result['alt_key_file']),Path(defaults.get('alt_key_file',root/'mcp/ssh/known_hosts')))
  self.assertEqual(result['system_host_keys'],defaults['system_host_keys'])
  backend.run_stdio.assert_called_once()
  self.assertEqual(backend.Collector.call_args.args[0]['devices'],devices)
  if inventory:backend.load_inventory_csv.assert_called_once_with(config,str(root/'MOCK.csv'))
  else:backend.load_inventory_csv.assert_not_called()
 def test_bootstrap_missing_alt_flag(self):self.bootstrap_case({'system_host_keys':False})
 def test_bootstrap_false_alt_flag(self):self.bootstrap_case({'system_host_keys':True,'alt_host_keys':False})
 def test_bootstrap_existing_alt_flag(self):self.bootstrap_case({'system_host_keys':False,'alt_host_keys':True})
 def test_bootstrap_custom_host_key_file(self):self.bootstrap_case({'system_host_keys':False,'alt_key_file':'custom/known_hosts','ssh_mode':'strict'})
 def test_bootstrap_without_inventory_preserves_config_devices(self):self.bootstrap_case({'system_host_keys':False},inventory=False)
 def test_data_directory_preserves_environment(self):
  with patch.dict('os.environ',{'NETWORK_MCP_DATA_DIR':'custom-data','NETWORK_SSH_USER':'MOCK','NETWORK_SSH_PASSWORD':'MOCK'}):
   bootstrap.prepare_environment()
   self.assertEqual(bootstrap.os.environ['NETWORK_MCP_DATA_DIR'],'custom-data')
 def test_data_directory_legacy_default(self):
  with patch.dict('os.environ',{'NETWORK_SSH_USER':'MOCK','NETWORK_SSH_PASSWORD':'MOCK'},clear=True):
   bootstrap.prepare_environment()
   self.assertEqual(Path(bootstrap.os.environ['NETWORK_MCP_DATA_DIR']),root/'runtime/data/netmiko')
