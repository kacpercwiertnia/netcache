import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
from types import SimpleNamespace

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src/kv_store'))
spec=importlib.util.spec_from_file_location('entrypoint',root/'docker/client-entrypoint.py')
client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)

class ValuesTests(unittest.TestCase):
    def args(self,op='read',entries=True):
        return SimpleNamespace(entries=json.dumps([{'key':'first','value':'alpha'},{'key':'second','value':'beta'}]) if entries else '',
            keys=['first','second'],value='common',op=op,prime_backend=True,control_entries='',switch_control_url='',
            servers=1,disable_cache=False,repeat=1,sleep_seconds=0,metrics=False,
            redis_host='redis',redis_port=6379,redis_retries=1)

    def test_backend_priming_and_cache_use_same_per_key_values(self):
        args=self.args();backend=unittest.mock.Mock();backend.put.return_value=True
        self.assertEqual(client.prime_backend_entries(args,backend),0)
        self.assertEqual(backend.put.call_args_list,[unittest.mock.call('first','alpha'),unittest.mock.call('second','beta')])
        self.assertEqual(client.control_entries(args),client.workload_entries(args))

    def test_cache_miss_subset_does_not_change_backend_entries(self):
        args=self.args();args.control_entries=json.dumps([{'key':'first','value':'alpha'}])
        self.assertEqual(len(client.control_entries(args)),1)
        self.assertEqual(client.value_for_key(args,'second'),'beta')

    def test_common_value_and_per_key_writes_for_both_backends(self):
        for redis in (False,True):
            for entries in (False,True):
                for op in ('put','put-read'):
                    with self.subTest(redis=redis,entries=entries,op=op):
                        args=self.args(op,entries);backend=unittest.mock.Mock()
                        with patch.object(client,'RedisClient' if redis else 'NetCacheClient',return_value=backend):
                            (client.run_redis_client if redis else client.run_client)(args)
                        values=['alpha','beta'] if entries else ['common','common']
                        self.assertEqual(backend.put.call_args_list,[unittest.mock.call(k,v) for k,v in zip(args.keys,values)])

    def test_redis_read_is_primed(self):
        args=self.args();backend=unittest.mock.Mock()
        with patch.object(client,'RedisClient',return_value=backend):client.run_redis_client(args)
        self.assertEqual(backend.put.call_args_list,[unittest.mock.call('first','alpha'),unittest.mock.call('second','beta')])

if __name__=='__main__':unittest.main()
