import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from master import configure_master

class Admin:
    def __init__(self,attributes):self.attributes=attributes;self.calls=[]
    def call(self,path,method='GET',body=None):
        self.calls.append((path,method,body))
        if method=='GET':return {'realm':'master','attributes':copy.deepcopy(self.attributes),'users':['must-not-reset']}
        self.attributes=body['attributes']

class MasterTests(unittest.TestCase):
    def test_only_native_frontend_attribute_changes_preserving_existing_values(self):
        a=Admin({'existing-policy':'keep'})
        self.assertTrue(configure_master(a,'https://admin.example.com'))
        self.assertEqual(a.calls[-1],('/admin/realms/master','PUT',{'attributes':{'existing-policy':'keep','frontendUrl':'https://admin.example.com'}}))
        self.assertFalse(configure_master(a,'https://admin.example.com'))
        self.assertEqual(len([c for c in a.calls if c[1]=='PUT']),1)
    def test_existing_other_frontend_fails_without_overwrite(self):
        a=Admin({'frontendUrl':'https://unexpected.example.com'})
        with self.assertRaises(ValueError):configure_master(a,'https://admin.example.com')
        self.assertFalse(any(c[1]=='PUT' for c in a.calls))
if __name__=='__main__':unittest.main()
