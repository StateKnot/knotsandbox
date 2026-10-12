import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from elf import GNU, STATIC, GNU_INTERPRETER, inspect, validate


def fixture(dynamic=True, needed=('libc.so.6','libgcc_s.so.1','libm.so.6'), interpreter=GNU_INTERPRETER, kind=3):
    data=bytearray(4096);data[:7]=b'\x7fELF\x02\x01\x01'
    segments=[(1,5,0,0x400000,0x400000,len(data),len(data),4096)]
    if dynamic:
        raw=interpreter.encode()+b'\0';data[256:256+len(raw)]=raw
        segments.append((3,4,256,0x400100,0x400100,len(raw),len(raw),1))
        table=b'\0'; offsets=[]
        for name in needed: offsets.append(len(table));table+=name.encode()+b'\0'
        data[1024:1024+len(table)]=table
        entries=[(5,0x400400),(10,len(table))]+[(1,n) for n in offsets]+[(0,0)]
        for i,item in enumerate(entries):struct.pack_into('<qQ',data,512+16*i,*item)
        segments.append((2,6,512,0x400200,0x400200,len(entries)*16,len(entries)*16,8))
    struct.pack_into('<HHIQQQIHHHHHH',data,16,kind,62,1,0x400900,64,0,0,64,56,len(segments),0,0,0)
    for i,s in enumerate(segments):struct.pack_into('<IIQQQQQQ',data,64+56*i,*s)
    return bytes(data)


class LinkageContract(unittest.TestCase):
    def test_gnu_is_explicit_and_static_pie_or_exec_has_no_loader(self):
        self.assertEqual(validate(fixture(),GNU)['needed'],['libc.so.6','libgcc_s.so.1','libm.so.6'])
        for kind in (2,3): self.assertEqual(validate(fixture(False,kind=kind),STATIC)['needed'],[])
        with self.assertRaisesRegex(ValueError,'STATIC_DEPENDENCY'):validate(fixture(),STATIC)
        with self.assertRaisesRegex(ValueError,'GNU_INTERPRETER'):validate(fixture(False),GNU)
    def test_unknown_loader_library_rpath_duplicate_and_profile_reject(self):
        for data in (fixture(interpreter='/tmp/ld.so'),fixture(needed=('libc.so.6','libssl.so.3')),fixture(needed=('libc.so.6','libc.so.6'))):
            with self.assertRaises(ValueError):validate(data,GNU)
        data=bytearray(fixture());struct.pack_into('<qQ',data,512,29,1)
        with self.assertRaisesRegex(ValueError,'RPATH'):inspect(bytes(data))
        with self.assertRaisesRegex(ValueError,'PROFILE_UNKNOWN'):validate(fixture(),'auto')
    def test_bounded_parser_rejects_truncation_stale_mapping_and_missing_null(self):
        values=[]
        data=bytearray(fixture());struct.pack_into('<H',data,56,0xffff);values.append(bytes(data))
        data=bytearray(fixture());struct.pack_into('<Q',data,32,4095);values.append(bytes(data))
        data=bytearray(fixture());struct.pack_into('<qQ',data,512,5,0x800000);values.append(bytes(data))
        data=bytearray(fixture());struct.pack_into('<qQ',data,512+16*5,1,1);values.append(bytes(data))
        values.extend((b'',fixture()[:65]))
        for data in values:
            with self.assertRaises(ValueError):inspect(data)

if __name__=='__main__':unittest.main()
