# -*- coding: utf-8 -*-
import os
import hashlib
from log_util import Logging


g_firmware_dir = os.path.join(os.path.dirname(__file__), "../firmware")
g_firemware_map = {
    'upgrade':{
        'VD':{
            'BMC':None,
            'CPLD':None,
            'BIOS':{
                '512G':None,
                '1024G':None,
            },
        },
        'VE':{
            'BMC':None,
            'CPLD':None,
            'BIOS':{
                '512G':None,
                '1024G':None,
            },
        }
    },
    'downgrade':{
        'VD':{
            'BMC':None,
            'CPLD':None,
            'BIOS':{
                '512G':None,
                '1024G':None,
            },
        },
        'VE':{
            'BMC':None,
            'CPLD':None,
            'BIOS':{
                '512G':None,
                '1024G':None,
            },
        }
    },
}
class FirmwareInfoParser(object):
    def __init__(self, firmware_dir=g_firmware_dir):
        self.firmware_dir = firmware_dir
        self.filelists = []
        self.firmware_map = {}
        self.logger = Logging()

    # 递归遍历所有文件
    def get_all_file(self):
        def gci(filepath):
            #遍历filepath下所有文件，包括子目录
            files = os.listdir(filepath)
            for fi in files:
                fi_d = os.path.join(filepath,fi)
                if os.path.isdir(fi_d):
                    gci(fi_d)
                else:
                    self.filelists.append(os.path.abspath(os.path.join(filepath,fi_d)))
                    with open(os.path.abspath(os.path.join(filepath,fi_d)), 'rb') as fp:
                        data = fp.read()
                    file_md5= hashlib.md5(data).hexdigest()
                    self.logger.info((os.path.abspath(os.path.join(filepath,fi_d)), "MD5:", file_md5))

        gci(self.firmware_dir)
        return self.filelists

    def filter_filelists_hpm(self):
        tmp_list = []
        for filename in self.get_all_file():
            if filename.endswith(".hpm"):
                tmp_list.append(filename)
        return tmp_list
    
    def build_firmware_map(self):
        def dict_generator2(indict, pre=None, filename=None):
            pre = pre[:] if pre else []
            if isinstance(indict, dict):
                for key, value in indict.items():
                    if isinstance(value, dict):
                        for d in dict_generator2(value, pre + [key], filename):
                            yield d
                    elif isinstance(value, list) or isinstance(value, tuple):
                        for v in value:
                            for d in dict_generator2(v, pre + [key], filename):
                                yield d
                    else:
                        # 匹配文件名，递归动态修改对应的value值，匹配实际文件路径
                        tmp_list =  pre + [key]
                        tmp_str1 = '/'.join(tmp_list)
                        tmp_str2 = '\\'.join(tmp_list)
                        if tmp_str1 in filename or tmp_str2 in filename:
                            indict[key] = filename
                            # print(pre + [key, value])
                            yield pre + [key, value]
            else:
                yield pre + [indict]
        
        self.firmware_map = g_firemware_map
        for filename in self.filter_filelists_hpm():
            for i in dict_generator2(self.firmware_map, None, filename):
                pass
        
        return self.firmware_map
                    

# def dict_generator(indict, pre=None):
#     pre = pre[:] if pre else []
#     if isinstance(indict, dict):
#         for key, value in indict.items():
#             if isinstance(value, dict):
#                 for d in dict_generator(value, pre + [key]):
#                     yield d
#             elif isinstance(value, list) or isinstance(value, tuple):
#                 for v in value:
#                     for d in dict_generator(v, pre + [key]):
#                         yield d
#             else:
#                 yield pre + [key, value]
#     else:
#         yield pre + [indict]

if __name__ == "__main__":
    F = FirmwareInfoParser()
    # tmp_list = F.filter_filelists_hpm()
    # print tmp_list

    # for t in tmp_list:
    #     for i in dict_generator2(g_firemware_map, None, t):
    #         pass
    #         # print i
    # print g_firemware_map

    print F.build_firmware_map()

    


