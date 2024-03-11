# 1.将从bmc环境上取下来的xml放在脚本文件同目录下的oldxml文件下
# 2.运行脚本
# 3.符合bmc上库格式的xml在newxml文件下

import os
g_oldxml_dir = os.path.join(os.path.dirname(__file__), "./oldxml")
g_newxml_dir = os.path.join(os.path.dirname(__file__), "./newxml")

class FirmwareInfoParser(object):
    def __init__(self, firmware_dir=g_oldxml_dir):
        self.firmware_dir = firmware_dir
        self.filelists = []

    # 递归遍历所有文件
    def get_all_file(self):
        def gci(filepath):
            #遍历filepath下所有文件，包括子目录
            files = os.listdir(filepath)
            for fi in files:
                fi_d = os.path.abspath(os.path.join(filepath,fi))
                if os.path.isdir(fi_d):
                    gci(fi_d)
                else:
                    self.filelists.append(os.path.abspath(os.path.join(filepath,fi_d)))

        gci(self.firmware_dir)
        return self.filelists

    def filter_filelists_xml(self):
        tmp_list = []
        for filename in self.get_all_file():
            if filename.endswith(".xml"):
                tmp_list.append(filename)
        return tmp_list


if __name__ == "__main__":
    print("---------Start-----------")
    f = FirmwareInfoParser(firmware_dir = g_oldxml_dir)
    if not os.path.exists(g_newxml_dir):
        os.makedirs(g_newxml_dir)
    os.chdir(g_newxml_dir)
    for xmlfilename in f.filter_filelists_xml():
        f3 = open(os.path.basename(xmlfilename), 'w', encoding='UTF-8')
        with open(xmlfilename, 'r', encoding='UTF-8') as f:
            line = f.readline()
            while line:
                if line == None or line == '\n' or line =='\r\n':
                    line = f.readline()
                    continue
                else:
                    f3.write(line.replace(r"<O ", "<OBJECT ").replace(r"</O>", "</OBJECT>").replace(r"<P ", "<PROPERTY").replace(r"</P>", "</PROPERTY>").replace(r"<V/>", "<VALUE></VALUE>").replace(r"<V>", "<VALUE>").replace(r"</V>", "</VALUE>"))
                    line = f.readline()
        f3.close()
        f.close()
    print("--------End------------")
