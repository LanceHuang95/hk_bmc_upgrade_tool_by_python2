#coding=UTF-8
#-- coding:UTF-8 --
import os
import re
import sys
import argparse
from time import sleep
from datetime import datetime
from utils.log_util import Logging
from utils.env_csv_parser import EnvParser
from utils.firware_info_parser import FirmwareInfoParser
from utils.ssh_util import SshClient
from src.upgrade import Upgrade


g_env_file = os.path.join(os.path.dirname(__file__), "config/env.csv")
g_firmware_dir = os.path.join(os.path.dirname(__file__), "firmware")

#  升降级，默认升级
#  VD VE，默认VD
#  升级方式：只升级BIOS BMC CPLD 全部升级
#  是否支持指定文件路径
def parse_args():
    parser = argparse.ArgumentParser(description="Tool for upgrading BMC firmware in batches By Python2.7")  
    parser.add_argument("-m", '--mode', type=str, help="Upgrade Mode:upgrade, downgrade, default=upgrade", default='upgrade', choices=['upgrade', 'downgrade'])
    parser.add_argument("-e", '--env', type=str, help="BMC Env Type:VD, VE, default=VD", default='VD', choices=['VD', 'VE'])
    parser.add_argument('-t', '--type', type=str, help='Firmware Type:BMC, BIOS, CPLD, ALL, default=BMC', default='BMC', choices=['BMC', 'BIOS', 'CPLD', 'ALL'])
    parser.add_argument('-f', '--filepath', type=str, help='User Defined Upgrade FilePath, default=None', default=None)
    args = parser.parse_args()
    return args


def get_os_memory(**env_info):
    if env_info['os_ip'] and env_info['os_user'] and env_info['os_passwd']:
        os_ssh_client = SshClient(env_info['os_ip'], env_info['os_user'], env_info['os_passwd'])
        output = os_ssh_client.excute_cmds(["cat /proc/meminfo | head -n 1 | awk '{print $2/(1024 * 1024)}'"])
        return '512G' if int(output) < 512 else '1024G'
    return '512G'


if __name__ == "__main__":
    args = parse_args()
    g_env_map_lists = EnvParser(g_env_file).get_env_lists()
    g_firmware_map = FirmwareInfoParser(g_firmware_dir).build_firmware_map()

    for env_info in g_env_map_lists:
        if args.filepath:
            Upgrade(args.filepath, **env_info).upgrade_action()
        elif args.type == 'BMC' or args.type == 'CPLD':
            Upgrade(g_firmware_map[args.mode][args.env][args.type], **env_info).upgrade(args.type)
        elif args.type == 'BIOS':
            memory_type = get_os_memory(**env_info)
            Upgrade(g_firmware_map[args.mode][args.env]['BIOS'][memory_type], **env_info).upgrade(args.type)
        elif args.type == 'ALL':
            Upgrade(g_firmware_map[args.mode][args.env]['BMC'], **env_info).upgrade('BMC')
            Upgrade(g_firmware_map[args.mode][args.env]['CPLD'], **env_info).upgrade('CPLD')
            memory_type = get_os_memory(**env_info)
            Upgrade(g_firmware_map[args.mode][args.env]['BIOS'][memory_type], **env_info).upgrade('BIOS')

