#coding=UTF-8
#-- coding:UTF-8 --
import os
import re
import sys
from time import sleep
from datetime import datetime
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from utils.ssh_util import SshClient
from utils.log_util import Logging
# from utils.env_csv_parser import EnvParser
# from utils.firware_info_parser import FirmwareInfoParser


# g_env_file = os.path.join(os.path.dirname(__file__), "../config/env.csv")
# g_firmware_dir = os.path.join(os.path.dirname(__file__), "../firmware")


# g_env_map_lists = EnvParser(g_env_file).get_env_lists()
# g_firmware_map = FirmwareInfoParser(g_firmware_dir).build_firmware_map()


class Upgrade(object):
    def __init__(self, firmware_real_path=None, **env_info):
        self.bmc_ssh_client = None
        self.os_ssh_client = None
        self.bmc_ip = None
        self.os_ip = None
        self.firmware_real_path = firmware_real_path
        self.logger = Logging()
        if env_info['bmc_ip']:
            self.bmc_ip = env_info['bmc_ip']
        if env_info['os_ip']:
            self.os_ip = env_info['os_ip']
        if env_info['bmc_ip'] and env_info['bmc_user'] and env_info['bmc_passwd']:
            self.bmc_ssh_client = SshClient(env_info['bmc_ip'], env_info['bmc_user'], env_info['bmc_passwd'])
        if env_info['os_ip'] and env_info['os_user'] and env_info['os_passwd']:
            self.os_ssh_client = SshClient(env_info['os_ip'], env_info['os_user'], env_info['os_passwd'])

    def try_bmc_connect(self):
        return self.bmc_ssh_client.try_connect() if self.bmc_ssh_client else False

    def try_os_connect(self):
        return self.os_ssh_client.try_connect() if self.os_ssh_client else False

    def env_ssh_connect_check(self):
        for i in range(3):
            if self.try_bmc_connect():
                return True
            elif i == 2:
                return False
    
    def firmware_real_path_check(self):
        if self.firmware_real_path and os.path.exists(self.firmware_real_path) and self.firmware_real_path.endswith(".hpm"):
            return True
        else:
            return False

    def collect_bmc_log(self):
        if self.try_bmc_connect():
            bmc_log_filename = 'dump_info.tar.gz'
            cmds = ['ipmcget -d diaginfo']
            current_time_str = str(datetime.now())[:19].replace(' ', '_').replace(':', '_')
            local_file_name = '_'.join([self.bmc_ip, current_time_str, bmc_log_filename])
            tmp_local_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../bmc_logs/", local_file_name))
            local_file = tmp_local_file.replace("\\", '/')
            remote_file = r'/tmp/' + bmc_log_filename
            self.logger.info("IP:%s Begin to Collect BMC Log" % self.bmc_ip)
            self.bmc_ssh_client.excute_cmds(cmds, is_need_refresh=True)
            sleep(5)
            self.bmc_ssh_client.download(remote_file, local_file)

    def collect_os_log(self, cmds= [], logname_lists=[]):
        if self.try_os_connect():
            self.os_ssh_client.excute_cmds(cmds, is_need_refresh=False)
            for logname in logname_lists:
                current_time_str = str(datetime.now())[:19].replace(' ', '_').replace(':', '_')
                local_file_name = '_'.join([self.os_ip, current_time_str, logname])
                tmp_local_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../bmc_logs/", logname))
                local_file = tmp_local_file.replace("\\", '/')
                remote_file = r'/tmp/' + logname
                self.logger.info("IP:%s Begin to Collect OS %s" %(self.os_ip, logname))
                sleep(1)
                self.os_ssh_client.download(remote_file, local_file)
                

    def prepare_upgrade_action(self, prepare_commands=None):
        if self.try_bmc_connect() and type(prepare_commands) == list:
            self.bmc_ssh_client.excute_cmds(prepare_commands)

    def after_upgrade_action(self, after_commands=None):
        # 如果升级完BIOS,执行重启
        if self.try_bmc_connect() and type(after_commands) == list:
            if "BIOS" in self.firmware_real_path or 'CPLD' in self.firmware_real_path:
                after_commands.extend(['ipmcset -d powerstate -v 0'])
                self.bmc_ssh_client.excute_cmds(after_commands)
            else:
                self.bmc_ssh_client.excute_cmds(after_commands)

    def upgrade_action(self):
        if self.try_bmc_connect() and self.firmware_real_path:
            firmware_name = '/tmp/tmp_upgrade.hpm'
            self.bmc_ssh_client.upload(self.firmware_real_path, firmware_name)
            cmds = ['ipmcset -d upgrade -v /tmp/tmp_upgrade.hpm 0']
            self.bmc_ssh_client.excute_cmds(cmds, is_need_refresh=True)

    def bmc_upgrade(self):
        self.logger.info("IP:%s BMC Prepare Update FirmWare:%s" %(self.bmc_ip, self.firmware_real_path))
        self.prepare_upgrade_action(['ipmcget -d ver'])
        self.upgrade_action()
        self.after_upgrade_action()
        sleep(90)
        while True:
            # 命令执行成功后一直ping服务器，从能ping通到不通再到通
            sleep(5)
            if self.try_bmc_connect():
                break
        self.collect_bmc_log()
        self.logger.info("IP:%s BMC Update FirmWare:%s Sucess" %(self.bmc_ip, self.firmware_real_path))

    def bios_upgrade(self):
        self.logger.info("IP:%s OS BIOS Prepare Update FirmWare:%s" %(self.os_ip, self.firmware_real_path))
        self.upgrade_action()
        self.after_upgrade_action([])
        while True:
            sleep(20)
            if self.try_bmc_connect():
                ret_val = self.bmc_ssh_client.excute_cmds(['ipmcset -d powerstate -v 1'])
                if ret_val:
                    if 'being upgraded' not in ret_val and 'failed' not in ret_val:
                        self.logger.info("IP:%s BMC Execute Power On:%s" %(self.bmc_ip, ret_val))
                        break
                    else:
                        self.logger.error("IP:%s BMC Execute Power On:%s" %(self.bmc_ip, ret_val))
        sleep(60)
        if self.os_ip:
            while True:
                # 命令执行成功后一直ping服务器，从能ping通到不通再到通
                sleep(20)
                if self.try_os_connect():
                    break
        self.collect_os_log(['ipmitool sel elist > /tmp/sel.log', 'dmidecode > /tmp/smbios.log', 'dmidecode -t bios > /tmp/bios_version.log'],
                            ['sel.log', 'smbios.log', 'bios_version.log'])
        self.logger.info("IP:%s OS BIOS Update FirmWare:%s Sucess" %(self.os_ip, self.firmware_real_path))

    def cpld_upgrade(self):
        self.logger.info("IP:%s BMC Cpld Prepare Update FirmWare:%s" %(self.bmc_ip, self.firmware_real_path))
        self.upgrade_action()
        self.after_upgrade_action([])
        while True:
            sleep(20)
            if self.try_bmc_connect():
                ret_val = self.bmc_ssh_client.excute_cmds(['ipmcset -d powerstate -v 1'])
                if ret_val:
                    if 'being upgraded' not in ret_val and 'failed' not in ret_val:
                        self.logger.info("IP:%s BMC Execute Power On:%s" %(self.bmc_ip, ret_val))
                        break
                    else:
                        self.logger.error("IP:%s BMC Execute Power On:%s" %(self.bmc_ip, ret_val)) 
        sleep(60)
        if self.os_ip:
            while True:
                # 命令执行成功后一直ping服务器，从能ping通到不通再到通
                sleep(20)
                if self.try_os_connect():
                    break
        self.logger.info("IP:%s BMC Cpld Update FirmWare:%s Sucess" %(self.bmc_ip, self.firmware_real_path))

    def upgrade(self, upgrade_type = None):
        if not self.env_ssh_connect_check():
            self.logger.error("----------BMC IP:%s SSH Connect Failed------------------" %(self.bmc_ip))
            return
        if not self.firmware_real_path_check():
            self.logger.error("----------BMC IP:%s Firmware Path:%s Failed------------------" %(self.bmc_ip, self.firmware_real_path))
            return
        if upgrade_type == 'BMC':
            self.logger.info("----------BMC IP:%s Update BMC FirmWare:%s BEGIN------------------" %(self.bmc_ip, self.firmware_real_path))
            self.bmc_upgrade()
            self.logger.info("----------BMC IP:%s Update BMC FirmWare:%s END------------------" %(self.bmc_ip, self.firmware_real_path))
        elif upgrade_type == 'BIOS':
            self.logger.info("----------BMC IP:%s Update BIOS FirmWare:%s BEGIN------------------" %(self.bmc_ip, self.firmware_real_path))
            self.bios_upgrade()
            self.logger.info("----------BMC IP:%s Update BIOS FirmWare:%s END------------------" %(self.bmc_ip, self.firmware_real_path))
        elif upgrade_type == 'CPLD':
            self.logger.info("----------BMC IP:%s Update CPLD FirmWare:%s BEGIN------------------" %(self.bmc_ip, self.firmware_real_path))
            self.cpld_upgrade()
            self.logger.info("----------BMC IP:%s Update CPLD FirmWare:%s END------------------" %(self.bmc_ip, self.firmware_real_path))
        else:
            return


if __name__ == "__main__":
    pass
