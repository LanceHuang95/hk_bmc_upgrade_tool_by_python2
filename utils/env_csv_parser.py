# -*- coding: utf-8 -*-
import csv
import os
from log_util import Logging


g_env_file = os.path.join(os.path.dirname(__file__), "../config/env.csv")

class EnvParser(object):
    def __init__(self, env_file_path=g_env_file):
        self.env_file_path = env_file_path if os.path.exists(env_file_path) else None
        self.env_list = []
        self.logger = Logging()
    
    def get_env_lists(self):
        if self.env_file_path:
            with open(self.env_file_path) as f:
                reader = csv.reader(line.replace('\0', '') for line in f)
                for row in reader:
                    env_info = {'bmc_ip':row[0], 'bmc_user':row[1], 'bmc_passwd':row[2],
                                'os_ip':row[3], 'os_user':row[4], 'os_passwd':row[5]}
                    self.env_list.append(env_info)
                    self.logger.info(env_info)
            return self.env_list[1:]
        else:
            self.logger.error("Env csv file Illegal")
            return self.env_list

if __name__ == "__main__":
    # env_file_path = "./ibmc_upgrade_tool_by_python2/config/env.csv"
    print EnvParser().get_env_lists()

    # env_file_path = ""
    # print EnvParser(env_file_path).get_env_lists()
