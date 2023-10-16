
#coding=UTF-8
#-- coding:UTF-8 --
import re
import sys
import time
import socket
import paramiko
from paramiko.ssh_exception import NoValidConnectionsError,AuthenticationException
from log_util import Logging

reload(sys)
sys.setdefaultencoding("utf-8")

class SshClient(object):
    def __init__(self, host, username, pwd, port=22, verbose=True):
        self.host = host
        self.user = username
        self.pwd = pwd
        self.port = port
        self.verbose = verbose
        self.logger = Logging()

    def try_connect(self):
        ret = False
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname=self.host,
                        username=self.user,
                        timeout=5,
                        compress=True,
                        password=self.pwd
                        #pkey=private,    #可以采用密钥连接
                        )

            self.logger.debug("Connecting Remote Host Sucess:{}.....".format(self.host))
            ret = True
        except NoValidConnectionsError:
            self.logger.error("There's been a problem with the connection:{}.....".format(self.host))
            ret = False
        except AuthenticationException:
            self.logger.error("Incorrect user name or password:{}.....".format(self.host))
            ret = False
        except Exception as e:
            self.logger.error("Other Errors:{}.....".format(self.host))
            print 'Other Errors:{}'.format(e)
            ret = False
        finally:
            ssh.close()
            return ret

    def excute_cmds(self, cmds, is_need_refresh=False):
        # 私钥文件的存放路径
        # private = paramiko.RSAKey.from_private_key_file(r'C:\Users\singvis\Documents\Identity')
        # 创建一个实例化
        ssh = paramiko.SSHClient()
        # 加载系统SSH密钥
        ssh.load_system_host_keys()
        # 自动添加策略，保存服务器的主机名和密钥信息，如果不添加，那么不在本地knows_hosts文件中记录的主机将无法连接，默认拒接
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # 连接设备
        try:
            ssh.connect(hostname=self.host,
                        username=self.user,
                        timeout=5,
                        compress=True,
                        password=self.pwd
                        #pkey=private,    #可以采用密钥连接
                        )
            # # 建立一个socket
            # trans = paramiko.Transport((self.host, self.port))
            # # 启动一个客户端
            # trans.start_client()
            # trans.auth_password(username=self.user, password=self.pwd)

            self.logger.debug("Connecting Remote Host Sucess:{} .....".format(self.host))
        except NoValidConnectionsError:
            self.logger.error("There's been a problem with the connection:{}.....".format(self.host))
        except AuthenticationException:
            self.logger.error("Incorrect user name or password:{}.....".format(self.host))
        except Exception as e:
            self.logger.error("Other Errors:{}.....".format(self.host))
            print 'Other Errors:{}'.format(e)
        finally:
            # 激活交互式shell
            cmd_retval = None
            chan = ssh.invoke_shell()

            # # 打开一个通道
            # chan = trans.open_session()
            # # 获取终端
            # chan.get_pty()
            # # 激活终端，这样就可以登录到终端了，就和我们用类似于xshell登录系统一样
            # chan.invoke_shell()
            time.sleep(1)
            for cmd in cmds:
                self.logger.info("IP:%s excute_cmd:%s" %(self.host, cmd))
                #一定要有回车'Enter'这个动作
                chan.send(cmd.encode() + '\n')
                time.sleep(2)
                # 解决Console实时升级打印显示乱序
                self.logger.remove_stream_handler()
                timeout = 0
                while True:
                    if cmd == 'exit':
                        break
                    r = chan.recv(4096).decode(encoding='utf-8')
                    if 'Y/N' in r:
                        # 解决交互式命令需要输入Y
                        chan.send(b'Y' + '\n')
                        time.sleep(2)
                        r = chan.recv(4096).decode(encoding='utf-8')
                    if r == None or r.strip() == None or r.strip() == '' or r == [] or r == {}:
                        # 解决升级时突然获取不到进度
                        if is_need_refresh == True:
                            timeout += 1
                            time.sleep(2)
                            if timeout == 3:
                                break
                    if self.verbose and r:
                        print r
                        # 解决Console实时升级打印多行进度到一行
                        cmd_retval = r.encode('utf-8').replace('\r', ' ')
                        self.logger.info(cmd_retval)
                    if is_need_refresh == True:
                        # 解决实时刷新进度
                        time.sleep(5)
                        r = None
                        chan.send(b' ')
                    else:
                        break
                self.logger.add_stream_handler()
                        
            chan.close()
            ssh.close()
        return cmd_retval

    def download(self, remote_file, local_file, port=22):
        try:
            t = paramiko.Transport(self.host, self.port)
            t.connect(username=self.user, password=self.pwd)
            sftp = paramiko.SFTPClient.from_transport(t)
            self.logger.info("IP:%s Begin to Download Remote File:%s to Local:%s" %(self.host, remote_file, local_file))
            sftp.get(remote_file, local_file)
            t.close()
            self.logger.info("IP:%s End to Download Remote File:%s to Local:%s" %(self.host, remote_file, local_file))

        except Exception as e:
            print e


    def upload(self, local_file, remote_file, port=22):
        # 实现sftp文件上传功能
        progressList = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]  # 只显示整数进度，受python 浮点计算影响，如果不处理会打印多次相同进度

        def showSftpProgress(xfer, to_be_xfer):
            # 显示sftp上传的进度
            percent = int((xfer / to_be_xfer) * 100)
            if percent % 10 == 0:
                if percent in progressList:
                    self.logger.info("IP:" + self.host + remote_file + " transferred: {0:d} %".format(percent))
                    progressList.remove(percent)

        try:
            t = paramiko.Transport(self.host, self.port)
            t.connect(username=self.user, password=self.pwd)
            sftp = paramiko.SFTPClient.from_transport(t)
            self.logger.info("IP:%s Begin to Upload Local File:%s to Remote:%s" %(self.host, local_file, remote_file))
            sftp.put(local_file, remote_file, callback=showSftpProgress)
            t.close()
            self.logger.info("IP:%s End to Upload Local File:%s to Remote:%s" %(self.host, local_file, remote_file))
        except Exception as e:
            print e


# def ping(ip):
#     import subprocess
#     try:
#         subprocess.check_output(["ping", "-n", "1", ip])
#         return True                      
#     except subprocess.CalledProcessError:
#         return False

if __name__ == '__main__':
    '''
    不要运行的，请注释掉，前面加'#'符号
    '''
    ip = '51.2.0.87'
    user= 'Administrator'
    pwd= 'Admin@9000'
    # local_file = r'C:\Users\hwx1223276\Documents\RCSIT_TG225B1_VE_BMC_1.10.12-2023.10.10.hpm'
    # remote_file = r'/tmp/RCSIT_TG225B1_VE_BMC_1.10.12-2023.10.10.hpm'

    local_file = r'D:\huangliang\rootfs_rw_TaiShan2280v2_1711.hpm'
    remote_file = r'/tmp/rootfs_rw_TaiShan2280v2_1711.hpm'
    local_file2 = r'D:\RCSIT_TG225B1_VE_BMC_1.10.12-2023.10.07.hpm'

    # cmds = ['ipmcget -d ver', 'ipmcset -d upgrade -v /tmp/rootfs_rw_TaiShan2280v2_1711.hpm 0', 'exit']
    # s = SshClient(ip, user, pwd)
    # cmds = ['ipmcset -d powerstate -v 0']
    # s.upload(local_file, remote_file)
    # s.download(local_file2, remote_file)

    # cmds = ['ipmcget -d ver', 'exit']
    # s.excute_cmds(cmds)

    # time.sleep(90)
    # while True:
    #     # 命令执行成功后一直ping服务器，从能ping通到不通再到通
    #     if s.try_connect():
    #         break
    #     time.sleep(5)
    # Logging().info((ip, 'OS reboot Complete'))

    import os
    from datetime import datetime
    from time import sleep
    bmc_log_filename = 'dump_info.tar.gz'
    cmds = ['ipmcget -d diaginfo']
    current_time_str = str(datetime.now())[:19].replace(' ', '_').replace(':', '_')
    local_file_name = '_'.join([ip, current_time_str, bmc_log_filename])
    tmp_local_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bmc_logs", local_file_name))
    local_file = tmp_local_file.replace("\\", '/')
    remote_file = r'/tmp/' + bmc_log_filename
    Logging().info("IP:%s Begin to Collect BMC Log" %ip)
    s = SshClient(ip, user, pwd)
    s.excute_cmds(cmds, is_need_refresh=True)
    sleep(5)
    s.download(remote_file, local_file)
