#coding=UTF-8
#-- coding:UTF-8 --
import os
import sys
import logging
import datetime
import colorlog
reload(sys)
sys.setdefaultencoding("utf-8")

def singleton(class_):
    instances = {}
    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance

default_log_colors = {
    'DEBUG': 'cyan',
    'INFO': 'green',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'CRITICAL': 'bold_red',
}
g_script_logs_dir = os.path.join(os.path.dirname(__file__), "../script_logs")

@singleton
class Logging:
    def __init__(self, log_dir=g_script_logs_dir, log_level=logging.INFO):
        self.log_dir = log_dir
        self.log_level = log_level
        self._prepare_log_dir()

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

        # File handler
        self.file_handler = logging.FileHandler(self._get_log_file_name(), encoding='utf-8')
        self.file_handler.setLevel(log_level)

        # Stream handler (console output)
        self.stream_handler = logging.StreamHandler()
        self.stream_handler.setLevel(log_level)

        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        color_formatter = colorlog.ColoredFormatter('%(log_color)s%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', log_colors=default_log_colors)
        self.file_handler.setFormatter(formatter)
        self.stream_handler.setFormatter(color_formatter)

        self.logger.addHandler(self.file_handler)
        self.logger.addHandler(self.stream_handler)

    def _prepare_log_dir(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def _get_log_file_name(self):
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, "{}.{}".format(current_date, "txt"))

    def debug(self, message):
        self.logger.debug(message) 

    def info(self, message):
        self.logger.info(message)

    def warn(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def remove_stream_handler(self):
        self.logger.removeHandler(self.stream_handler)

    def add_stream_handler(self):
        self.logger.addHandler(self.stream_handler)

    # def get_last_log_line(self):
    #     try:
    #         with open(self._get_log_file_name(), "r", encoding="utf-8", errors='replace') as log_file:
    #             lines = log_file.readlines()
    #             return lines[-1] if lines else None
    #     except FileNotFoundError:
    #         return None

if __name__ == '__main__':
    Logger = Logging(log_level=logging.DEBUG)
    Logger.debug("This is an info message")
    Logger.info("This is an info message")

    Logger.remove_stream_handler()
    Logger.warn("This is a warning message")
    Logger.error("This is an error message")
    Logger.add_stream_handler()

    local_file = r'C:\Users\hwx1223276\Documents\RCSIT_TG225B1_VE_BMC_1.10.12-2023.10.10.hpm'
    remote_file = r'/tmp/RCSIT_TG225B1_VE_BMC_1.10.12-2023.10.10.hpm'
    Logger.info("Begin to download File:%s to local:%s" %(remote_file, local_file))

    r = u' \r4%\r4%\r4%\r5%\r5%\r6%\r6%\r6%\r7%\r7%\r8%\r8%\r9%\r9%\r9%\r10%\r10%\r11%\r11%\r12%'
    t = r.encode('utf-8').replace('\r', ' ')
    Logger.error(t)
    

        
