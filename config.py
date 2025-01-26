from dotenv import load_dotenv
import os
import sys
from logger import logging


class Config:
    def __init__(self):
        # 获取应用程序的根目录路径
        if getattr(sys, "frozen", False):
            # 如果是打包后的可执行文件
            application_path = os.path.dirname(sys.executable)
        else:
            # 如果是开发环境
            application_path = os.path.dirname(os.path.abspath(__file__))

        # 指定 .env 文件的路径
        dotenv_path = os.path.join(application_path, ".env")

        if not os.path.exists(dotenv_path):
            raise FileNotFoundError(f"文件 {dotenv_path} 不存在")

        # 加载 .env 文件
        load_dotenv(dotenv_path)

        # 默认使用 IMAP 模式
        self.imap = True
        self.imap_server = os.getenv("IMAP_SERVER", "").strip()
        self.imap_port = os.getenv("IMAP_PORT", "").strip()
        self.imap_user = os.getenv("IMAP_USER", "").strip()
        self.imap_pass = os.getenv("IMAP_PASS", "").strip()
        self.imap_dir = os.getenv("IMAP_DIR", "INBOX").strip()

        self.check_config()

    def get_imap(self):
        return {
            "imap_server": self.imap_server,
            "imap_port": self.imap_port,
            "imap_user": self.imap_user,
            "imap_pass": self.imap_pass,
            "imap_dir": self.imap_dir,
        }

    def check_config(self):
        """检查 IMAP 配置是否有效

        检查规则：
        1. 必须配置 IMAP_SERVER、IMAP_PORT、IMAP_USER、IMAP_PASS
        2. IMAP_DIR 是可选的，默认为 INBOX
        """
        imap_configs = {
            "imap_server": "IMAP服务器",
            "imap_port": "IMAP端口",
            "imap_user": "IMAP用户名",
            "imap_pass": "IMAP密码",
        }

        for key, name in imap_configs.items():
            value = getattr(self, key)
            if not self.check_is_valid(value):
                raise ValueError(f"{name}未配置，请在 .env 文件中设置 {key.upper()}")

    def check_is_valid(self, value):
        """检查配置项是否有效

        Args:
            value: 配置项的值

        Returns:
            bool: 配置项是否有效
        """
        return isinstance(value, str) and len(str(value).strip()) > 0

    def print_config(self):
        logging.info(f"\033[32mIMAP服务器: {self.imap_server}\033[0m")
        logging.info(f"\033[32mIMAP端口: {self.imap_port}\033[0m")
        logging.info(f"\033[32mIMAP用户名: {self.imap_user}\033[0m")
        logging.info(f"\033[32mIMAP密码: {'*' * len(self.imap_pass)}\033[0m")
        logging.info(f"\033[32mIMAP收件箱目录: {self.imap_dir}\033[0m")


# 使用示例
if __name__ == "__main__":
    try:
        config = Config()
        print("环境变量加载成功！")
        config.print_config()
    except ValueError as e:
        print(f"错误: {e}")
