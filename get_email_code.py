from config import Config
from imap import ImapEmailHandler
import logging


class EmailVerificationHandler:
    def __init__(self):
        config = Config()
        self.imap_config = config.get_imap()
        self.imap_handler = ImapEmailHandler(self.imap_config)

    def get_verification_code(self):
        code = None
        try:
            logging.info("正在通过 IMAP 获取验证码...")
            code = self.imap_handler.get_verification_code()
            if code:
                logging.info(f"成功获取验证码: {code}")
            else:
                logging.error("获取验证码失败")
        except Exception as e:
            logging.error(f"获取验证码失败: {str(e)}")

        return code


if __name__ == "__main__":
    email_handler = EmailVerificationHandler()
    code = email_handler.get_verification_code()
    print(f"获取到的验证码: {code}")
