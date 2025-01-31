import imaplib
import email
import time
import re
import logging


class ImapEmailHandler:
    def __init__(self, imap_config):
        self.imap_config = imap_config
        self.base_email = self._get_base_email(imap_config["imap_user"])

    def is_gmail(self):
        """判断是否是Gmail邮箱"""
        return "gmail.com" in self.imap_config["imap_server"].lower()

    def is_outlook(self):
        """判断是否是Outlook邮箱"""
        return (
            "outlook.com" in self.imap_config["imap_server"].lower()
            or "office365.com" in self.imap_config["imap_server"].lower()
        )

    def _get_base_email(self, email):
        """获取邮箱的基本地址（移除别名部分）
        例如：
        - Gmail: username+alias@gmail.com -> username@gmail.com
        - Outlook: username+alias@outlook.com -> username@outlook.com
        """
        if not self.is_gmail() and not self.is_outlook():
            return email

        if "+" not in email:
            return email

        username, domain = email.split("@")
        base_username = username.split("+")[0]
        return f"{base_username}@{domain}"

    def get_verification_code(self, retry=0):
        if retry > 0:
            time.sleep(3)
        if retry >= 20:
            raise Exception("获取验证码超时")

        try:
            print("正在连接到IMAP服务器...")
            # 连接到IMAP服务器
            mail = imaplib.IMAP4_SSL(
                self.imap_config["imap_server"], self.imap_config["imap_port"]
            )
            print("连接到IMAP服务器成功")
            # 使用基本邮箱地址登录（不带别名）
            mail.login(self.base_email, self.imap_config["imap_pass"])
            print("登录成功")
            mail.select(self.imap_config["imap_dir"])
            print("选择邮箱目录成功")
            # 搜索来自 Cursor 的邮件
            status, messages = mail.search(None, "FROM", '"no-reply@cursor.sh"')
            print("搜索邮件成功")
            if status != "OK":
                return None
            mail_ids = messages[0].split()
            if not mail_ids:
                # 没有获取到，就再获取一次
                return self.get_verification_code(retry=retry + 1)

            latest_mail_id = mail_ids[-1]
            print("获取最新邮件ID成功")
            # 获取邮件内容
            status, msg_data = mail.fetch(latest_mail_id, "(RFC822)")
            if status != "OK":
                return None
            print("获取邮件内容成功")
            raw_email = msg_data[0][1]
            email_message = email.message_from_bytes(raw_email)
            print("解析邮件内容成功")
            # 提取邮件正文
            body = self._extract_mail_body(email_message)
            print("提取邮件正文成功")
            if body:
                # 使用正则表达式查找验证码
                # 匹配模式：
                # 1. 查找包含常见验证码相关词的上下文
                # 2. 查找附近的6位数字（可能带空格）
                code_patterns = [
                    r"code is:[\s\n]*([0-9][\s]*[0-9][\s]*[0-9][\s]*[0-9][\s]*[0-9][\s]*[0-9])",  # Cursor格式
                    r"验证码[：:\s]*?(\d{6})",  # 中文场景
                    r"verification code[：:\s]*?(\d{6})",  # 英文场景
                    r"code[：:\s]*?(\d{6})",  # 简单场景
                    r"(\d{6})",  # 降级匹配：仅匹配6位数字
                ]
                print("开始匹配验证码")
                for pattern in code_patterns:
                    code_match = re.search(pattern, body, re.IGNORECASE)
                    if code_match:
                        print("匹配到验证码")
                        # 移除所有空白字符
                        code = re.sub(r"\s", "", code_match.group(1))
                        # 删除邮件
                        mail.store(latest_mail_id, "+FLAGS", "\\Deleted")
                        mail.expunge()
                        mail.logout()
                        return code

            mail.logout()
            return None

        except Exception as e:
            logging.error(f"发生错误: {e}")
            return None

    def _extract_mail_body(self, email_message):
        """提取邮件正文"""
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if (
                    content_type == "text/plain"
                    and "attachment" not in content_disposition
                ):
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body = part.get_payload(decode=True).decode(
                            charset, errors="ignore"
                        )
                        return body
                    except Exception as e:
                        logging.error(f"解码邮件正文失败: {e}")
        else:
            content_type = email_message.get_content_type()
            if content_type == "text/plain":
                charset = email_message.get_content_charset() or "utf-8"
                try:
                    body = email_message.get_payload(decode=True).decode(
                        charset, errors="ignore"
                    )
                    return body
                except Exception as e:
                    logging.error(f"解码邮件正文失败: {e}")
        return ""
