import os
import requests
import json
import sys
from colorama import Fore, Style
from enum import Enum
from typing import Optional
import webbrowser  # 添加到文件顶部的导入部分

from exit_cursor import ExitCursor
import go_cursor_help
import patch_cursor_get_machine_id
from reset_machine import MachineIDResetter

os.environ["PYTHONVERBOSE"] = "0"
os.environ["PYINSTALLER_VERBOSE"] = "0"

import time
import random
from cursor_auth_manager import CursorAuthManager
import os
from logger import logging
from browser_utils import BrowserManager
from get_email_code import EmailVerificationHandler
from logo import print_logo
from config import Config
from datetime import datetime
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gzip

# 定义 EMOJI 字典
EMOJI = {"ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}

# 添加常量
API_HOST = "https://cursoracct.wgets.org"
AES_KEY = "04eb155c79214c869be5d83d3f3c28dc"

class User:
    def __init__(self, username="", password="", token=""):
        self.username = username
        self.password = password
        self.token = token


class VerificationStatus(Enum):
    """验证状态枚举"""

    PASSWORD_PAGE = "@name=password"
    CAPTCHA_PAGE = "@data-index=0"
    ACCOUNT_SETTINGS = "Account Settings"


class TurnstileError(Exception):
    """Turnstile 验证相关异常"""

    pass


def save_screenshot(tab, stage: str, timestamp: bool = True) -> None:
    """
    保存页面截图

    Args:
        tab: 浏览器标签页对象
        stage: 截图阶段标识
        timestamp: 是否添加时间戳
    """
    try:
        # 创建 screenshots 目录
        screenshot_dir = "screenshots"
        if not os.path.exists(screenshot_dir):
            os.makedirs(screenshot_dir)

        # 生成文件名
        if timestamp:
            filename = f"turnstile_{stage}_{int(time.time())}.png"
        else:
            filename = f"turnstile_{stage}.png"

        filepath = os.path.join(screenshot_dir, filename)

        # 保存截图
        tab.get_screenshot(filepath)
        logging.debug(f"截图已保存: {filepath}")
    except Exception as e:
        logging.warning(f"截图保存失败: {str(e)}")


def check_verification_success(tab) -> Optional[VerificationStatus]:
    """
    检查验证是否成功

    Returns:
        VerificationStatus: 验证成功时返回对应状态，失败返回 None
    """
    for status in VerificationStatus:
        if tab.ele(status.value):
            logging.info(f"验证成功 - 已到达{status.name}页面")
            return status
    return None


def handle_turnstile(tab, max_retries: int = 2, retry_interval: tuple = (1, 2)) -> bool:
    """
    处理 Turnstile 验证

    Args:
        tab: 浏览器标签页对象
        max_retries: 最大重试次数
        retry_interval: 重试间隔时间范围(最小值, 最大值)

    Returns:
        bool: 验证是否成功

    Raises:
        TurnstileError: 验证过程中出现异常
    """
    logging.info("正在检测 Turnstile 验证...")
    save_screenshot(tab, "start")

    retry_count = 0

    try:
        while retry_count < max_retries:
            retry_count += 1
            logging.debug(f"第 {retry_count} 次尝试验证")

            try:
                # 定位验证框元素
                challenge_check = (
                    tab.ele("@id=cf-turnstile", timeout=2)
                    .child()
                    .shadow_root.ele("tag:iframe")
                    .ele("tag:body")
                    .sr("tag:input")
                )

                if challenge_check:
                    logging.info("检测到 Turnstile 验证框，开始处理...")
                    # 随机延时后点击验证
                    time.sleep(random.uniform(1, 3))
                    challenge_check.click()
                    time.sleep(2)

                    # 保存验证后的截图
                    save_screenshot(tab, "clicked")

                    # 检查验证结果
                    if check_verification_success(tab):
                        logging.info("Turnstile 验证通过")
                        save_screenshot(tab, "success")
                        return True

            except Exception as e:
                logging.debug(f"当前尝试未成功: {str(e)}")

            # 检查是否已经验证成功
            if check_verification_success(tab):
                return True

            # 随机延时后继续下一次尝试
            time.sleep(random.uniform(*retry_interval))

        # 超出最大重试次数
        logging.error(f"验证失败 - 已达到最大重试次数 {max_retries}")
        logging.error(
            "请前往开源项目查看更多信息："+API_HOST
        )
        save_screenshot(tab, "failed")
        return False

    except Exception as e:
        error_msg = f"Turnstile 验证过程发生异常: {str(e)}"
        logging.error(error_msg)
        save_screenshot(tab, "error")
        raise TurnstileError(error_msg)


def get_cursor_session_token(tab, max_attempts=3, retry_interval=2):
    """
    获取Cursor会话token，带有重试机制
    :param tab: 浏览器标签页
    :param max_attempts: 最大尝试次数
    :param retry_interval: 重试间隔(秒)
    :return: session token 或 None
    """
    logging.info("开始获取cookie")
    attempts = 0

    while attempts < max_attempts:
        try:
            cookies = tab.cookies()
            for cookie in cookies:
                if cookie.get("name") == "WorkosCursorSessionToken":
                    return cookie["value"].split("%3A%3A")[1]

            attempts += 1
            if attempts < max_attempts:
                logging.warning(
                    f"第 {attempts} 次尝试未获取到CursorSessionToken，{retry_interval}秒后重试..."
                )
                time.sleep(retry_interval)
            else:
                logging.error(
                    f"已达到最大尝试次数({max_attempts})，获取CursorSessionToken失败"
                )

        except Exception as e:
            logging.error(f"获取cookie失败: {str(e)}")
            attempts += 1
            if attempts < max_attempts:
                logging.info(f"将在 {retry_interval} 秒后重试...")
                time.sleep(retry_interval)

    return None


def update_cursor_auth(email=None, access_token=None, refresh_token=None):
    """
    更新Cursor的认证信息的便捷函数
    """
    auth_manager = CursorAuthManager()
    return auth_manager.update_auth(email, access_token, refresh_token)


def sign_up_account(browser, tab):
    logging.info("=== 开始注册账号流程 ===")
    logging.info(f"正在访问注册页面: {sign_up_url}")
    tab.get(sign_up_url)

    try:
        if tab.ele("@name=first_name"):
            logging.info("正在填写个人信息...")
            tab.actions.click("@name=first_name").input(first_name)
            logging.info(f"已输入名字: {first_name}")
            time.sleep(random.uniform(1, 3))

            tab.actions.click("@name=last_name").input(last_name)
            logging.info(f"已输入姓氏: {last_name}")
            time.sleep(random.uniform(1, 3))

            tab.actions.click("@name=email").input(account)
            logging.info(f"已输入邮箱: {account}")
            time.sleep(random.uniform(1, 3))

            logging.info("提交个人信息...")
            tab.actions.click("@type=submit")

    except Exception as e:
        logging.error(f"注册页面访问失败: {str(e)}")
        return False

    handle_turnstile(tab)

    try:
        if tab.ele("@name=password"):
            logging.info("正在设置密码...")
            tab.ele("@name=password").input(password)
            time.sleep(random.uniform(1, 3))

            logging.info("提交密码...")
            tab.ele("@type=submit").click()
            logging.info("密码设置完成，等待系统响应...")

    except Exception as e:
        logging.error(f"密码设置失败: {str(e)}")
        return False

    if tab.ele("This email is not available."):
        logging.error("注册失败：邮箱已被使用")
        return False

    handle_turnstile(tab)

    while True:
        try:
            if tab.ele("Account Settings"):
                logging.info("注册成功 - 已进入账户设置页面")
                break
            if tab.ele("@data-index=0"):
                logging.info("正在获取邮箱验证码...")
                code = email_handler.get_verification_code()
                if not code:
                    logging.error("获取验证码失败")
                    return False

                logging.info(f"成功获取验证码: {code}")
                logging.info("正在输入验证码...")
                i = 0
                for digit in code:
                    tab.ele(f"@data-index={i}").input(digit)
                    time.sleep(random.uniform(0.1, 0.3))
                    i += 1
                logging.info("验证码输入完成")
                break
        except Exception as e:
            logging.error(f"验证码处理过程出错: {str(e)}")

    handle_turnstile(tab)
    wait_time = random.randint(3, 6)
    for i in range(wait_time):
        logging.info(f"等待系统处理中... 剩余 {wait_time-i} 秒")
        time.sleep(1)

    logging.info("正在获取账户信息...")
    tab.get(settings_url)
    try:
        usage_selector = (
            "css:div.col-span-2 > div > div > div > div > "
            "div:nth-child(1) > div.flex.items-center.justify-between.gap-2 > "
            "span.font-mono.text-sm\\/\\[0\\.875rem\\]"
        )
        usage_ele = tab.ele(usage_selector)
        if usage_ele:
            usage_info = usage_ele.text
            total_usage = usage_info.split("/")[-1].strip()
            logging.info(f"账户可用额度上限: {total_usage}")
            logging.info(
                "请前往开源项目查看更多信息："+API_HOST
            )
    except Exception as e:
        logging.error(f"获取账户额度信息失败: {str(e)}")

    logging.info("\n=== 注册完成 ===")
    account_info = f"Cursor 账号信息:\n邮箱: {account}\n密码: {password}"
    logging.info(account_info)
    time.sleep(5)
    return True


class EmailGenerator:
    def __init__(
        self,
        password="".join(
            random.choices(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*",
                k=12,
            )
        ),
    ):
        configInstance = Config()
        configInstance.print_config()
        self.domain = configInstance.get_domain()
        self.default_password = password
        self.default_first_name = self.generate_random_name()
        self.default_last_name = self.generate_random_name()

    def generate_random_name(self, length=6):
        """生成随机用户名"""
        first_letter = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        rest_letters = "".join(
            random.choices("abcdefghijklmnopqrstuvwxyz", k=length - 1)
        )
        return first_letter + rest_letters

    def generate_email(self, length=8):
        """生成随机邮箱地址"""
        random_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=length))
        timestamp = str(int(time.time()))[-6:]  # 使用时间戳后6位
        return f"{random_str}{timestamp}@{self.domain}"

    def get_account_info(self):
        """获取完整的账号信息"""
        return {
            "email": self.generate_email(),
            "password": self.default_password,
            "first_name": self.default_first_name,
            "last_name": self.default_last_name,
        }


def get_user_agent():
    """获取user_agent"""
    try:
        # 使用JavaScript获取user agent
        browser_manager = BrowserManager()
        browser = browser_manager.init_browser()
        user_agent = browser.latest_tab.run_js("return navigator.userAgent")
        browser_manager.quit()
        return user_agent
    except Exception as e:
        logging.error(f"获取user agent失败: {str(e)}")
        return None


def check_cursor_version():
    """检查cursor版本"""
    pkg_path, main_path = patch_cursor_get_machine_id.get_cursor_paths()
    with open(pkg_path, "r", encoding="utf-8") as f:
        version = json.load(f)["version"]
    return patch_cursor_get_machine_id.version_check(version, min_version="0.45.0")


def reset_machine_id(greater_than_0_45):
    if greater_than_0_45:
        # 提示请手动执行脚本 https://github.com/shengdingbox/cursor-auto-free/blob/main/patch_cursor_get_machine_id.py
        go_cursor_help.go_cursor_help()
    else:
        MachineIDResetter().reset_machine_ids()


def disable_auto_update():
    """禁用Cursor自动更新功能"""
    try:
        pkg_path, main_path = patch_cursor_get_machine_id.get_cursor_paths()
        main_js_path = os.path.join(os.path.dirname(pkg_path), "out", "main.js")
        if not os.path.exists(main_js_path):
            logging.error("未找到main.js文件，无法禁用自动更新")
            return False
            
        with open(main_js_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 替换更新检查逻辑
            updated_content = content.replace('!!this.args["disable-updates"]', 'true')
            
            with open(main_js_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            
            logging.info("已成功禁用Cursor自动更新")
            return True
    except Exception as e:
        logging.error(f"禁用自动更新失败: {str(e)}")
        return False


def login(user):
    """登录函数"""
    try:
        logging.info("正在尝试登录...")
        url = f"{API_HOST}/api/login?username={user.username}&password={user.password}&t={int(time.time() * 1000)}"
        
        response = requests.get(url)
        if response.status_code >= 400:
            logging.error(f"HTTP错误: {response.status_code}")
            return False
            
        data = response.json()
        if data.get("token"):
            user.token = data["token"]
            return True
            
        logging.error(f"登录错误: {data.get('error', '未知错误')}")
        return False
        
    except Exception as e:
        logging.error(f"登录失败: {str(e)}")
        return False


def get_main_js_from_network(token):
    """从网络获取main.js文件"""
    try:
        url = f"{API_HOST}/api/ts?t={int(time.time() * 1000)}"
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        
        response = requests.get(url, headers=headers)
        if response.status_code >= 400:
            logging.error(f"获取main.js失败，状态码: {response.status_code}")
            return None
            
        try:
            data = response.json().get('data')
            if not data:
                logging.error("响应数据格式错误")
                return None
            return data
        except ValueError:
            logging.error("解析JSON响应失败")
            return None
            
    except Exception as e:
        logging.error(f"网络请求失败: {str(e)}")
        return None


def decrypt_main_js(encrypted_data):
    """解密main.js文件内容"""
    try:
        # Base64解码
        base64_decoded = base64.b64decode(encrypted_data)
        
        # AES解密
        key = bytes(AES_KEY, 'utf-8')  # 使用正确的密钥
        iv = key[:16]  # 使用密钥的前16位作为IV
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(base64_decoded) + decryptor.finalize()
        
        # 移除PKCS7填充
        if len(decrypted_data) == 0:
            raise ValueError("解密后数据为空")
            
        padding_length = decrypted_data[-1]
        if padding_length > len(decrypted_data):
            raise ValueError("无效的填充长度")
            
        decrypted_data = decrypted_data[:-padding_length]
        
        # GZIP解压
        try:
            decompressed_data = gzip.decompress(decrypted_data)
            return decompressed_data.decode('utf-8')
        except Exception as gz_error:
            logging.error(f"GZIP解压失败: {str(gz_error)}")
            # 打印一些调试信息
            logging.debug(f"解密数据前16字节: {decrypted_data[:16]}")
            return None
        
    except Exception as e:
        logging.error(f"解密过程失败: {str(e)}")
        return None


def get_gateway_path():
    """获取网关文件路径"""
    try:
        # 判断操作系统
        if sys.platform == "win32":  # Windows
            home = os.path.expanduser("~")
            gateway_path = os.path.join(
                home,
                "AppData",
                "Local", 
                "Programs", 
                "cursor", 
                "resources",
                "app", 
                "extensions", 
                "cursor-always-local", 
                "dist",
                "main.js"
            )
        elif sys.platform == "darwin":  # macOS
            gateway_path = os.path.abspath(os.path.expanduser(
                "/Applications/Cursor.app/Contents/Resources/app/extensions/cursor-always-local/dist/main.js"
            ))
        else:
            raise OSError("不支持的操作系统")
            
        if not os.path.exists(gateway_path):
            raise FileNotFoundError("未找到网关文件，请确认Cursor安装正确")
            
        return gateway_path
    except Exception as e:
        logging.error(f"获取网关路径失败: {str(e)}")
        return None


def apply_gateway_patch():
    """应用无限额度网关补丁"""
    try:
        # 获取用户登录信息
        username = input("请输入用户名: ").strip()
        password = input("请输入密码: ").strip()
        
        user = User(username=username, password=password)
        
        # 尝试登录
        logging.info("正在登录...")
        if not login(user):
            logging.error("登录失败，无法应用补丁")
            return False
            
        # 获取网关文件
        logging.info("正在从网络获取最新网关文件...")
        encrypted_js = get_main_js_from_network(user.token)
        if not encrypted_js:
            logging.error("获取网关文件失败")
            return False
            
        logging.info("正在解密网关文件...")
        decrypted_js = decrypt_main_js(encrypted_js)
        if not decrypted_js:
            logging.error("解密网关文件失败")
            return False
            
        # 获取目标文件路径
        gateway_path = get_gateway_path()
        if not gateway_path:
            return False
            
        # 备份原文件
        backup_path = f"{gateway_path}.bak"
        if not os.path.exists(backup_path):
            try:
                import shutil
                shutil.copy2(gateway_path, backup_path)
                logging.info("已创建原文件备份")
            except Exception as e:
                logging.error(f"创建备份失败: {str(e)}")
                return False
        
        # 替换账号信息并写入文件
        try:
            # 使用token替换test:123456
            updated_content = decrypted_js.replace('test:123456', user.token)
            
            with open(gateway_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)
                
            logging.info("网关补丁应用成功")
            return True
        except Exception as e:
            logging.error(f"写入文件失败: {str(e)}")
            return False
            
    except Exception as e:
        logging.error(f"应用网关补丁失败: {str(e)}")
        return False


def restore_gateway():
    """还原网关文件"""
    try:
        gateway_path = get_gateway_path()
        if not gateway_path:
            return False
            
        backup_path = f"{gateway_path}.bak"
        if not os.path.exists(backup_path):
            logging.error("未找到备份文件，无法还原")
            return False
            
        try:
            # 删除当前的main.js
            os.remove(gateway_path)
            logging.info("已删除当前网关文件")
            
            # 将backup文件重命名为main.js
            os.rename(backup_path, gateway_path)
            logging.info("网关文件已还原成功")
            return True
            
        except Exception as e:
            logging.error(f"还原文件失败: {str(e)}")
            return False
            
    except Exception as e:
        logging.error(f"还原网关失败: {str(e)}")
        return False


def show_menu():
    """显示操作菜单"""
    print("\n=== Cursor 配置工具 ===")
    print("0. 打开官网地址: "+API_HOST)
    print("1. 重置机器码")
    print("2. 自动注册账号")
    print("3. 禁用自动更新")
    print("4. 无限额度网关补丁")
    print("5. 还原网关文件")
    print("6. 退出程序")
    print("=" * 30)


if __name__ == "__main__":
    print_logo()
    greater_than_0_45 = check_cursor_version()
    browser_manager = None
    
    try:
        logging.info("\n=== 初始化程序 ===")
        ExitCursor()

        while True:
            show_menu()
            try:
                choice = int(input("请输入选项 (0-6): ").strip())
                if choice not in [0, 1, 2, 3, 4, 5, 6]:
                    print("无效的选项，请重新输入")
                    continue
                    
                if choice == 0:
                    logging.info("正在打开官网...")
                    webbrowser.open(API_HOST)
                    continue
                    
                if choice == 6:
                    logging.info("程序退出")
                    break
                    
                if choice == 3:
                    if disable_auto_update():
                        logging.info("自动更新已禁用，请重启Cursor")
                    continue
                    
                if choice == 4:
                    if apply_gateway_patch():
                        logging.info("网关补丁已应用，请重启Cursor")
                    continue
                    
                if choice == 5:
                    if restore_gateway():
                        logging.info("网关已还原，请重启Cursor")
                    continue
                    
                if choice == 1:
                    # 仅执行重置机器码
                    reset_machine_id(greater_than_0_45)
                    logging.info("机器码重置完成")
                    continue

                # choice == 2 的情况，执行完整注册流程
                logging.info("正在初始化浏览器...")
                
                # 获取user_agent
                user_agent = get_user_agent()
                if not user_agent:
                    logging.error("获取user agent失败，使用默认值")
                    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

                # 剔除user_agent中的"HeadlessChrome"
                user_agent = user_agent.replace("HeadlessChrome", "Chrome")

                browser_manager = BrowserManager()
                browser = browser_manager.init_browser(user_agent)

                # 获取并打印浏览器的user-agent
                user_agent = browser.latest_tab.run_js("return navigator.userAgent")

                logging.info("正在初始化邮箱验证模块...")
                email_handler = EmailVerificationHandler()
                logging.info(
                    "请前往开源项目查看更多信息："+API_HOST
                )
                logging.info("\n=== 配置信息 ===")
                login_url = "https://authenticator.cursor.sh"
                sign_up_url = "https://authenticator.cursor.sh/sign-up"
                settings_url = "https://www.cursor.com/settings"
                mail_url = "https://tempmail.plus"

                logging.info("正在生成随机账号信息...")
                email_generator = EmailGenerator()
                account = email_generator.generate_email()
                password = email_generator.default_password
                first_name = email_generator.default_first_name
                last_name = email_generator.default_last_name

                logging.info(f"生成的邮箱账号: {account}")
                auto_update_cursor_auth = True

                tab = browser.latest_tab

                tab.run_js("try { turnstile.reset() } catch(e) { }")

                logging.info("\n=== 开始注册流程 ===")
                logging.info(f"正在访问登录页面: {login_url}")
                tab.get(login_url)

                if sign_up_account(browser, tab):
                    logging.info("正在获取会话令牌...")
                    token = get_cursor_session_token(tab)
                    if token:
                        logging.info("更新认证信息...")
                        update_cursor_auth(
                            email=account, access_token=token, refresh_token=token
                        )
                        logging.info(
                            "请前往开源项目查看更多信息："+API_HOST
                        )
                        logging.info("重置机器码...")
                        reset_machine_id(greater_than_0_45)
                        htps_request = requests.post(
                            url=API_HOST+"/addToken",
                            json={
                                "email": account,
                                "password": password,
                                "first_name": first_name,
                                "last_name": last_name,
                                "token": token,
                            }
                        )
                        logging.info("所有操作已完成")
                    else:
                        logging.error("获取会话令牌失败，注册流程未完成")

            except ValueError:
                print("请输入有效的数字")

    except Exception as e:
        logging.error(f"程序执行出现错误: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
    finally:
        if browser_manager:
            browser_manager.quit()
        input("\n程序执行完毕，按回车键退出...")
