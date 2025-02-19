CURSOR_LOGO = """
  ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗     ██████╗ ██████╗  ██████╗ 
 ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗
 ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝    ██████╔╝██████╔╝██║   ██║
 ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗    ██╔═══╝ ██╔══██╗██║   ██║
 ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║    ██║     ██║  ██║╚██████╔╝
  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 

Pro Version Activator v1.3.02
Author: Pin Studios | yeongpin

Press 5 to change language | 按下 5 键切换语言
"""

VERSION = "1.3.02"
AUTHOR = "shengdingbox|📺 B站UP主: 想回家的前端"


def print_logo():
    """打印带有版本号和作者信息的 logo"""
    from colorama import Fore, Style
    
    # 使用蓝色打印 LOGO
    print(Fore.LIGHTBLUE_EX + CURSOR_LOGO.strip())
    
    # 使用黄色打印版本信息
    print(Fore.YELLOW + f"Pro Version Activator v{VERSION}")
    
    # 使用绿色打印作者信息
    print(Fore.GREEN + f"Author: {AUTHOR}")
    
    # 使用红色打印语言切换提示
    print(Fore.RED + "请前往官网查看更多信息：https://cursoracct.wgets.org")
    
    # 重置颜色
    print(Style.RESET_ALL)


if __name__ == "__main__":
    print_logo()
