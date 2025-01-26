# Cursor Pro 自动化工具使用说明


[English doc](./README.EN.md)



## 在线文档
[cursor-auto-free-doc.vercel.app](https://cursor-auto-free-doc.vercel.app)


## 许可证声明
本项目采用 [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/) 许可证。
这意味着您可以：
- 分享 — 在任何媒介以任何形式复制、发行本作品
但必须遵守以下条件：
- 非商业性使用 — 您不得将本作品用于商业目的

## 声明
- 本项目仅供学习交流使用，请勿用于商业用途。
- 本项目不承担任何法律责任，使用本项目造成的任何后果，由使用者自行承担。



## 你让开源没有爱啊！！！！（非法商用黑名单）
| 仓库 | 售卖方式 | 
| ----- | ----- | 
| [gitee海豚](https://gitee.com/ydd_energy/dolphin_-cursor) | survivor_bias_  （微信） | 




## 请我喝杯茶
![image](./screen/28613e3f3f23a935b66a7ba31ff4e3f.jpg)


# Cursor Auto Free

自动注册 Cursor Pro 账号，支持 Gmail/Outlook 邮箱别名。

## 特性

- 支持 Gmail 和 Outlook 邮箱别名
- 自动处理 Turnstile 验证
- 自动获取邮箱验证码
- 自动注册账号

## 使用说明

### 1. 配置邮箱

#### Gmail 配置
1. 开启两步验证：
   - 访问 [Google 账号安全设置](https://myaccount.google.com/security)
   - 开启"两步验证"
2. 生成应用专用密码：
   - 访问 [应用专用密码](https://myaccount.google.com/apppasswords)
   - 选择"其他"，输入名称（如 "Cursor"）
   - 复制生成的 16 位密码

#### Outlook 配置
1. 开启双重验证：
   - 访问 [Outlook 账户安全设置](https://account.live.com/proofs/manage/additional)
   - 开启"双重验证"
2. 生成应用密码：
   - 访问 [安全信息](https://account.live.com/proofs/manage)
   - 选择"创建新的应用密码"
   - 复制生成的密码

### 2. 配置 .env 文件

```env
# Gmail 配置示例
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USER=your.email@gmail.com
IMAP_PASS=xxxx xxxx xxxx xxxx  # Gmail 应用专用密码

# Outlook 配置示例
# IMAP_SERVER=outlook.office365.com
# IMAP_PORT=993
# IMAP_USER=your.email@outlook.com
# IMAP_PASS=xxxx xxxx xxxx xxxx  # Outlook 应用密码
```

### 3. 运行程序

```bash
python cursor_pro_keep_alive.py
```

## 工作原理

1. 使用邮箱别名功能：
   - Gmail 格式：`username+alias@gmail.com`
   - Outlook 格式：`username+alias@outlook.com`
2. 程序会自动生成随机别名，实现无限邮箱地址
3. 所有邮件都会发送到你的主邮箱，但对 Cursor 来说是不同的邮箱地址

## 注意事项

1. 确保已开启邮箱的 IMAP 访问
2. Gmail 需要使用应用专用密码
3. Outlook 需要使用应用密码
4. 建议使用单独的邮箱账号，避免影响主邮箱使用

## 常见问题

1. 无法连接 IMAP 服务器
   - 检查邮箱和密码是否正确
   - 确认是否使用了正确的应用专用密码
   - 检查是否开启了 IMAP 访问

2. 收不到验证码
   - 检查垃圾邮件文件夹
   - 确认邮箱别名格式是否正确
   - 检查邮箱过滤器设置

## 更新日志

- 2024-01-20: 移除域名邮箱支持，改用 Gmail/Outlook 别名
- 2024-01-11: 添加无头模式和代理配置
- 2024-01-10: 优化验证码获取逻辑
- 2024-01-09: 添加日志和自动构建

