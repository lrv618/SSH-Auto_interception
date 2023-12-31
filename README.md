# SSH Auto Interception Project

​		该项目是一个自动化SSH登录拦截的脚本，它可以监控安全日志文件中的SSH登录尝试事件，并自动拦截恶意用户或密码错误频繁的IP地址，将其添加到 `hosts.deny` 文件，从而防止进一步的登录尝试。



## 功能特性

- 监控安全日志文件中的SSH登录尝试事件。
- 根据设定的阈值自动拦截恶意用户或密码错误频繁的IP地址。
- 将拦截的IP地址添加到 `hosts.deny` 文件，阻止其后续的登录尝试。
- 将拦截的IP地址的相关事件记录到 `ssh_auto_interception.log` 文件中。



## 使用方法

1. 将 `ssh_auto_interception.py` 脚本拷贝到您的Linux服务器上。(推荐centOS7)

2. 配置安全日志文件路径：打开脚本，修改 `logFile` 变量为您的安全日志文件的路径，通常为 `/var/log/secure`。

3. 配置黑名单文件路径：同样在脚本中，修改 `hostDeny` 变量为您的黑名单文件的路径，通常为 `/etc/hosts.deny`。

4. 配置密码错误次数阈值：根据您的需求，可以修改 `passwd_wrong_num_1` 和 `passwd_wrong_num_2` 变量来设定非法用户登录错误次数和密码错误登录次数的阈值。

5. 运行脚本：在终端中运行以下命令启动监控脚本：

   ```
   bashCopy code
   python3 ssh_auto_interception.py
   ```

6. 日志记录：脚本会将拦截的IP地址和相关事件记录到 `ssh_auto_interception.log` 文件中，您可以使用文本编辑器查看。



## 注意事项

- 在修改 `passwd_wrong_num_1` 和 `passwd_wrong_num_2` 变量时，请谨慎设置阈值，避免误拦截合法用户。
- 使用前请确保您有足够的权限读取安全日志文件和写入黑名单文件。
- 脚本默认以 `WARNING` 级别记录事件日志，您可以根据需要在脚本中调整日志级别。

------



## 免责声明

​			本项目旨在增强服务器安全性，但不保证完全抵御所有可能的攻击。使用本项目时，请根据实际情况综合考虑其他安全措施。

**重要提示：** 未经授权的测试可能涉及非法行为，请确保您获得了合法授权并遵守相关法律法规。