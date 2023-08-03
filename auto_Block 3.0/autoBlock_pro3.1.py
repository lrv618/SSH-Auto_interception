#!/usr/bin/env python3

import re
import subprocess
import time
import logging

# 安全日志文件的路径
logFile = '/var/log/secure'   

# 黑名单文件的路径
hostDeny = '/etc/hosts.deny'

# 密码错误次数的阈值
passwd_wrong_num_1 = 2   # 非法用户登录错误次数
passwd_wrong_num_2 = 5   # 密码错误登录次数

# 配置日志记录
logging.basicConfig(filename='ssh_auto_interception.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 读取黑名单文件，并将其中的IP地址转换为字典
def getDenies():
    deniedDict = {}  

    with open(hostDeny) as file:  
        for ip in file:  
            group = re.search(r'(\d+\.\d+\.\d+\.\d+)', ip)     
            if group: 
                deniedDict[group[1]] = 'Ban'  
    return deniedDict   

# 监控方法
def monitorLog(logFile):   
    tempIp = {}        
    deniedDict = getDenies()     
    with open(logFile) as file:
        while True:   # 无限循环，用于持续监控安全日志文件。           
            line = file.readline().strip()   
            if line:                 
                # 1.用户不存在情况
                group = re.search(r'Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)', line)  
                if group:
                    ip = group[1]  
                    if not tempIp.get(ip): 
                        tempIp[ip] = 1   
                    else:
                        tempIp[ip] = tempIp[ip] + 1  
                    
                    if tempIp[ip] > passwd_wrong_num_1 and not deniedDict.get(ip):  
                        del tempIp[ip]  
                        subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny)) 
                        deniedDict[ip] = 'Ban' 
                        logging.warning('Invalid user IP: {}'.format(ip)) 
                    continue 
                       
                # 2.用户存在，但是密码错误情况
                group = re.search(r'Failed password for \w+ from (\d+\.\d+\.\d+\.\d+) ', line)
                if group:  
                    ip = group[1]  
                    if not tempIp.get(ip):   
                        tempIp[ip] = 1  
                    else:  
                        tempIp[ip] = tempIp[ip] + 1  
                    
                    if tempIp[ip] > passwd_wrong_num_2 and not deniedDict.get(ip):  
                        del tempIp[ip]  
                        subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny))  
                        deniedDict[ip] = 'Ban'  
                        logging.warning('Invalid password IP: {}'.format(ip))
                    continue
   
                        
if __name__ == '__main__':  # 表示以下代码块只在直接运行脚本时执行
    logging.info('SSH Auto Interception Started')  # 记录脚本开始的日志
    monitorLog(logFile)   # 调用 monitorLog 方法，开始监控安全日志文件
