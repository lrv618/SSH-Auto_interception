#!/usr/bin/env python3

import re
import subprocess
import time

#安全日志文件的路径
logFile = '/var/log/secure'   

#黑名单文件的路径
hostDeny = '/etc/hosts.deny'

# 密码错误次数的阈值
passwd_wrong_num_1 = 2   #非法用户登录错误次数
passwd_wrong_num_2 = 5   #密码错误登录次数

# 读取黑名单文件，并将其中的IP地址转换为字典
def getDenies():
    deniedDict = {}  

    with open(hostDeny) as file:  
        for ip in file:  
            group = re.search(r'(\d+\.\d+\.\d+\.\d+)', ip)     
            if group:   # 如果找到了匹配的IP地址
                deniedDict[group[1]] = 'Hacker'  
    return deniedDict   

# 监控方法
def monitorLog(logFile):   
    tempIp = {}        
    deniedDict = getDenies()     
    with open(logFile) as file:
        while True:   #无限循环，用于持续监控安全日志文件。           
            line = file.readline().strip()   
            if line:                 
                #1.用户不存在情况
                group = re.search(r'Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)', line)  
                if group:
                    ip = group[1]  
                    if not tempIp.get(ip): 
                        tempIp[ip]=1   
                    else:
                        tempIp[ip] = tempIp[ip] + 1  
                    
                    if tempIp[ip] > passwd_wrong_num_1 and not deniedDict.get(ip):  
                        del tempIp[ip]  #从 tempIp 字典中删除这个IP_ADDRESS 的记录。
                        subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny)) 
                        deniedDict[ip] = 'Hacker' 
                        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                        print('{} --- add ip:{} to hosts.deny for invalid user'.format(time_str, ip)) 
                    continue 
                       
                #2.用户存在，但是密码错误情况
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
                        deniedDict[ip] = '1'  
                        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                        print('{} --- add ip:{} to hosts.deny for invalid password'.format(time_str, ip))
                    continue    
if __name__ == '__main__':  #表示以下代码块只在直接运行脚本时执行
    monitorLog(logFile)   #调用monitorLog方法，开始监控安全日志文件

