#!/usr/bin/env python3

import re
import subprocess
import time

#安全日志文件的路径
logFile = '/var/log/secure'   

#黑名单文件的路径
hostDeny = '/etc/hosts.deny'

# 密码错误次数的阈值
passwd_wrong_num = 3

# 读取黑名单文件，并将其中的IP地址转换为字典
def getDenies():
    deniedDict = {}  

    with open(hostDeny) as file: 
        for ip in file:  
            group = re.search(r'(\d+\.\d+\.\d+\.\d+)', ip)  
            if group:   
                deniedDict[group[1]] = 'BLOCKER'  
    return deniedDict   

# 监控方法
def monitorLog(logFile):   
    tempIp = {}         
    deniedDict = getDenies() 
    
    with open(logFile) as file:
        file.seek(0, 2)  # 将文件指针移到文件末尾，以便持续监控文件新增的日志。
        while True:   
            line = file.readline().strip()    
            if line:   
                #1.用户不存在情况
                group = re.search(r'Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)', line)  
                if group and not deniedDict.get(group[1]):  
                    subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(group[1], hostDeny))  
                    deniedDict[group[1]] = 'BLOCKER'  
                    time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    print('{} --- add ip:{} to hosts.deny for invalid user'.format(time_str, group[1]))
                    continue  
                       
                #2.用户存在，但是密码错误情况
                group = re.search(r'Failed password for \w+ from (\d+\.\d+\.\d+\.\d+) ', line)
                if group:  
                    ip = group[1]  
                    if not tempIp.get(ip):   
                        tempIp[ip] = 1  
                    else:  
                        tempIp[ip] = tempIp[ip] + 1  
                    if tempIp[ip] > passwd_wrong_num and not deniedDict.get(ip):  
                        del tempIp[ip]  
                        subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny))  
                        deniedDict[ip] = '1'  
                        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                        print('{} --- add ip:{} to hosts.deny for invalid password'.format(time_str, ip))
                        continue 
if __name__ == '__main__':  
    monitorLog(logFile)   

