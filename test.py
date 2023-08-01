import re
import subprocess
import time

#安全日志文件的路径
logFile ='/var/log/secure'

#黑名单文件的路径
hostDeny ='/etc/hosts.deny'

# 密码错误次数的阈值
passwd_num = 3

#读取黑名单
def getDenies():
    deniedDict = {}
    with open(hostDeny) as file:
        for ip in file:
            group = re.search(r'(\d+\.\d+\.\d+\.\d+)', ip)
            if group:
                deniedDict[group[1]] ='Hacker'
    return deniedDict


#读取安全日志
def monitorLog(logFile):
    tempIP = {}
    deniedDict = getDenies()
    with open(logFile) as file:
        file.seek(0,2)
        while True:
            line = file.readline().strip()
            if line:
                group = re.search(r'Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)', line)
                if group:
                    ip=group[1]
                    if not tempIP.get(ip):
                        tempIP[ip]=1
                    else:
                        tempIP[ip]=tempIP[ip]+1

                    if tempIP[ip] > passwd_num and not deniedDict.get(ip):
                        del tempIP[ip]
                        subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny))
                        deniedDict[ip]='Hacker'
                        print('This test is acess')
                    else:
                        pass
                    
                        
            
if __name__ == '__main__':  
    monitorLog(logFile)   