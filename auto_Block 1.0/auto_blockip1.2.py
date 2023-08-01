#！/usr/bin/env python3

import re
import subprocess
import time


#安全日志
logFile='/var/log/secure'    

#黑名单
hostDeny='/etc/hosts.deny'   

#封禁阈值
passwd_wrong_num = 5      

#获取已经加入黑名单IP，转化为字典
def getDenies():      
    deniedDict={}  
    list=open(hostDeny).readlines()   
    for ip in list:    
        group=re.search(r'(\d+\.\d+\.\d+\.\d+)',ip)  
        if group:   
            deniedDict[group[1]]='1'   
    return deniedDict  

#监控方法
def monitorLog(logfile):
    tempIp = {}   
    deniedDict=getDenies()  
    
    #读取安全日志
    popen=subprocess.Popen('tail -f '+logFile,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    

    #监控日志
    while True:   
        time.sleep(0.1)  
        
        line=popen.stdout.readline().strip()  
        if line: 
            group=re.search(r'Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)',str(line))  

            #1.用户不存在情况
            if group and not deniedDict.get(group[1]):  
                subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(group[1],hostDeny))  
                deniedDict[group[1]]='1' 
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))  
                print('{} --- add ip:{} to hosts.deny for invalid user'.format(time_str,group[1]))
                continue   

            #2.用户存在，但是密码错误情况
            group=re.search(r'Failed password for \w+ from (\d+\.\d+\.\d+\.\d+)',str(line))
            if group:  
                ip = group[1]  
                #统计IP错误次数
                if not tempIp.get(ip):  
                    tempIp[ip]=1  
                else:  
                    tempIp[ip]=tempIp[ip]+1   
                
                #如果错误次数大于阈值，直接封禁该IP
                if tempIp[ip] > passwd_wrong_num and not deniedDict.get(ip):   
                    del tempIp[ip]  
                    subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip,hostDeny))  
                    deniedDict[ip]='1'  
                    time_str=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
                    print('{} --- add ip:{} to hosts.deny for invalid password'.format(time_str,ip))  


if __name__=='__main__':
    monitorLog(logFile)
#表示以下代码块只在直接运行脚本时执行，而在作为模块被导入时不会执行