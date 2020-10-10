import os
import re
from datetime import datetime
import configparser

#load config on the file 
config = configparser.ConfigParser()
config.sections()
config.read('/home/test/Desktop/config.ini')

#read from config.ini paths for files
pathlog = config['NMapLog']['pathlog']
pathwhitelist = config['whiteList']['pathwhitelist']
badMacLog = config['BadMacLog']['badMacLog']
scanpath = config['BadScanPath']['scanpath']
password = config['SystemPass']['password']

#read from config.ini display settings
display = config['Display']['Display']

#read from config.ini for log copy this is needed for webpage to work
weboutput = config['Web Output']['weboutput']

#read from config.ini whether to log ip or just mac
logIP = config['log IP']['logIP']


#scan network for new mac address
def Nmap (password,path):
    command = 'nmap -sP -n 10.10.2.0/24 -oN',path
    command = ' '.join(command)
    os.system('echo %s|sudo -S %s' % (password,command))
    return

#Enable OS detection, version detection, script scanning, and traceroute
def NmapOSscan(password,path,IP,Mac):
    command = 'nmap -A -sU -oN',path+'sU'+Mac+'.txt',IP
    command = ' '.join(command)
    os.system('echo %s|sudo -S %s' % (password,command))
    return

#re filters
def Filter (data,pattern):
    return(re.match(pattern,data))

def Mac (data):
    pattern = '[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]'
    return(re.findall(pattern,data))

def IP (data):
    pattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' 
    return(re.findall(pattern,data))

#load whitelist log
def fileload (path):
    file1 = []
    with open (path) as file:
        for row in file:
            file1.append(row)
    file.close()
    return(file1)

#load Nmap log
def fileloadlog (path):
    file1 = []
    with open (path) as file:
        for row in file:
            pattern = 'Nmap scan report for'
            ipAddress = Filter(row,pattern)
            if ipAddress:
                row = IP(row)
                file1.append(row[0])
            else:
                pattern = 'MAC Address:'
                macAddress = Filter(row,pattern)
                if macAddress:
                    row = Mac(row)
                    file1.append(row[0])
    file.close()
    return(file1)

#logic for if address appears in whitelist output ip
def logLogic(whitelist,Nmaplog,logIP,password,path):
    badList = []
    for i in range(0, len(Nmaplog), +2):
        mac = 0
        if i+1 < len(Nmaplog):
            for x in range(0, len(whitelist), +1):
                if Nmaplog[i+1] == whitelist[x]:
                    mac = 1
            if mac == 0:
                print(logIP)
                if logIP == '0':
                    #just log bac Mac
                    badList.append(Nmaplog[i+1])
                elif logIP == '1':
                    #log bad Mac and IP of bad Mac
                    badList.append(Nmaplog[i])
                    badList.append(Nmaplog[i+1])
                elif logIP == '2':
                    print('logIP2')
                    #log bad Mac and IP of bad Mac and scan IP from OS
                    IP = Nmaplog[i]
                    Mac = Nmaplog[i+1]    
                    NmapOSscan(password,path,IP,Mac)
                    badList.append(IP)
                    badList.append(Mac)
                else:
                   badList.append(Nmaplog[i+1]) 
    return(badList)

#print log file
def logFile(badList, path):
    file = open(path,"a")
    file.write(str(datetime.now())+'\n')
    file.close()
    for i in range(0,len(badList), +1):
        file = open(path,"a")
        file.write(badList[i]+'\n')
        file.close()

#Display Findings
def Display(badList,whitelist):
    print ('\nBelow MAC Address not in whitelist\n')
    for i in range(0,len(badList), +1):
        print(badList[i])
    print('\nWhitelist\n')
    for i in range(0, len(whitelist), +1):
        print(whitelist[i])
    return

#move log to /var/www/html for web output
def copyLog (password,path):
    hardpath = '/var/www/html/badMacLog.txt'
    command = 'cp',path,hardpath
    command = ' '.join(command)
    os.system('echo %s|sudo -S %s' % (password,command))
    return

#run network scanner
Nmap (password,pathlog)

#find pattern in log and whitelist
Nmaplog = fileloadlog(pathlog)

whitelist = Mac(' '.join(fileload(pathwhitelist)))

#run logic to compair log to whitelist
badList = logLogic(whitelist,Nmaplog,logIP,password,scanpath)

#Output BadList to log file
logFile(badList, badMacLog)

#display output if configered to
if display == '1':
    Display(badList,whitelist)

#run copyLog if web output is on
if weboutput == '1':
    copyLog(password,badMacLog)

