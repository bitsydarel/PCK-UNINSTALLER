# -*- coding: utf-8 -*-
#!/usr/bin/python
import os
import sys
import json
import httplib
  
user = os.popen("/usr/bin/stat -f%Su /dev/console").read().split("\n")[0]
  
try:
    plist1 = [item.lower() for item in os.listdir("/Users/" + user + "/Library/LaunchAgents")]
except OSError:
    plist1 = []
try:
    plist2 = [item.lower() for item in os.listdir("/Library/LaunchAgents/")]
except OSError:
    plist2 = []
try:    
    plist3 = [item.lower() for item in os.listdir("/Library/LaunchDaemons/")]
except OSError:
    plist3 = []
  
#plist1 = [item.lower() for item in os.listdir("D:\Archive\home-LaunchAgents\\")]
#plist2 = [item.lower() for item in os.listdir("D:\Archive\LaunchAgents\\")]
#plist3 = [item.lower() for item in os.listdir('D:\Archive\LaunchDaemons\\')]
  
  
headers = {
    "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAAFo8DOE_eQCSVHZxDcb_oyPBXuJyqrRIicNEddOwkyaNv",
    "Dropbox-API-Arg": "{\"path\":\"/red.txt\"}"
}
  
c = httplib.HTTPSConnection("content.dropboxapi.com")
c.request("POST", "/2/files/download", "", headers)
r = c.getresponse()
red = str(r.read().lower())
  
headers = {
    "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAAF3nXzkmiAFo-BvoCREdZvDIyZUL-Eedx9fiOF-r9z720",
    "Dropbox-API-Arg": "{\"path\":\"/blue.txt\"}"
}
  
c2 = httplib.HTTPSConnection("content.dropboxapi.com")
c2.request("POST", "/2/files/download", "", headers)
r2 = c2.getresponse()
blue = str(r2.read().lower())
  
blueplist1 = []
redplist1 = []
unknown1 = []
blueplist2 = []
redplist2 = []
unknown2 = []
blueplist3 = []
redplist3 = []
unknown3 = []
  
for u in range(10):
    for i in plist1:
        a = i
        if a[:-6] in red:
           redplist1.append(i)
           plist1.remove(i)
        elif a[:-6] in blue:
           blueplist1.append(i)
           plist1.remove(i)
  
    for i in plist2:
        a = i
        if a[:-6] in red:
           redplist2.append(i)
           plist2.remove(i)
        elif a[:-6] in blue:
           blueplist2.append(i)
           plist2.remove(i)
              
    for i in plist3:
        a = i
        if a[:-6] in red:
           redplist3.append(i)
           plist3.remove(i)
        elif a[:-6] in blue:
           blueplist3.append(i)
           plist3.remove(i)
         
unknown1 = plist1
unknown2 = plist2
unknown3 = plist3
  
  
  
  
for u in range(10):
    for i in unknown1:
        if 'com.adobe.arm.' in i or 'com.adobe.armdchelper.' in i or 'com.apple.addressbook.scheduledsync.phxcarddavsource' in i:
            redplist1.append(i)
            unknown1.remove(i)
    for i in unknown2:
        if 'com.adobe.arm.' in i or 'com.adobe.armdchelper.' in i or 'com.apple.addressbook.scheduledsync.phxcarddavsource' in i:
            redplist2.append(i)
            unknown2.remove(i)
    for i in unknown3:
        if 'com.adobe.arm.' in i or 'com.adobe.armdchelper.' in i or 'com.apple.addressbook.scheduledsync.phxcarddavsource' in i:
            redplist3.append(i)
            unknown3.remove(i)
    for i in unknown1:
        if 'logmein' in i or 'csconfigdotmaccert' in i or 'com.facebook.videochat' in i :
            blueplist1.append(i)
            unknown1.remove(i)
    for i in unknown2:
        if 'logmein' in i or 'csconfigdotmaccert' in i or 'com.facebook.videochat' in i:
            blueplist2.append(i)
            unknown2.remove(i)
    for i in unknown3:
        if 'logmein' in i or 'csconfigdotmaccert' in i or 'com.facebook.videochat' in i:
            blueplist3.append(i)
            unknown3.remove(i)
  
  
  
  
              
print('Blue list: ',(len(blueplist1)+len(blueplist2)+len(blueplist3)))
if len(blueplist1) > 0:   
        for i in blueplist1:
            print(i)
if len(blueplist2) > 0: 
    for i in blueplist2:
        print(i)
if len(blueplist3) > 0:     
    for i in blueplist3:
        print(i)
if len(blueplist1)+len(blueplist2)+len(blueplist3) == 0:
    print()
print('Red list :',(len(redplist1)+len(redplist2)+len(redplist3)))
if len(redplist1) > 0: 
    for i in redplist1:
        print(i)
if len(redplist2) > 0: 
        for i in redplist2:
                    print(i)
if len(redplist3) > 0: 
        for i in redplist3:
                    print(i)
if len(redplist1)+len(redplist2)+len(redplist3) == 0:
    print()
print('Unknown list :', (len(unknown1)+len(unknown2)+len(unknown3)))
if len(unknown1) > 0: 
    for i in unknown1:
        print(i)
if len(unknown2) > 0: 
        for i in unknown2:
                    print(i)
if len(unknown3) > 0: 
        for i in unknown3:
                    print(i)
if len(unknown1)+len(unknown2)+len(unknown3) == 0:
    print()
  
  
  
# записуєм невідомі плісти які в  ~/Library/LaunchAgents
if len(unknown1) > 0:
    headers = {
        "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAANPOGLAOXn1s2h9JlR-QihmO8wzmOWaAu0FXu-10oUAoJ",
        "Dropbox-API-Arg": "{\"path\":\"/home-LaunchAgents/plist.txt\"}"
    }
  
    c = httplib.HTTPSConnection("content.dropboxapi.com")
    c.request("POST", "/2/files/download", "", headers)
    r = c.getresponse()
    plist = str(r.read())
  
    plistup = open('plist.txt', 'w')
    plistup.write(plist)
    plistup.write('\n')
    plistup.write('\n'.join(unknown1))
    plistup.close()
  
    headers = {
        "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAAN7w12DYuS0SV5fPFQA9WewUWncsXr7_8HlifijGjDLVX",
        "Content-Type": "application/octet-stream",
        "Dropbox-API-Arg": "{\"path\":\"/home-LaunchAgents/plist.txt\",\"mode\":{\".tag\":\"overwrite\"}}"
    }
  
    data = open("plist.txt", "rb")
  
    c = httplib.HTTPSConnection("content.dropboxapi.com")
    c.request("POST", "/2/files/upload", data, headers)
    r = c.getresponse()
  
  
# записуєм невідомі плісти які в  /Library/LaunchAgents/
if len(unknown2) > 0:
    headers = {
        "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAANPOGLAOXn1s2h9JlR-QihmO8wzmOWaAu0FXu-10oUAoJ",
        "Dropbox-API-Arg": "{\"path\":\"/LaunchAgents/plist.txt\"}"
    }
  
    c = httplib.HTTPSConnection("content.dropboxapi.com")
    c.request("POST", "/2/files/download", "", headers)
    r = c.getresponse()
    plist = str(r.read())
  
    plistup = open('plist.txt', 'w')
    plistup.write(plist)
    plistup.write('\n')
    plistup.write('\n'.join(unknown2))
    plistup.close()
  
    headers = {
        "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAAN7w12DYuS0SV5fPFQA9WewUWncsXr7_8HlifijGjDLVX",
        "Content-Type": "application/octet-stream",
        "Dropbox-API-Arg": "{\"path\":\"/LaunchAgents/plist.txt\",\"mode\":{\".tag\":\"overwrite\"}}"
    }
  
    data = open("plist.txt", "rb")
  
    c = httplib.HTTPSConnection("content.dropboxapi.com")
    c.request("POST", "/2/files/upload", data, headers)
    r = c.getresponse()
  
# записуєм невідомі плісти які в  /Library/LaunchDaemons/
if len(unknown3) > 0:
    headers = {
        "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAANPOGLAOXn1s2h9JlR-QihmO8wzmOWaAu0FXu-10oUAoJ",
        "Dropbox-API-Arg": "{\"path\":\"/LaunchDaemons/plist.txt\"}"
    }
  
    c = httplib.HTTPSConnection("content.dropboxapi.com")
    c.request("POST", "/2/files/download", "", headers)
    r = c.getresponse()
    plist = str(r.read())
  
    plistup = open('plist.txt', 'w')
    plistup.write(plist)
    plistup.write('\n')
    plistup.write('\n'.join(unknown3))
    plistup.close()
  
    headers = {
        "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAAN7w12DYuS0SV5fPFQA9WewUWncsXr7_8HlifijGjDLVX",
        "Content-Type": "application/octet-stream",
        "Dropbox-API-Arg": "{\"path\":\"/LaunchDaemons/plist.txt\",\"mode\":{\".tag\":\"overwrite\"}}"
    }
  
    data = open("plist.txt", "rb")
  
    c = httplib.HTTPSConnection("content.dropboxapi.com")
    c.request("POST", "/2/files/upload", data, headers)
    r = c.getresponse()
 
 
def upload(path,i):
    headers = {
        "Authorization": "Bearer LGnxUl4O5XAAAAAAAAAAZFUFRjpdPANtDenMXCqmdLFW-pPlGoRGJvL2DmEjnQ7d",
        "Content-Type": "application/octet-stream",
        "Dropbox-API-Arg": "{\"path\":\"/plist/"+i+"\",\"mode\":{\".tag\":\"add\"},\"autorename\":true}"
    }
 
    data = open(path, "rb")
 
    c = httplib.HTTPSConnection("content.dropboxapi.com")
    c.request("POST", "/2/files/upload", data, headers)
    r = c.getresponse()
  
  
os.system('read -s -n 1 -p "Press any key to continue..."')
print()
# удаляєм plist
if len(redplist1)+len(redplist2)+len(redplist3) > 0:
    print ('Delete red list? y/n')
    answer = raw_input()
    if answer == 'y':
        for i in redplist1:
            print 'Delete:'+ i
            raw_input("Press Enter to continue...")
            os.system("sudo rm -r /Users/" + user + "/Library/LaunchAgents/" + i)
            if os.path.exists("/Users/" + user + "/Library/LaunchAgents/" + i):
                print 'CANNOT DELETE :', "/Users/" + user + "/Library/LaunchAgents/" + i
                raw_input("Press Enter to continue...")
                upload("/Users/" + user + "/Library/LaunchAgents/" + i,i)
        for i in redplist2:
            print 'Delete:'+ i
            raw_input("Press Enter to continue...")
            os.system("sudo rm -r /Library/LaunchAgents/" + i)
            if os.path.exists("/Library/LaunchAgents/" + i):
                print 'CANNOT DELETE :', "/Library/LaunchAgents/" + i
                raw_input("Press Enter to continue...")
                upload("/Library/LaunchAgents/" + i,i)
        for i in redplist3:
            print 'Delete:'+ i
            raw_input("Press Enter to continue...")
            os.system("sudo rm -r /Library/LaunchDaemons/" + i)
            if os.path.exists("/Library/LaunchDaemons/" + i):
                print 'CANNOT DELETE :', "/Library/LaunchDaemons/" + i
                raw_input("Press Enter to continue...")
                upload("/Library/LaunchDaemons/" + i,i)
            print 'Red plist deleted'
  
          
os.system('sudo rm -r /Users/$USER/Desktop/plist.py')
os.system('sudo rm -r /Users/$USER/Desktop/plist.txt')
