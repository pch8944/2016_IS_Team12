import sys
import urllib2
from urllib import urlencode
from cookielib import CookieJar
from lxml.html import fromstring

class Xss(object):
    def __init__(self, url, payloads):
        #payloads
        self.comp = payloads
        #testing url
        self.url = url
        #list for get, post attack points
        self.get = []
        self.post = []
        #for parsing url page
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(CookieJar()))
        self.opener.addheaders = [("Content-type", "application/x-www-form-urlencoded"),
                                 ('User-Agent',
                                  'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.0.14) Gecko/2009082706 Firefox/3.0.14'),
                                  ("Accept", "text/plain")]
        # # of vectors
        self.vectors = 0
        # # of succeed attacks
        self.success = 0

    #parsing url page, and generate xss attack vectors
    def parse(self, xsscript):
        #parsing phase
        links = {}
        #open url and make it as string, and make their link as absolute
        resp = self.opener.open(self.url).read()
        doc = fromstring(resp)
        doc.make_links_absolute(self.url)
        #
        for (el, attr, link, pos) in doc.iterlinks():
            #split links using ?: using parameter
            href = link.split("?")
            #if there are ?
            if len(href) == 2:
                #split it into action and fields
                action, fields = link.split("?")
                #make action list - no duplicate
                if action not in links:
                    links[action] = {}
                #if there are &(more than 1 parameters)
                for field in fields.split("&"):
                    try:
                        #make list of parameter name and values
                        name, value = field.split("=")
                        links[action][name] = value
                    except:
                        #ignore other
                        pass

        #making xss attack from links
        for action in links:
            for field, value in links[action].iteritems():
                #for all value
                params = dict(links[action])
                #change value as xsscript
                params[field] = xsscript
                #make request of it
                request = action + "?" + urlencode(params)
                #appent it to self.get
                self.get.append(request)

        #making xss attack from forms
        for form in doc.forms:
            for field, value in form.form_values():
                #for all value
                params = dict(form.form_values())
                #change value as xsscript
                params[field] = xsscript
                #extract action from form
                action = form.action
                #if no action, make it empty
                if action == None: action = ""
                #make request of it
                request = action + "?" + urlencode(params)
                #determine method-get? post?
                method = form.method.lower()
                if method == "post":
                    #if post, append it to self.post
                    self.post.append((action, urlencode(params)))
                else:
                    #if anothers, treat it as get
                    self.get.append(request)

        #calculate # of vectors for report
        self.vectors = (len(self.get) + len(self.post)) / len(self.comp)

    #try xss attacks from parse()
    def scan(self):
        #for report
        f = open("XSSreport.txt", "w")
        f.write("Scanning " + str(len(self.comp)) + " * " + str(self.vectors) + " vectors\n")

        #try get attacks
        for request in self.get:
            try:
                #from response of xss attack
                resp = self.opener.open(request).read()
                #find exact xss payload from response page
                a = self.print_match(resp, f)
                #if found, write it on report
                if a==1:
                    f.write("GET " + request + "\n")
            except:
                #if error or not found, pass it
                pass
        #try post attacks
        for action, params in self.post:
            try:
                #post request, response
                req = urllib2.Request(action, params)
                response = urllib2.urlopen(req)
                resp = response.read()
                # find exact xss payload from response page
                a = self.print_match(resp, f)
                # if found, write its action and parameters on report
                if a==1:
                    f.write("POST " + action + "\n")
                    f.write("Parameters " + params + "\n")
            except:
                pass

        f.close()
    #exact match
    def print_match(self, resp, f):
        filtered = 0
        #find returns -1 if not found
        for checker in self.comp:
            filtered += resp.find(checker)
        #if all payload is not in response(-1)
        if filtered != -len(self.comp):
            #add success
            self.success += 1
            #return 1 to write report
            return 1
        #else return 0
        return 0

#exec
class execxss:
    def run(self, url):
        #open payloads and make it as list
        fo = open("xsspayloads.txt", "r")
        payloads = fo.read().splitlines()
        fo.close()
        #make Xss obkect
        xss = Xss(url, payloads)
        #make get, post for all payloads
        for script in payloads:
            xss.parse(script)
        #try it
        xss.scan()
        #add # of succeed in report
        f = open("XSSreport.txt", "a")
        f.write("\nSucceed XSS :" + str(xss.success))
        f.close()

# https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#META

#call = execxss()
#call.run("https://xss-game.appspot.com/level1/frame")