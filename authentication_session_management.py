import re
import urllib2
import webbrowser
from bs4 import BeautifulSoup

class auth_sess:
    # file open
    def inspection(self, file_name, edit_url):
        # target = open("test.php", 'r')
        target = open(file_name, 'r')
        content = target.read()

        # get url
        # edit_url = input("url for modification : ")
        # edit_url = "http://www.naver.com"

        if edit_url.find('http') == -1:
            edit_url = "http://" + edit_url

        # cookie inspection
        f_cookie = re.compile('cookie.*;')
        result = f_cookie.findall(content)

        str1 = "".join(result)

        index = 0
        cookie_point = 0
        while cookie_point >= 0:
            cookie_point = str1.find('cookie', cookie_point)
            # print(cookie_point)
            if cookie_point == -1:
                break
            key1 = str1.find('\"', cookie_point)
            if key1 == -1:
                key1 = str1.find('\'', cookie_point)
            key2 = str1.find('\"', key1+1)
            if key2 == -1:
               key1 = str1.find('\'', cookie_point)

            print "cookie " + str1[key1:key2+1] + " is can be attacked by cookie injection"
            print "vulnerable code: " + result[index]
            cookie_point += 1
            index += 1


        # url jumping inspection (have to know board URL)

        # soup = BeautifulSoup(urllib.request.urlopen('http://kupa.korea.ac.kr/btbkplus/commu/notice3.do?mode=edit&articleNo=22559&article.offset=0&articleLimit=10').read(), "lxml")
        # editData = soup.find_all('div', {'class': "login"})
        # soup = BeautifulSoup(content, "lxml")
        # webbrowser.open_new("http://kupa.korea.ac.kr/btbkplus/etc/login.do")

        soup = BeautifulSoup(urllib2.urlopen(edit_url))
        text_area = soup.find_all('textarea')
        edit_area = soup.find_all('iframe')

        # print(text_area)
        # print(edit_area)

        if len(text_area)!=0 or len(edit_area)!=0:
            print("This website have url jumping threats")

        # time out inspection (have to detect function file)
        f_timeout = re.compile('timeout ?=')
        result_t =  f_timeout.findall(content.lower())

        # print(result_t)

        if len(result_t) == 0:
            print("Timeout function is not implemented in this web page")

# call = auth_sess()
# call.inspection("test.php", "www.naver.com")
