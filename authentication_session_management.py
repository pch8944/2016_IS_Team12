import os
import re
import urllib2
import webbrowser
from bs4 import BeautifulSoup

class auth_sess:
    #folder search
    def f_search(self, f_name):
        filenames = os.listdir(f_name)
        if not os.path.isdir(f_name):
            print("Error: cannot find directory")
            return 0
        else:
            return filenames

    # file open
    def inspection(self, folder_name, file_name, edit_url):
        # target = open("test.php", 'r')

        # get url
        # edit_url = input("url for modification : ")
        # edit_url = "http://www.naver.com"

        if edit_url.find('http') == -1:
            edit_url = "http://" + edit_url

        # cookie inspection
        print("#1. Cookie inspection")

        for filename in file_name:
            target = open(folder_name + "/" + filename, "r")
            content = target.read()

            f_cookie = re.compile('.*cookie\(.*;')
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
                   key2 = str1.find('\'', key1+1)

                print "cookie " + str1[key1:key2+1] + " is can be attacked by cookie injection"
                print "vulnerable code: " + result[index].lstrip()
                cookie_point += 1
                index += 1
            target.close()


        # url jumping inspection (have to know board URL)
        print("\n#2. URL jumping inspection")

        # soup = BeautifulSoup(urllib.request.urlopen('http://kupa.korea.ac.kr/btbkplus/commu/notice3.do?mode=edit&articleNo=22559&article.offset=0&articleLimit=10').read(), "lxml")
        # editData = soup.find_all('div', {'class': "login"})
        # soup = BeautifulSoup(content, "lxml")
        # webbrowser.open_new("http://kupa.korea.ac.kr/btbkplus/etc/login.do")

        soup = BeautifulSoup(urllib2.urlopen(edit_url), "html.parser")
        text_area = soup.find_all('textarea')
        edit_area = soup.find_all('iframe')

        # print(text_area)
        # print(edit_area)

        if len(text_area)!=0 or len(edit_area)!=0:
            print("This web site have url jumping vulnerability")
        else:
            print("This web site have no url jumping vulnerability")


        # time out inspection (have to detect function file)
        print("\n#3. Timeout function inspection")

        no_timeout = 0
        for filename in file_name:
            target = open(folder_name + "/" + filename, "r")
            content = target.read()

            f_timeout = re.compile('timeout ?=')
            result_t =  f_timeout.findall(content.lower())

            if len(result_t) != 0:
                no_timeout = 1
            target.close()

        if no_timeout != 1:
            print("Timeout function is not implemented in this web site")
        else:
            print("Timeout function is implemented in this web site")

# f_name = raw_input()
# asm = auth_sess()
# filenames = asm.f_search(f_name)

# if len(filenames) != 0:
    # asm.inspection(f_name, filenames, "www.naver.com")
