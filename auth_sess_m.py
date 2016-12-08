import os
import re
import urllib2
from bs4 import BeautifulSoup

class auth_sess:
    def inspection(self, folder_name, file_name, edit_url):
        # result file open
        f_result = open('result.txt', 'w')

        # edit url to right format
        if edit_url.find('http') == -1:
            edit_url = "http://" + edit_url

        # cookie inspection
        f_result.write("#1. Cookie inspection\n")

        # search all files in selected folder
        for filename in file_name:
            target = open(folder_name + "/" + filename, "r")
            content = target.read()

            # find cookie declaration with regular experssion
            f_cookie = re.compile('.*cookie\(.*;')
            result = f_cookie.findall(content)

            str1 = "".join(result)

            index = 0
            cookie_point = 0
            while cookie_point >= 0:
                cookie_point = str1.find('cookie', cookie_point)
                if cookie_point == -1:
                    break
                key1 = str1.find('\"', cookie_point)
                if key1 == -1:
                    key1 = str1.find('\'', cookie_point)
                key2 = str1.find('\"', key1+1)
                if key2 == -1:
                   key2 = str1.find('\'', key1+1)

                f_result.write("cookie " + str1[key1:key2+1] + " is can be attacked by cookie injection\n")
                f_result.write("vulnerable code: " + result[index].lstrip() + "\n")
                cookie_point += 1
                index += 1
            target.close()


        # url jumping inspection (have to know board URL)
        f_result.write("\n#2. URL jumping inspection\n")

        # parsing selected web page with beautifulsoup
        soup = BeautifulSoup(urllib2.urlopen(edit_url), "html.parser")
        text_area = soup.find_all('textarea')
        edit_area = soup.find_all('iframe')

        if len(text_area)==0 and len(edit_area)==0:
            f_result.write("This web site have url jumping vulnerability\n")
        else:
            f_result.write("This web site have no url jumping vulnerability\n")

        # time out inspection (have to detect function file)
        f_result.write("\n#3. Timeout function inspection\n")

        # If there exist one timeout function then that site is secure
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
            f_result.write("Timeout function is not implemented in this web site\n")
        else:
            f_result.write("Timeout function is implemented in this web site\n")

        f_result.close()
