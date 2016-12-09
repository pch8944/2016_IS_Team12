import os
from sqlinjection import SQL
from auth_sess_m import auth_sess
from xss2 import Xss
from xss2 import execxss
from secure_file_uploader import FileUploader

def f_search(f_name):
    filenames = os.listdir(f_name)
    if not os.path.isdir(f_name):
        print("Error: cannot find directory")
        return 0
    else:
        return filenames

#folder input
f_name = raw_input("Folder directory (ex: C:/test): ")
#f_name = "D:/2016_IS_Team12-master/Termproject"
filenames = f_search(f_name)
#target php input
phpfile = raw_input("Path of the target php that contains parameters' information: ")
#phpfile = "site1.php"

#url input
url = raw_input("URL : ")
#url = "http://wargame.kr:8080/SimpleBoard/read.php"
xss_url = raw_input("Xss test URL (ex: http://www.google.com/): ")
#xss_url = "https://xss-game.appspot.com/level1/frame"
upload_url = raw_input("Upload URL (ex: http://127.0.0.1:/upload): ")
#upload_url = "http://127.0.0.1:/upload"
mod_url = raw_input("Modify screen's URL (ex: http://kupa.korea.ac.kr/notice3.do?mode=edit&articleNo=22559: ")
#mod_url = "http://kupa.korea.ac.kr/btbkplus/commu/notice3.do?mode=edit&articleNo=35190&article.offset=0&articleLimit=10 "

#SQL Injection - target url, post parameter need
sqlinj = SQL()
geturl = sqlinj.fileopen(phpfile)
geturl = url + geturl
sqlinj.proc(geturl,phpfile)

#Xss test - target url
xss = execxss()
xss.run(xss_url)

#auth_sess - folder name, url need
asm = auth_sess()
if len(filenames) != 0:
    asm.inspection(f_name, filenames, mod_url)
    
#File upload
uploader = FileUploader()
# set upfile
file_name = "test.php"
# upload
uploader.upload(file_name, upload_url)
# white list check
uploader.print_whitelist()
