from sqlinjection import SQL
from authentication_session_management import auth_sess
from secure_file_uploader import FileUploader
from xss2 import xss
from xss2 import execxss

def f_search(f_name):
    filenames = os.listdir(f_name)
    if not os.path.isdir(f_name):
        print("Error: cannot find directory")
        return 0
    else:
        return filenames

#folder input
f_name = raw_input("Folder directory (ex: C:/test): ")   
filenames = f_search(f_name)
#target php input
phpfile = raw_input("Path of the target php that contains parameters' information: ")

#url input
url = raw_input("URL : ")
xss_url = raw_input("Xss test URL (ex: http://www.google.com/): ")
upload_url = raw_input("Upload URL (ex: http://127.0.0.1:/upload): ")
mod_url = raw_input("Modify screen's URL (ex: http://kupa.korea.ac.kr/notice3.do?mode=edit&articleNo=22559: ")

#SQL Injection - target url, post parameter need
sqlinj = SQL()
geturl = sqlinj.fileopen(path)
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
# 업로드 할 파일 설정
file_name = "test.php"
# 파일 업로드
uploader.upload(file_name, upload_url)
# white list 확인
uploader.print_whitelist()
