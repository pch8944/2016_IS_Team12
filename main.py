from sqlinjection import SQL
from authentication_session_management import auth_sess
from secure_file_uploader import FileUploader

def f_search(f_name):
    filenames = os.listdir(f_name)
    if not os.path.isdir(f_name):
        print("Error: cannot find directory")
        return 0
    else:
        return filenames

#folder input
f_name = raw_input()   
filenames = f_search(f_name)

#SQL Injection - target url, post parameter need
sqlinj = SQL()
sqlinj.proc(url,post)

#auth_sess - folder name, url need
asm = auth_sess()
if len(filenames) != 0:
    asm.inspection(f_name, filenames, "www.naver.com")
    
#File upload
uploader = FileUploader()
# 파일을 업로드 할 url 설정 (여기서는 local server) , 업로드 할 파일 설정
url = "http://127.0.0.1:/upload"
file_name = "test.txt"
# 파일 업로드
uploader.upload(file_name, url)
# white list 확인
uploader.print_whitelist()
