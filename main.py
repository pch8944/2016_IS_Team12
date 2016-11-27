from sqlinjection import SQL
from authentication_session_management import auth_sess
from secure_file_uploader import FileUploader

#SQL Injection - target url, post parameter need
sqlinj = SQL()
sqlinj.proc(url,post)

#auth_sess - file name, url need
asm = auth_sess()
asm.inpection(file_name,url)

#File upload
uploader = FileUploader()
# 파일을 업로드 할 url 설정 (여기서는 local server) , 업로드 할 파일 설정
url = "http://127.0.0.1:/upload"
file_name = "test.txt"
# 파일 업로드
uploader.upload(file_name, url)
# white list 확인 , hite list 추가(확장자 log 파일을 화이트리스트에 추가)
uploader.print_whitelist()
uploader.add_whitelist('log')
uploader.print_whitelist()
