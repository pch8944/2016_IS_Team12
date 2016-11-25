from sqlinjection import SQL
from authentication_session_management import auth_sess

#SQL Injection - target url, post parameter need
sqlinj = SQL()
sqlinj.proc(url,post)

#auth_sess - file name, url need
asm = auth_sess()
asm.inpection(file_name,url)
