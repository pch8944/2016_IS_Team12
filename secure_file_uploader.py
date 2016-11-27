#-*- coding: utf-8 -*-
import os
import sys
import uuid
import shutil
import urllib2
import requests

class FileUploader:
    def __init__(self, white_list=None):
        if white_list is None:
            # 기본 화이트 리스트 : 미리 정의된 확장자 txt,doc,hwp,pdf,xls 파일만 업로드 가능
            self.white_list = ['txt','doc','hwp','pdf','xls']
        else:
            # 기본 화이트 리스트를 전달받으면 전달 받은 리스트 사용
            self.white_list.extend(white_list)

    def reset_whitelist(self):
        # 화이트리스트를 모두 삭제
        self.white_list = []

    def add_whitelist(self, white_list):
        # 화이트리스트에 확장자 리스트 추가
        if type(white_list) is str:
            self.white_list.append(white_list)
        elif type(white_list) is list:
            self.white_list.extend(white_list)
        else:
            print "white list shoud be string or list"
            print "ex 1) txt"
            print "ex 2) ['txt','jpg']"

    def print_whitelist(self):
        print self.white_list

    def change_filename(self):
        # 파일 이름을 랜덤하게 변경하여 리턴
        new_string = list(str(uuid.uuid4()).replace('-',''))
        new_string[-4] = '.'

        new_file = ''.join(new_string)

        return new_file

    def check_file(self, file_name):
        # 파일이 존재하는지 확인
        if not os.path.exists(file_name):
            print "File does not exists"
            return False

        # 정상적인 파일이 맞는지 확인
        if not os.path.isfile(file_name):
            print file_name + " is not a file."
            return False

        return True

    def check_suffix(self, file_name):
        # 파일의 확장자 추출
        name, suffix = os.path.splitext(file_name)
        suffix = suffix[1:]

        # 확장자가 화이트리스트에 있는지 확인
        result = suffix in self.white_list

        return result

    def _file_upload(self, file_path, url):
        # 실제 url로 파일을 업로드
        files = {'file': open(file_path, 'rb')}
        r = requests.post(url, files=files)

        #if r.ok: print file_path + ' is uploaded to ' + url

        return r.ok


    def file_upload(self, file_name, new_filename, url):
        # 파일을 새로운 파일이름으로 현재 디렉토리에 복사
        shutil.copy(file_name, new_filename)

        try:
            # 복사한 파일을 url에 업로드
            res = self._file_upload(new_filename, url)
        finally:
            # 복사한 파일 삭제
            os.remove(new_filename)


    def upload(self, file_name, url):
        # 파일명을 절대경로로 변경
        abs_file_name = os.path.abspath(file_name)

        # 업로드 가능한 파일인지 확인
        if not self.check_file(abs_file_name):
            print 'Upload failed. Check your file'
            return

        # 화이트 리스트에 등록된 확장자인지 확인
        if not self.check_suffix(abs_file_name):
            print 'Upload failed. Check your white list'
            return

        # 랜덤하게 파일이름 변경
        new_filename = self.change_filename()

        # 실제 파일 업로드
        self.file_upload(abs_file_name, new_filename, url)
