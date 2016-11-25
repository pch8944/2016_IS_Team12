import logging
from upload.lib.base import *
log = logging.getLogger(__name__)

import os
import shutil
import cgi

class ProgressFile(file):
    def write(self, *k, **p):
        if hasattr(self, 'callback'):
            self.callback(self, *k, **p)
        return file.write(self, *k,**p)

    def set_callback(self, callback):
        self.callback = callback

def stream(file_object):

    class CustomFieldStorage(cgi.FieldStorage):
        def make_file(self, binary=None):
            self.open_file = file_object
            return self.open_file

    return CustomFieldStorage

class UpController(BaseController):

    def index(self):
        return """
            <html>
            <body>
            <h1>Upload</h1>
            <form action="up" method="post" enctype="multipart/form-data">
            Upload file: <input type="file" name="myfile" /> <br />
                         <input type="submit" name="submit" value="Submit" />
            </form>
            </body>
            </html>
        """

    def upload(self):

        def callback(file, *k, **p):
            log.debug("Logged %s", [file.tell()])

        fp = ProgressFile('somefile', 'wb')
        fp.set_callback(callback)
        custom_field_storage = stream(fp)(
            environ=request.environ,
            strict_parsing=True,
            fp=request.environ['wsgi.input']
        )
        fp.close()
        return 'done'