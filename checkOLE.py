import olefile
import struct
import zlib
import os
import shutil

path = 'NOT_PE'
# 그 파일 안에 있는 모든 파일명을 읽어들임
dirs = os.listdir(path)

# 폴더이름/파일명 이렇게 경로를 만들기 위해
for name in dirs:
    fname = os.path.join(path, name)
    if olefile.isOleFile(fname) == False:
        shutil.move(fname, 'NOT_PE_notOLE')
