# checkELF.py
# ELF파일인지 구별하는 코드

import os
import struct 
import shutil

path = 'elf_test_in'
# 그 파일 안에 있는 모든 파일명을 읽어들임
dirs = os.listdir(path)

# 폴더이름/파일명 이렇게 경로를 만들기 위해
for name in dirs:
    fname = os.path.join(path, name)
    # 바이트로 경로의 파일을 오픈한다
    fp = open(fname, 'rb') # read byte
    buf = fp.read(10) # 처음부터 10바이트를 읽음
    fp.close()

    # PE파일인지 판단할거임. MX와 PE 글자를 탐지하는 코드
    # 32비트인지 64비트인지는 무시함.
    v = buf[:4]
    if v == b'\x7f\x45\x4c\x46':
        print(fname)
        shutil.move(fname, 'elf_test_out')
            

