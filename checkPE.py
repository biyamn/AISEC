# check_pe.py
# PE파일인지 구별하는 코드

import os
import struct 
import shutil

path = 'train\\'
# 그 파일 안에 있는 모든 파일명을 읽어들임
dirs = os.listdir(path)

# PE 위치 가져오기
def get_dword(buf, off):
    # 4바이트를 읽는 방법
    # <는 리틀엔디안 방식으로 읽을 거라는 것
    return struct.unpack('<L', buf[off:off+4])[0] # 4바이트를 읽는 방법

# 폴더이름/파일명 이렇게 경로를 만들기 위해
for name in dirs:
    fname = os.path.join(path, name)
    # 바이트로 경로의 파일을 오픈한다
    fp = open(fname, 'rb') # read byte
    # b'MZ\x90\x00\x03\x00\x00\'이런식으로 읽는다.
    buf = fp.read(10240) # 처음부터 10240바이트를 읽음.
    fp.close()

    # PE파일인지 판단할거임. MX와 PE 글자를 탐지하는 코드
    # 32비트인지 64비트인지는 무시함.
    if buf[:2] == b'MZ':
        # 0x3c 떨어진 곳의 주소를 off에 넣음
        off = get_dword(buf, 0x3c)
        if buf[off:off+2] == b'PE':
            print(fname)
            # PE라는 파일을 따로 만들 거임. 
            shutil.move(fname, 'PE')
            

