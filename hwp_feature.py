# Project : Malware_Detect_HWP
# main.py

import olefile
import pandas as pd
import os
import zlib
import struct
import re
import sys


# ---------------------------------------------------
# 폴더 내부의 파일 목록 가져오기
# ---------------------------------------------------
def scan_dir(path):
    ret = []

    p = os.path.abspath(path)  # 절대 경로 확인
    fl = [p]

    while len(fl):
        fname = fl.pop()
        if os.path.isdir(fname):  # 폴더일 때 처리
            for n in os.listdir(fname):
                p = os.path.join(fname, n)  # 상대 경로 확인
                fl.append(p)

        elif os.path.isfile(fname):  # 파일일 때 처리
            ret.append(fname)

    ret.sort()  # 파일 목록 정렬
    return ret


# ---------------------------------------------------
# OLE 피처 추출 함수들
# ---------------------------------------------------
# OLE 파일 크기는 항상 512로 나누어짐
def check_ole_filesize(fname):
    return os.path.getsize(fname) % 512


# PS, EPS 포함 여부
def check_ps_in_hwp(ole):
    for name in ole.listdir():
        path_name = '/'.join(name)

        t = path_name.lower()
        if t[:8] == 'bindata/' and (t[-3:] == '.ps' or t[-4:] == '.eps'):
            return 1

    return 0


def get_dword(buf, off):  # DWORD 읽기
    return struct.unpack('<L', buf[off:off+4])[0]


def get_record(val):  # val : DWORD
    tag_id = val & 0b1111111111
    level = (val & (0b1111111111 << 10)) >> 10
    size = (val & (0b111111111111 << 20)) >> 20
    return tag_id, level, size


# Tag 추적  (NOT EOF: 1, EOF: 0)
def check_eof_tag(ole):
    for name in ole.listdir():
        path_name = '/'.join(name)
        t = path_name.lower()

        if not (t[:9] == 'bodytext/' or t[:7] == 'docinfo'):
            continue

        fh = ole.openstream(path_name)
        data = fh.read()

        try:
            data = zlib.decompress(data, -15)
        except:
            pass

        # HWP Tag 추적하기
        off = 0
        while off < len(data):
            val = get_dword(data, off)
            off += 4

            tag_id, _, size = get_record(val)
            if size == 0xfff:
                size = get_dword(data, off)
                off += 4

            off += size

        if off != len(data):
            return 1

    return 0


# exe 또는 rtf 헤더를 가졌는가?  (1: 존재, 0, 없음)
def check_exe_rtf(ole):
    for name in ole.listdir():
        path_name = '/'.join(name)

        fh = ole.openstream(path_name)
        data = fh.read()

        try:
            data = zlib.decompress(data, -15)
        except:
            pass

        if data[:2] == b'MZ' or data[:4] == b'{\rtf':  # EXE 헤더 or RTF 헤더를 가졌나?
            return 1

    return 0


# 쉘코드 의심 문자가 존재하는가? (1: 존재, 0: 없음)
def check_shellcode(ole):
    shellcodes = [
        b'\x90\x90\x90\x90\x90\x90',
        b'\xe8\x00\x00\x00\x00'
    ]

    for name in ole.listdir():
        path_name = '/'.join(name)

        fh = ole.openstream(path_name)
        data = fh.read()

        try:
            data = zlib.decompress(data, -15)
        except:
            pass

        for sc in shellcodes:
            if data.find(sc) != -1:
                return 1

    return 0


# API 문자열이 존재하는가? (1: 존재, 0: 없음)
def check_api_string(ole):
    api_strings = [
        b'UrlDownloadToFile',
        b'GetTempPath',
        b'GetWindowsDirectory',
        b'GetSystemDirectory',
        b'ShellExecute',
        b'IsBadReadPtr',
        b'IsBadWritePtr',
        b'CreateFile',
        b'CreateHandle',
        b'ReadFile',
        b'WriteFile',
        b'SetFilePointer',
        b'VirtualAlloc',
        b'GetProcAddress',
        b'LoadLibrary',
    ]

    for name in ole.listdir():
        path_name = '/'.join(name)

        fh = ole.openstream(path_name)
        data = fh.read()

        try:
            data = zlib.decompress(data, -15)
        except:
            pass

        for api in api_strings:
            if data.find(api) != -1:
                print(api)
                return 1

    return 0


# 자바스크립트 크기 확인하기
def check_size_javascript(ole):
    for name in ole.listdir():
        path_name = '/'.join(name)
        t = path_name.lower()

        if t == 'scripts/defaultjscript':
            fh = ole.openstream(path_name)
            data = fh.read()

            return len(data)

    return 0


def calc_compress_ratio(buf):
    org_size = len(buf)
    comp_size = len(zlib.compress(buf))

    return float(comp_size)/org_size * 100


# 문단 텍스트의 압축률
def check_ratio_para_text(ole):
    ratio = [100]

    for name in ole.listdir():
        path_name = '/'.join(name)
        t = path_name.lower()

        if t.find('bodytext/section') != 0:
            continue

        fh = ole.openstream(path_name)
        data = fh.read()

        try:
            data = zlib.decompress(data, -15)
        except:
            pass

        # HWP Tag 추적하기
        off = 0
        while off < len(data):
            val = get_dword(data, off)
            off += 4

            tag_id, _, size = get_record(val)
            if size == 0xfff:
                size = get_dword(data, off)
                off += 4

            # PARA Text 압축률 계산
            if tag_id == 0x43:  # PARA Text
                t_data = data[off:off+size]
                ratio.append(calc_compress_ratio(t_data))

            off += size

    return min(ratio)


# 스트림의 압축률
def check_ratio_stream(ole):
    ratio = [100]

    for name in ole.listdir():
        path_name = '/'.join(name)

        fh = ole.openstream(path_name)
        data = fh.read()

        try:
            data = zlib.decompress(data, -15)
        except:
            pass

        ratio.append(calc_compress_ratio(data))

    return min(ratio)


# 압축 > 압축해제 인가? (1: 맞음, 0: 아님)
def compare_compress_size(ole):
    for name in ole.listdir():
        path_name = '/'.join(name)
        t = path_name.lower()

        if t.find('bodytext/') != 0:
            continue

        fh = ole.openstream(path_name)
        data = fh.read()
        comp_size = len(data)

        try:
            data = zlib.decompress(data, -15)
            decomp_size = len(data)
        except:
            decomp_size = 0x8fffffff

        if comp_size > decomp_size:
            return 1

    return 0


# 유효한 스트림명인가? (1:이상한거 있음, 0: 정상)
def check_stream_name(ole):
    sname1 = [
        'PrvText', 'PrvImage', 'FileHeader', 'DocInfo', '\x05HwpSummaryInformation',
        'Scripts/DefaultJScript', 'Scripts/JScriptVersion', 'DocOptions/_LinkDoc'
    ]

    sname2 = [
        re.compile(r'BodyText/Section[0-9]+'),
        re.compile(r'BinData/BIN[0-9A-F]{4}\.[A-Za-z0-9]+'),
    ]

    for name in ole.listdir():
        path_name = '/'.join(name)

        if path_name in sname1:
            # print(path_name, True)
            continue

        for p in sname2:
            if p.search(path_name):
                break
        else:
            # print(path_name, False)
            return 1

        # print(path_name, True)

    # print('_' * 20)

    return 0


# ---------------------------------------------------
# 메인 함수
# ---------------------------------------------------
def main():
    data = []

    flists = scan_dir(sys.argv[1])
    for name in flists:
        if not olefile.isOleFile(name):
            continue

        print(name)
        ole = olefile.OleFileIO(name)

        ole_feature = [
            name,
            check_ole_filesize(name),
            check_ps_in_hwp(ole),
            check_eof_tag(ole),
            check_exe_rtf(ole),
            check_shellcode(ole),
            check_api_string(ole),
            check_size_javascript(ole),
            check_ratio_para_text(ole),
            check_ratio_stream(ole),
            compare_compress_size(ole),
            check_stream_name(ole),
            int(sys.argv[2])  # 악성: 1, 정상, 0
        ]

        ole.close()

        data.append(ole_feature)

    col_name = [
        '파일명', '크기_512_나머지', 'PS_존재여부', 'Tag 추적', 'EXE_RTF',
        '쉘코드_의심', 'API_문자열', '자바스크립트_크기', '문단텍스트_압축률',
        '스트림_압축률', '유효_압축_크기_여부', '스트림명_이상여부',
        '악성여부'
    ]

    df = pd.DataFrame(data, columns=col_name)
    df.to_csv('word.csv', index=False)

    # print(df.iloc[:][['파일명', '스트림명_이상여부']])


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: main.py [path] [0|1]')
    else:
        main()
