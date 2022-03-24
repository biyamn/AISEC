#-*- coding:utf-8 -*-
# subprocess: 파이썬 프로그램 내에서 새로운 프로세스를 스폰하고 
# 여기에 입출력 파이프를 연결하며 리턴코드를 획득할 수 있도록 하는 모듈
import subprocess
import pathlib
import shutil

COMMAND = "C:\\Users\\biyam\\Desktop\\die_win64_portable\\diec.exe"
DIRPATH = pathlib.Path("PE")
_dict = {}
dict_id_packing = {}
packer_list = []
def output_parser(data):
    _list = data.split(b"\n")
    for _ in _list:
        if b"packer:" in _:
            try:
                _dict[_] += 1
                packer_list.append(_)
                    
            except KeyError:
                _dict[_] = 1
                packer_list.append(_)


def main():
    cnt = 0
    # glob: 디렉토리 밑에 있는 파일을 리스트로 리턴
    glob_path = DIRPATH.glob("*")
    glob_size = len(list(glob_path))

    for _path in DIRPATH.glob("*"):
        cnt += 1 
        # is_dir(): 디렉토리가 존재하는가 -> true, false 리턴
        if _path.is_dir():
            continue
        # check_output: 서브프로세스를 실행하고 그 출력 문자열을 리턴한다
        output = subprocess.check_output([COMMAND, str(_path)])
        # 볼 수 있게 파싱
        output_parser(output)
        dict_id_packing[_path] = output
        # f스트링 사용 - cnt, glob_size
        print(f"{cnt}/{glob_size}")

    for key, value in _dict.items():
        print(f"Type: {key}\tCount:{value}")
    print('\n') 
    # print(dict_id_packing)
    # for key, value in dict_id_packing:
    keyList = list(dict_id_packing.keys())
    valueList = list(dict_id_packing.values())

    for i in range (len(keyList)):
        if b"packer:" in valueList[i]:
            print(f"id:{keyList[i]}\nCount:{valueList[i]}\n")
            shutil.move(str(keyList[i]), 'raw')


if __name__ == "__main__":
    main()
