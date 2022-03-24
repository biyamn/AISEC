import subprocess
import pathlib
import unicorn
import os
import sys


COMMAND = "C:\\Users\\biyam\\Desktop\\die_win64_portable_3.02\\die_win64_portable\\diec.exe"
DIRPATH = pathlib.Path("./2_packing")

count = 0


def output_parser(filename, data):
    global count
    if " mpress" in data.decode().lower() or "aspack" in data.decode().lower()\
            or "fsg" in data.decode().lower() or "mew" in data.decode().lower()\
            or "petite" in data.decode().lower() or "yzpack" in data.decode().lower():
        try:
            print(str(filename) + "//추출시작")
            print(data.decode())
            try:
                output = subprocess.check_output(["unipacker", filename, "-d", "./unipacker"], timeout=300)
                os.remove(filename)
            except subprocess.TimeoutExpired:
                print(filename, file=f)
                return False
            except Exception as e:
                print(e)
                return False
            print(output)
            count += 1
            return True
        except unicorn.unicorn.UcError:
            return False
        except Exception as e:
            print(e)
            return False

    elif "upx" in data.decode().lower() :
        try:
            print(data.decode())
            try:
                output = subprocess.check_output(["unipacker", filename, "-d", "./unipacker_not"], timeout=100)
                os.remove(filename)
            except subprocess.TimeoutExpired:
                return False

            print(output)
            count += 1
            return True
        except unicorn.unicorn.UcError:
            return False


def main():

    print("start main")
    cnt = 0
    glob_path = DIRPATH.glob("*")
    glob_size = len(list(glob_path))

    print(list(glob_path), DIRPATH.absolute())
    for _path in DIRPATH.glob("*"):
        cnt += 1
        if _path.is_dir():
            continue

        output = subprocess.check_output([COMMAND, str(_path)])
        if output_parser(_path, output):
            print(f"{_path.name} {count}/{glob_size}")
        else:
            continue


if __name__ == "__main__":
    print("start")
    main()