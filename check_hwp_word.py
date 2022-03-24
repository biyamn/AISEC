# check_HWP_WORD.py
import os
import struct 
import shutil
import olefile

path = 'NOT_PE_OLE\\'

lst = []
dirs = os.listdir(path)
for name in dirs:
    lst.append(name)
print('총 파일 개수: ', len(lst))


hwp = []
word = []

for name in dirs:
    fname = os.path.join(path, name)
    
    ole = olefile.OleFileIO(fname)
    fname = os.path.join(path, name)
    if ole.exists('WordDocument') == True:
        ole.close()
        shutil.move(fname, 'NOT_PE_OLE_word')
        word.append(name)

    elif ole.exists('FileHeader'):
        # ole.close()
        fh = ole.openstream('FileHeader')
        data = fh.read()
        if data[0:3] == b'HWP':
            ole.close()
            shutil.move(fname, 'NOT_PE_OLE_hwp')
            hwp.append(name)
    

   
print("hwp파일 개수: ", len(hwp))
print("word파일 개수: ", len(word))