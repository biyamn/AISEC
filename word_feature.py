from oletools.olevba import VBA_Parser
import pefile
import array
import math
import os
import pandas as pd
from capstone import *
lst = []
for fname in os.listdir('NOT_PE_OLE_word'):
    lst.append(fname)


lst_name = []
for fname in os.listdir('NOT_PE_OLE_word'):
    path = 'NOT_PE_OLE_word'
    fpath = os.path.join(path, fname)
    vbaparser = VBA_Parser(fpath)
    if vbaparser.detect_vba_macros():
        print(fname, 'is macro')
        lst_name.append(1)

    else:  
        print(fname, 'is not macro')
        lst_name.append(0)

df = pd.DataFrame({'id':lst, 'macro': lst_name})
print(df)
df.to_csv("word_macro_feature_please.csv", index=False)