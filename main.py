# pe2csv.py
# 멀티프로세싱을 하면 최소 2배 이상 빠르게 처리할 수 있다. 

import pefile
import array
import math
import os
import pandas as pd
from capstone import *


def get_opcode(data):
    opcode = []

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(data, 0x1000):
        opcode.append(f"{i.mnemonic}")

    # print(set(opcode))
    return opcode

def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy


def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                   resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res

def extract_infos(fpath, is_malware):
    res = {}

    # res['name']

    pe = pefile.PE(fpath)
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # Sections
    res['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x: x.get_entropy(), pe.sections))
    res['SectionsMeanEntropy'] = sum(entropy) / float(len(entropy))
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
    res['SectionsMeanRawsize'] = sum(raw_sizes) / float(len(raw_sizes))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
    res['SectionsMeanVirtualsize'] = sum(virtual_sizes) / float(len(virtual_sizes))
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    # 섹션 이름 존재 여부 확인
    none_section_count = len(pe.sections)  # 전체 섹션 수

    sec_names = []
    for sec in pe.sections:
        sec_name = sec.Name.decode('utf-8').replace('\x00', '')
        sec_names.append(sec_name)

    for chk_sec in [
        '.rsrc', '.data', '.text', '.bss', '.crt', '.rdata', '.reloc', '.idata',
        'data', '.edata', '.sdata', '.ndata', '.itext', '.tls', '.crt', 'bss',
        'code', '.code'
        ]:
        if chk_sec in sec_names:
            res[chk_sec] = 1  # 섹션 존재
            none_section_count -= 1
        else:
            res[chk_sec] = 0  # 섹션 없음

    res['section_not_selected'] = none_section_count  # 잔여 섹션 수

    # Imports
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = len(list(filter(lambda x: x.name is None, imports)))
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    # Exports
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        res['ExportNb'] = 0

    # Resources
    resources = get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources) > 0:
        # [x[0] for x in resources]
        entropy = list(map(lambda x: x[0], resources))
        res['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        # [x[1] for x in resources]
        sizes = list(map(lambda x: x[1], resources))
        res['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    # 리소스 체크
    resource_ids = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries]
    res['RT_STRING'] = resource_ids.count(6)
    res['RT_DIALOG'] = resource_ids.count(5)
    res['RT_GROUP_ICON'] = resource_ids.count(14)
    res['RT_VERSION'] = resource_ids.count(16)
    res['RT_BITMAP'] = resource_ids.count(2)
    res['RT_RCDATA'] = resource_ids.count(10)
    res['RT_ICON'] = resource_ids.count(3)
    res['RT_GROUP_CURSOR'] = resource_ids.count(12)

    # Load configuration size
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0

    # 1-gram 처리
    data = open(fpath, 'rb').read()
    gram = [0] * 256
    for c in data:
        gram[c] += 1

    for idx, value in enumerate(gram):
        res[f'byte_{idx}'] = value

    # 기계어 OPcode 추출
    check_opcode = ['movzx', 'in', 'jl', 'or', 'movq', 'into', 'fsubr', 'stmxcsr', 'psrlq', 'fiadd', 'int3', 'fsubp',
                    'fidiv', 'neg', 'jmp', 'xacquire xchg', 'fsub', 'cmp', 'movapd', 'imul', 'lea', 'xchg', 'faddp',
                    'clc', 'ficom', 'sar', 'lodsb', 'jnp', 'int1', 'setb', 'movsw', 'ja', 'rep stosd', 'stosb', 'fld',
                    'salc', 'sete', 'aam', 'pushal', 'psllq', 'jp', 'lock xadd', 'jg', 'jle', 'test', 'fdiv', 'call',
                    'fstp', 'cmpnlepd', 'ret', 'inc', 'rol', 'mul', 'rep movsd', 'insb', 'psubd', 'movsd', 'fadd',
                    'jns', 'setge', 'push', 'setne', 'fnstcw', 'fmul', 'add', 'shl', 'addsd', 'out', 'fst', 'mov',
                    'shr', 'seto', 'arpl', 'fild', 'movsx', 'pop', 'movsb', 'jbe', 'stosd', 'fnstsw', 'seta', 'andpd',
                    'fldz', 'movups', 'xor', 'lahf', 'sbb', 'idiv', 'adc', 'sahf', 'scasb', 'fdivp', 'and', 'setg',
                    'ucomisd', 'div', 'jne', 'jb', 'js', 'not', 'jae', 'cdq', 'setl', 'leave', 'nop', 'movd', 'jge',
                    'je', 'ror', 'cmpsb', 'dec', 'fcomp', 'sub']
    data = pe.sections[0].get_data()
    opcode_lists = get_opcode(data)

    for op in check_opcode:
        res[op] = opcode_lists.count(op)

    # IAT
    check_apis = [
        '_iob', 'send', 'connect','recv', '_initterm_e', 'free', '_acmdln', '_unlock', 
        'gethostbyaddr', '__dllonexit', '_lock', 'lockresource', 'socket', 'gethostbyname', 'select'
    ]

    pe_iat = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                pe_iat.append(imp.name.decode('utf-8').lower())
    except:
        pass

    for api in check_apis:
        for pe_api in pe_iat:
            if pe_api.find(api) == 0 and len(api) + 1 == len(pe_api) and pe_api[-1] in ['a', 'w']:
                res['api_' + api] = 1
                break
        else:  # end for
            res['api_' + api] = 0

    # TLS
    try:
        _tls = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']].VirtualAddress
        if _tls:
            res['tls_exist'] = 1
        else:
            res['tls_exist'] = 0
    except:
        res['tls_exist'] = 0

    # Rich Header
    rh = pe.parse_rich_header()
    rh_data = [0] * 20

    try:
        for i, val in enumerate(rh.get('values')):
            rh_data[i] = val
    except:
        pass

    for i, val in enumerate(rh_data):
        res[f'rich_{i}'] = val

    # 악성 여부
    res['malware'] = is_malware

    return res


def get_file_info(df, fname):
    is_malware = df.loc[fname.lower()].values[0]
    x = extract_infos(f'PE\\{fname}', is_malware)
    return x


if __name__ == '__main__':
    # 정답지 읽기
    colnames = ['id', 'class']
    df = pd.read_csv('train_answer.csv', names=colnames, header=None)
    df = df.set_index('id')

    # CSV 헤더 만들기
    fp = open('pe.csv', 'wt', encoding='utf-8')

    # 헤더만 생성 (임시 파일 입력)
    x = get_file_info(df, '00a2e51f59b2b6464a9131c37e712b3f')
    print(x)
    print(len(x))

    header = ','.join(x.keys())
    fp.write(header + '\n')

    # 실제 PE 특징 추출
    for fname in os.listdir('PE_test'):
        try:
            print(fname)
            x = get_file_info(df, fname)

            data = ','.join([str(t) for t in x.values()])
            fp.writelines(data + '\n')
        except:
            # import traceback
            # print(traceback.format_exc())
            pass

    fp.close()
