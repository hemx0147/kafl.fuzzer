import os   # access shell environment
import subprocess
from tdvf_module import *


GHIDRA_BIN = os.environ['GHIDRA_ROOT'] + '/support/analyzeHeadless'
PROJ_DIR = os.environ['KAFL_WORKDIR'] + '/traces/ghidra'
PROJ_NAME = 'cov_analysis'
target = os.environ['TDVF_ROOT'] + '/Build/IntelTdx/DEBUG_GCC5/X64/SecMain.debug'
baseaddr = '0xfffcc000'
jfile = os.environ['BKC_ROOT'] + '/tdvf-modules.json'


# param = json file
mt = TdvfModuleTable()
mt.read_from_file(jfile)

def ghidra_import_targets(targets:dict, proj_dir:str, proj_name:str):
    '''load a set of target binaries at an offset into the ghidra project'''

    for target, address in targets.items():
        # command line to execute
        args = [GHIDRA_BIN, proj_dir, proj_name, '-import', target, '-overwrite', '-loader', 'ElfLoader', '-loader-imagebase', baseaddr]
        completed_proc = subprocess.run(args, capture_output=True, encoding='utf-8')
        print(completed_proc.stdout)
        print(completed_proc.stderr)