import os   # access shell environment
import subprocess
from tdvf_module import *
import argparse


# GHIDRA_BIN = os.environ['GHIDRA_ROOT'] + '/support/analyzeHeadless'
# PROJ_DIR = os.environ['KAFL_WORKDIR'] + '/traces/ghidra'
# PROJ_NAME = 'cov_analysis'
# target = os.environ['TDVF_ROOT'] + '/Build/IntelTdx/DEBUG_GCC5/X64/SecMain.debug'
# baseaddr = '0xfffcc000'
# jfile = os.environ['BKC_ROOT'] + '/tdvf-modules.json'

# def ghidra_import_targets(targets:dict, proj_dir:str, proj_name:str):
#     '''load a set of target binaries at an offset into the ghidra project'''
#     for target, address in targets.items():
#         # command line to execute
#         args = [GHIDRA_BIN, proj_dir, proj_name, '-import', target, '-overwrite', '-loader', 'ElfLoader', '-loader-imagebase', baseaddr]
#         completed_proc = subprocess.run(args, capture_output=True, encoding='utf-8')
#         print(completed_proc.stdout)
#         print(completed_proc.stderr)

def get_targets_from_file(file_path:str):
    if file_path.endswith('.json'):
        # file contains list of TdvfModule objects in json format
        mt = TdvfModuleTable()
        mt.read_from_file(file_path)
        targets = dict((module.d_path, module.img_base) for module in mt.modules.values())
    else:
        # file line format: "<binary-path> <base-address>"
        with open(file_path, 'r') as f:
            lines = f.readlines().strip()
        targets = dict(map(lambda s: tuple(s.split(' ')), lines))
    return targets

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise NotADirectoryError(path)

def file_path(path):
    if os.path.isfile(path):
        return path
    else:
        raise FileNotFoundError(path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Import binaries into Ghidra for further analysis.'
    )

    parser.add_argument(
        'workdir',
        type=dir_path,
        help='Path to the kAFL working directory'
    )

    parser.add_argument(
        'target',
        type=file_path,
        help='Path to the target ELF binary, or a path to a file specifying target binaries and base addresses for loading into Ghidra.'
    )

    parser.add_argument(
        'address',
        metavar='ADDRESS',
        type=str,
        nargs='?',
        help='The base address where the target image should be loaded to. If this option is omitted, TARGET will be treated as a path to a target specification file.'
    )

    args = parser.parse_args()

    workdir = args.workdir
    file_path = args.target
    if args.address:
        address = args.address
        targets = {file_path: address}
    else:
        targets = get_targets_from_file(file_path)

    for binary, address in targets.items():
        print(f'ghidra load {binary} @ {address}')