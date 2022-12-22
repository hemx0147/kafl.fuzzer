import os   # access shell environment
import sys  # print on stderr
import subprocess
from tdvf_module import *
import argparse

def get_env_var(var_name:str):
    try:
        var_value = os.environ[var_name]
    except Exception as e:
        print(f"Could not find \${var_name}. Missing 'make env'?", file=sys.stderr)
        exit(-1)
    return var_value

def ghidra_import_targets(proj_dir:str, proj_name:str, ghidra_bin:str, targets:dict):
    '''load a set of target binaries at an offset into the ghidra project and return process stdout & stderr'''
    num_targets = len(targets)
    for i, (target, address) in enumerate(targets.items()):
        # command line to execute
        print(f'ghidra import {target} @ {address} to {proj_dir}/{proj_name}.gpr')
        print(f'completed {i}/{num_targets}')
        args = [ghidra_bin, proj_dir, proj_name, '-import', target, '-overwrite', '-loader', 'ElfLoader', '-loader-imagebase', address]
        completed_proc = subprocess.run(args, capture_output=True, encoding='utf-8')
        print(completed_proc.stdout)
    print(f'completed {num_targets}/{num_targets}')

def get_targets_from_file(file_path:str):
    if file_path.endswith('.json'):
        # file contains list of TdvfModule objects in json format
        mt = TdvfModuleTable()
        mt.read_from_file(file_path)
        targets = dict((module.d_path, str(module.img_base)) for module in mt.modules.values())
    else:
        # file line format: "<binary-path> <base-address>"
        with open(file_path, 'r') as f:
            lines = list(line.strip() for line in f.readlines())
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

    # assert that we are within kAFL environment & ghidra binary exists
    get_env_var('KAFL_ROOT')
    ghidra_root = get_env_var('GHIDRA_ROOT')
    ghidra_bin = ghidra_root + '/support/analyzeHeadless'
    assert os.path.isfile(ghidra_bin), "Could not find Ghidra headless binary"

    args = parser.parse_args()

    workdir = args.workdir
    target_path = args.target
    if args.address:
        address = args.address
        targets = {target_path: address}
    else:
        targets = get_targets_from_file(target_path)

    proj_dir = workdir + '/traces/ghidra'
    proj_name = 'cov_analysis'
    # print(targets)
    ghidra_import_targets(proj_dir, proj_name, ghidra_bin, targets)
