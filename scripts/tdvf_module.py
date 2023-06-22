# Some helper classes to deal with TDVF modules

import json
import os.path
from typing import List, Tuple, Dict
import pefile
from collections import OrderedDict


class Address:
    '''A helper class for dealing with int-str address conversion'''

    # set max. address size to 64-bit 
    __ADDR_MAX_VAL = 2 ** 64 - 1

    def __init__(self, value):
        '''initialize an Address object with given value.
        value can be anything that can be converted to int.
        '''
        if isinstance(value, str):
            value = int(value, 16)
        value = int(value)
        assert value is not None, 'no address value given'
        assert isinstance(value, int), 'address value must be an int'
        assert value >= 0, 'address value must be positive'
        assert value <= self.__ADDR_MAX_VAL, f'address value must be smaller or equal to {self.__ADDR_MAX_VAL}'
        self.__value = value
        self.__address = hex(value)

    def __str__(self) -> str:
        return self.__address

    def __int__(self) -> int:
        return self.__value

    def __add__(self, other):
        return Address(int(self) + int(other))

    def __lt__(self, other):
        return self.__value < other.__value

    def __gt__(self, other):
        return self.__value > other.__value

    def __eq__(self, other):
        return self.__value == other.__value


class TdvfModule:
    '''A TDVF module object consisting of module name, image base address, info about the .text section, and the paths of the module's .debug and .efi files'''

    def __init__(self, name:str='', img_base:int=0, t_start:int=0, t_end:int=0, t_size:int=0, bin_path:str=None, dbg_path:str=None, efi_path:str=None):
        self.name = name
        self.img_base = img_base
        self.t_start = t_start
        self.t_end = t_end
        self.t_size = t_size
        self.bin_path = bin_path
        self.dbg_path = dbg_path
        self.efi_path = efi_path
    
    def __str__(self) -> str:
        return str(self.to_dict())

    # define compare-methods so class instances can be easily sorted
    # comparisons are done via start of .text section
    def __lt__(self, other): 
        return self.t_start < other.t_start or (self.t_start == other.t_start and self.t_end < other.t_end)

    def __gt__(self, other):
        return self.t_start > other.t_start or (self.t_start == other.t_start and self.t_end > other.t_end)

    def __eq__(self, other):
        return self.t_start == other.t_start and self.t_end == other.t_end

    @property
    def name(self) -> str:
        return self.__name

    @name.setter
    def name(self, name:str):
        self.__name = name

    @property
    def img_base(self) -> int:
        return self.__img_base

    @img_base.setter
    def img_base(self, addr:int):
        self.__img_base = Address(addr)

    @property
    def t_start(self) -> int:
        return self.__t_start

    @t_start.setter
    def t_start(self, addr:int):
        self.__t_start = Address(addr)

    @property
    def t_end(self) -> int:
        return self.__t_end

    @t_end.setter
    def t_end(self, addr:int):
        self.__t_end = Address(addr)

    @property
    def t_size(self) -> int:
        return self.__t_size

    @t_size.setter
    def t_size(self, size:int):
        assert size is not None, "no .text size value given"
        assert isinstance(size, int), ".text size value must be an integer"
        assert size >= 0, ".text size value must be positive"
        self.__t_size = size

    @property
    def bin_path(self) -> str:
        return self.__bin_path

    @bin_path.setter
    def bin_path(self, path:str):
        if path:
            assert isinstance(path, str), "path must be of type str"
            assert os.path.exists(path), "invalid path to module binary directory"
        self.__bin_path = path

    @property
    def dbg_path(self) -> str:
        return self.__dbg_path

    @dbg_path.setter
    def dbg_path(self, path:str):
        if not path:
            if self.bin_path and self.name:
                path = self.bin_path + '/' + self.name + '.debug'
        if path:
            assert isinstance(path, str), "path must be of type str"
            assert path.endswith('.debug') and os.path.exists(path), "invalid path to module .debug file"
        self.__dbg_path = path

    @property
    def efi_path(self) -> str:
        return self.__efi_path

    @efi_path.setter
    def efi_path(self, path:str):
        if not path:
            if self.bin_path and self.name:
                path = self.bin_path + '/' + self.name + '.efi'
        if path:
            assert isinstance(path, str), "path must be of type str"
            assert path.endswith('.efi') and os.path.exists(path), "invalid path to module .efi file"
        self.__efi_path = path

    def set_module_paths(self, bin_path:str, dbg_path:str=None, efi_path:str=None):
        '''Set paths for module binary directory and module debug- and efi files. If a path to .debug or .efi file is not specified, it is assumed to exist within the bin_path directory.'''
        self.bin_path = bin_path
        self.dbg_path = dbg_path
        self.efi_path = efi_path

    def to_dict(self) -> dict:
        d = {
            'name': self.name,
            'img_base': str(self.img_base),
            'text_start': str(self.t_start),
            'text_end': str(self.t_end),
            'text_size': self.t_size,
            'binary_path': self.bin_path,
            'debug_path': self.dbg_path,
            'efi_path': self.efi_path
        }
        return d
    
    def from_dict(self, d:dict={}):
        name = d['name']
        img_base = d['img_base']
        t_start = d['text_start']
        t_end = d['text_end']
        t_size = d['text_size']
        bin_path = d['binary_path']
        if 'debug_path' in d.keys():
            dbg_path = d['debug_path']
        if 'efi_path' in d.keys():
            efi_path = d['efi_path']
        self.__init__(name, img_base, t_start, t_end, t_size, bin_path, dbg_path, efi_path)
    
    def get_toffset_and_tsize(self) -> Tuple[Address, int]:
        '''analyze this module's .efi file and obtain offset & size of its .text section'''
        module_efi = pefile.PE(self.efi_path)
        toffset = module_efi.OPTIONAL_HEADER.BaseOfCode
        tsize = module_efi.OPTIONAL_HEADER.SizeOfCode
        return Address(toffset), tsize
    
    def compute_tstart(self, t_offset:Address) -> Address:
        '''calculate .text start address from module's image base address and an offset'''
        assert self.img_base, "cannot compute .text start without image base"
        return self.img_base + t_offset
    
    def compute_tend(self, t_start:Address=None, t_size:int=None) -> Address:
        '''calculate .text end address from module's image base and .text start addresses and a size value'''
        if t_start is None:
            t_start = self.t_start
        if t_size is None:
            t_size = self.t_size
        assert t_start, "cannot compute .text end without .text start"
        assert t_size, "cannot compute .text end without .text size"
        return Address(int(t_start) + t_size)
    
    def fill_text_info(self, efi_path:str=None):
        '''fill the module's missing .text start, -end & -size info'''
        if not efi_path:
            efi_path = self.efi_path
        assert efi_path, "must specify a valid module .efi file path"
        t_offset, self.t_size = self.get_toffset_and_tsize()
        self.t_start = self.compute_tstart(t_offset)
        self.t_end = self.compute_tend()
    
    def print_short(self):
        print(f'{self.name} {self.img_base} {self.t_start}-{self.t_end}')
    
    def to_json(self, pretty=True):
        '''transform this module's info to a json object'''
        indent = None
        if pretty:
            indent = 4
        return json.dumps(self.to_dict(), indent=indent)




class TdvfModuleTable:
    '''A sorted dict of TDVF modules that can be presented in tabular form'''
    def __init__(self, modules:Dict[str, TdvfModule]=None):
        '''create a new TdvfModuleTable'''
        if modules:
            self.modules = OrderedDict(sorted(modules.items(), key=lambda item: item[1]))
            module_adrs = [m.t_start for m in self.modules.values()]
            assert module_adrs == sorted(module_adrs)

    def __str__(self):
        s = ''
        for module in self.modules.values():
            name = module.name
            base = Address(module.img_base)
            tstart = Address(module.t_start)
            tend = Address(module.t_end)
            tsize = module.t_size
            binpath = module.bin_path
            # print only shortened version of file paths starting from inside TDVF Build directory
            s += f'{name} {base} {tstart} {tend} {tsize} {binpath}\n'
        # use strip to remove the last (unnecessary) newline character
        return s.strip()

    @property
    def modules(self) -> dict:
        return self.__modules

    @modules.setter
    def modules(self, modules):
        if modules is None:
            modules = []
        if isinstance(modules, dict):
            modules = modules.values()
        for m in modules:
            if not isinstance(m, TdvfModule):
                assert m['name'], "module name is empty"
        self.__modules = OrderedDict((m.name, m) for m in sorted(modules))

    def set_module_paths(self, bin_path:str):
        '''Set paths for module binary directory and module debug- and efi files for all modules. The module .debug & .efi files are assumed to exist within the bin_path directory.'''
        for module in self.modules.values():
            module.set_module_paths(bin_path)

    def fill_text_info(self):
        '''fill all modules missing .text start, -end & -size info'''
        for m in self.modules.values():
            m.fill_text_info()

    def print_modules(self, only_modules:List[str]=[], print_table:bool=False):
        for mname in only_modules:
            assert mname, "module name must not be empty"

        if print_table:
            # print table header
            hname = "Module Name"
            hbase = "Image Base"
            hstart = ".text Start"
            hend = ".text End"
            hsize = "Size"
            bpath = "Binary Path"
            print(f'{hname:<32} {hbase:<12} {hstart:<12} {hend:<12} {hsize:<6} {bpath}')
            print('-' * 138)
        
        # print body
        for module in sorted(self.modules.values()):
            if only_modules and module.name not in only_modules:
                # if only_modules is given, print only those
                continue
            if print_table:
                name = module.name
                base = str(module.img_base)[2:]
                tstart = str(module.t_start)[2:]
                tend = str(module.t_end)[2:]
                tsize = module.t_size
                # print only shortened version of file paths starting from inside TDVF Build directory
                bpath = module.bin_path
                print(f'{name:<32} {base:0>12} {tstart:0>12} {tend:0>12} {tsize:<6} {bpath}')
            else:
                module.print_short()

    def print_short(self, only_modules:List[str]=[]):
        self.print_modules(only_modules, False)

    def print_table(self, only_modules:List[str]=[]):
        self.print_modules(only_modules, True)
    
    def to_json(self, only_modules:List[str]=[], pretty:bool=True) -> str:
        indent = None
        if pretty:
            indent = 4
        if not only_modules:
            only_modules = self.modules.keys()
        l = list(self.modules[name].to_dict() for name in only_modules)
        return json.dumps(l, indent=indent)
    
    def write_to_file(self, only_modules:List[str]=[], file_name:str='modules.json', pretty:bool=True):
        '''Write all module info to a json file, optionally pretty printed''' 
        with open(file_name, 'w') as f:
            f.write(self.to_json(only_modules, pretty))
    
    def read_from_file(self, file_name=str):
        '''read module information from file and create a TdvfModuleTable accordingly'''
        assert os.path.isfile(file_name), f'cannot find file \"{file_name}\"'
        with open(file_name, 'r') as f:
            module_info = json.load(f)
        
        modules = {}
        for minfo in module_info:
            m = TdvfModule()
            m.from_dict(minfo)
            modules[m.name] = m
        self.__init__(modules)