# Some helper classes to deal with TDVF modules

import re
import json
import os.path
from typing import List, Tuple
from elftools.elf.elffile import ELFFile


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
    


class TdvfModule:
    '''A TDVF module object consisting of module name, image base address, info about the .text section and the file path of the module's .debug file'''

    def __init__(self, name: str, img_base:int=0, t_start:int=0, t_end:int=0, t_size:int=0, d_path:str=None):
        assert name, "name must contain at least one character"
        self.__name = name
        self.img_base = img_base
        self.t_start = t_start
        self.t_end = t_end
        self.t_size = t_size
        self.d_path = d_path
    
    def __str__(self) -> str:
        return str(self.to_dict())

    # define less-than method so class instances can be easily sorted
    def __lt__(self, other): 
        return self.name < other.name

    @property
    def name(self) -> str:
        return self.__name

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
    def d_path(self) -> str:
        return self.__d_path

    @d_path.setter
    def d_path(self, path:str):
        if path:
            assert isinstance(path, str), "path must be of type str"
            assert os.path.exists(path), "invalid path to module .debug file"
        self.__d_path = path

    def to_dict(self) -> dict:
        d = {
            'name': self.name,
            'img_base': str(self.img_base),
            'text_start': str(self.t_start),
            'text_end': str(self.t_end),
            'text_size': self.t_size,
            'debug_path': self.d_path
        }
        return d
    
    def get_toffset_and_tsize(self) -> Tuple[Address, int]:
        '''analyze this module's .debug file and obtain offset & size of its .text section'''
        with open(self.d_path, 'rb') as f:
            module_elf = ELFFile(f)
            for section in module_elf.iter_sections():
                if not section.name.startswith('.text'):
                    continue
                tsize = section.header['sh_size']
                toffset = section.header['sh_addr']
                break
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
    
    def fill_text_info(self, debug_path:str=None):
        '''fill the module's missing .text start, -end & -size info'''
        if not debug_path:
            debug_path = self.d_path
        assert self.d_path, "must specify a valid module .debug file path"
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
    def __init__(self, modules=None):
        '''create a new TdvfModuleTable'''
        self.modules = modules

    def __str__(self):
        s = ''
        for module in self.modules.values():
            _name = module.name
            _base = Address(module.img_base)
            _start = Address(module.t_start)
            _end = Address(module.t_end)
            _size = module.t_size
            _path = module.d_path
            s += f'{_name} {_base} {_start} {_end} {_size} {_path}\n'
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
            assert isinstance(m, TdvfModule), "module must be of type TdvfModule"
            assert m.name, "module name is empty"
        self.__modules = dict((m.name, m) for m in sorted(modules))

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
            hpath = "Debug Path"
            print(f'{hname:<32} {hbase:<12} {hstart:<12} {hend:<12} {hsize:<6} {hpath}')
            print('-' * 164)
        
        # print body
        for module in self.modules.values():
            if only_modules and module.name not in only_modules:
                # if only_modules is given, print only those
                continue
            if print_table:
                _name = module.name
                _base = _start = _end = _size = _path = ""
                _base = str(module.img_base)[2:]
                _start = str(module.t_start)[2:]
                _end = str(module.t_end)[2:]
                _size = module.t_size
                _path = module.d_path
                print(f'{_name:<32} {_base:0>12} {_start:0>12} {_end:0>12} {_size:>6} {_path}')
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