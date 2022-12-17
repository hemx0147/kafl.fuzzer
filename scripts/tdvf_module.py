# Some helper classes to deal with TDVF modules

import json
import os.path
from typing import List, Tuple
from elftools.elf.elffile import ELFFile



class TdvfModule:
    '''A TDVF module object consisting of module name, image base address, info about the .text section and the file path of the module's .debug file'''

    # set max. address size to 64-bit 
    __ADDR_MAX_VAL = 2**64

    def __init__(self, name: str, img_base:int=0, t_start:int=0, t_end:int=0, t_size:int=0, d_path:str=''):
        self.__name = name
        self.__img_base = img_base
        self.__t_start = t_start
        self.__t_end = t_end
        self.__t_size = t_size
        self.__d_path = d_path
    
    def __str__(self) -> str:
        return str(self.to_dict())

    # define less-than method so class instances can be easily sorted
    def __lt__(self, other): 
        return self.name < other.name

    def __validate_address(self, address:int):
        '''perform some sanity checks on a given address'''
        assert isinstance(address, int), "address must be an integer value"
        assert address >= 0, "address must not be negative"
        assert address <= self.__ADDR_MAX_VAL, "address must be max. 64-bit"

    def __validate_path(self, path:str):
        '''perform some sanity checks on a given file/directory path'''
        assert isinstance(path, str), "path must be a string"
        assert path, "path string must not be empty"
        assert os.path.exists(path), "invalid path: path \"path\" does not exist"

    @property
    def name(self) -> str:
        return self.__name

    @property
    def img_base(self) -> int:
        return self.__img_base

    @img_base.setter
    def img_base(self, addr:int):
        self.__validate_address(addr)
        self.__img_base = addr

    @property
    def t_start(self) -> int:
        return self.__t_start

    @t_start.setter
    def t_start(self, addr:int):
        self.__validate_address(addr)
        self.__t_start = addr

    @property
    def t_end(self) -> int:
        return self.__t_end

    @t_end.setter
    def t_end(self, addr:int):
        self.__validate_address(addr)
        self.__t_end = addr

    @property
    def t_size(self) -> int:
        return self.__t_size

    @t_size.setter
    def t_size(self, size:int):
        assert isinstance(size, int), "size of .text section must be an int"
        self.__t_size = size

    @property
    def d_path(self) -> str:
        return self.__d_path

    @d_path.setter
    def d_path(self, path:str):
        self.__validate_path(path)
        self.__d_path = path

    def to_dict(self) -> dict:
        d = {
            'name': self.name,
            'img_base': self.img_base,
            'text_start': self.t_start,
            'text_end': self.t_end,
            'text_size': self.t_size,
            'debug_path': self.d_path
        }
        return d
    
    def get_toffset_and_tsize(self) -> Tuple[int, int]:
        '''analyze this module's .debug file and obtain offset & size of its .text section'''
        with open(self.d_path, 'rb') as f:
            module_elf = ELFFile(f)
            for section in module_elf.iter_sections():
                if not section.name.startswith('.text'):
                    continue
                tsize = section.header['sh_size']
                toffset = section.header['sh_addr']
                break
        return toffset, tsize
    
    def compute_tstart(self, t_offset:int) -> int:
        '''calculate .text start address from module's image base address and an offset'''
        assert self.img_base, "cannot compute .text start without image base"
        self.__validate_address(t_offset)
        return self.img_base + t_offset
    
    def compute_tend(self, t_size:int=None, t_start:int=None) -> int:
        '''calculate .text end address from module's image base and .text start addresses and a size value'''
        if not t_size:
            t_size = self.t_size
        if not t_start:
            t_start = self.t_start
        assert self.img_base, "cannot compute .text start without image base"
        assert t_size, "cannot compute .text end without .text size"
        assert isinstance(t_size, int), ".text size is not an integer value"
        assert t_size >= 0, ".text size must not be negative"
        assert self.t_start, "cannot compute .text end without .text start"
        return t_start + t_size
    
    def fill_text_info(self):
        '''fill the module's missing .text start, -end & -size info'''
        t_offset, self.t_size = self.get_toffset_and_tsize()
        self.t_start = self.compute_tstart(t_offset)
        self.t_end = self.compute_tend()



class TdvfModuleTable:
    '''A sorted list of TDVF modules that can be presented in tabular form'''
    def __init__(self, module_list:List[TdvfModule]=None):
        for m in module_list:
            self.__validate_module(m)
        self.__modules = sorted(module_list)

    def __int_to_addr(self, address: int, prefix:bool = True) -> str:
        '''format an address value (int) to hex-address format ("0x"-prefix followed by 16 hex chars)'''
        hexval = hex(address)[2:]     # hex address without '0x' prefix for further processing
        _prefix = ''
        if prefix:
                _prefix = '0x'    # prepend '0x' if necessary
        return _prefix + '{0:0>16}'.format(hexval)

    def __str_to_addr(self, address: str, prefix:bool = True) -> str:
        '''format an address value string to hex-address format ("0x" followed by 16 hex chars)'''
        addr = ""
        if address:
            addr = self.__int_to_addr(int(address, 16), prefix)
        return addr

    def __validate_module(self, module:TdvfModule):
        assert isinstance(module, TdvfModule), "module must be an instance of the TdvfModule class"
        assert module.name, "module name must not be empty"

    def __str__(self):
        s = ''
        for module in self.modules:
            _name = module.name
            _base = self.__int_to_addr(module.img_base, False)
            _start = self.__int_to_addr(module.t_start, False)
            _end = self.__int_to_addr(module.t_end, False)
            _size = module.t_size
            _path = module.d_path
            s += f'{_name} {_base} {_start} {_end} {_size} {_path}\n'
        # use strip to remove the last (unnecessary) newline character
        return s.strip()

    @property
    def modules(self) -> list:
        return self.__modules

    @modules.setter
    def modules(self, module_list:List[TdvfModule]):
        for m in module_list:
            self.__validate_module(m)
        self.modules = sorted(module_list)

    def add_module(self, module:TdvfModule):
        self.__validate_module(module)
        self.modules.append(module)
        self.modules = sorted(self.modules)
    
    def get_module(self, name:str) -> TdvfModule:
        '''return a single module from the table matching the specified name'''
        try:
            module = next(filter(lambda module: name == module.name, self.modules))
        except StopIteration:
            raise Exception("module table does not contain module named \"name\"")
        return module

    def print_table(self, only_modules:List[str]=[], header:bool=True, i_base:bool=True, t_start:bool=True, t_end:bool=True, t_size:bool=True, d_path:bool=True):
        for mname in only_modules:
            assert mname, "module name must not be empty"

        # build table header
        if header:
            hname = "Module Name"
            if i_base:
                hbase = "Image Base"
            if t_start:
                hstart = ".text Start"
            if t_end:
                hend = ".text End"
            if t_size:
                hsize = "Size"
            if d_path:
                hpath = "Debug Path"
            print(f'{hname:<32} {hbase:<16} {hstart:<16} {hend:<16} {hsize:0>6} {hpath}')
        
        # build table body
        for module in self.modules:
            if only_modules and module.name not in only_modules:
                # if only_modules is given, print only those
                continue
            _name = module.name
            _base = _start = _end = _size = _path = ""
            if i_base:
                _base = self.__int_to_addr(module.img_base, False)
            if t_start:
                _start = self.__int_to_addr(module.t_start, False)
            if t_end:
                _end = self.__int_to_addr(module.t_end, False)
            if t_size:
                _size = module.t_size
            if d_path:
                _path = module.d_path
                print(f'{_name:<32} {_base:<16} {_start:<16} {_end:<16} {_size:0>6} {_path}')

    def to_json_file(self, file_name:str='modules.json', pretty:bool=True):
        '''Write all module info to a json file, optionally pretty printed''' 
        indent = None
        if pretty:
            indent = 4
        with open(file_name, 'w') as f:
            json.dump(self.modules, f, indent=indent)