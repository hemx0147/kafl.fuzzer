# Some helper classes to deal with TDVF modules

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
        try:
            value = int(value, 16)
        except:
            value = int(value)
        assert self.__is_valid_address(value), f'invalid address value "{value}"'
        self.__value = value
        self.__address = hex(value)

    def __is_valid_address(self, address:int) -> bool:
        '''perform some sanity checks on a given address
        a valid address must be an integer value between 0 and ADDR_MAX_VAL (inclusively)
        '''
        if address is not None and isinstance(address, int) and address >= 0 and address <= self.__ADDR_MAX_VAL:
            return True
        return False

    @property
    def address(self) -> str:
        return self.__address
    
    @address.setter
    def address(self, address):
        assert self.__is_valid_address(address), f'invalid address value "{address}"'
        self.__address = address
        self.__value = int(address, 16)
    
    @property
    def value(self) -> int:
        return self.__value

    @value.setter
    def value(self, value):
        assert self.__is_valid_address(value), f'invalid address value "{value}"'
        self.__value = value
        self.__address = hex(value)

    def __str__(self) -> str:
        return self.__address


class TdvfModule:
    '''A TDVF module object consisting of module name, image base address, info about the .text section and the file path of the module's .debug file'''

    def __init__(self, name: str, img_base:int=0, t_start:int=0, t_end:int=0, t_size:int=0, d_path:str=''):
        assert self.__is_valid_address(img_base), "invalid image base address"
        assert self.__is_valid_address(t_start), "invalid .text start address"
        assert self.__is_valid_address(t_end), "invalid .text end address"
        assert self.__is_valid_size(t_size), "invalid .text section size"
        assert self.__is_valid_path(d_path), "invalid path to module .debug file"
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


    def __is_valid_size(self, size:int) -> bool:
        '''a valid size is a positive integer value'''
        if size is not None and isinstance(size, int) and size >= 0:
            return True
        return False

    def __is_valid_path(self, path:str) -> bool:
        '''perform some sanity checks on a given file/directory path
        a valid path must be a non-empty path string pointing to an existing file/dir
        '''
        if path and isinstance(path, str) and os.path.exists(path):
            return True
        return False

    @property
    def name(self) -> str:
        return self.__name

    @property
    def img_base(self) -> int:
        return self.__img_base

    @img_base.setter
    def img_base(self, addr:int):
        assert self.__is_valid_address(addr), "invalid image base address"
        self.__img_base = addr

    @property
    def t_start(self) -> int:
        return self.__t_start

    @t_start.setter
    def t_start(self, addr:int):
        assert self.__is_valid_address(addr), "invalid .text start address"
        self.__t_start = addr

    @property
    def t_end(self) -> int:
        return self.__t_end

    @t_end.setter
    def t_end(self, addr:int):
        assert self.__is_valid_address(addr), "invalid .text end address"
        self.__t_end = addr

    @property
    def t_size(self) -> int:
        return self.__t_size

    @t_size.setter
    def t_size(self, size:int):
        assert self.__is_valid_size(size), "invalid .text section size"
        self.__t_size = size

    @property
    def d_path(self) -> str:
        return self.__d_path

    @d_path.setter
    def d_path(self, path:str):
        assert self.__is_valid_path(path), "invalid path to module .debug file"
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
        assert self.__is_valid_address(t_offset), "invalid offset value"
        return self.img_base + t_offset
    
    def compute_tend(self, t_size:int=None, t_start:int=None) -> int:
        '''calculate .text end address from module's image base and .text start addresses and a size value'''
        if not t_size:
            t_size = self.t_size
        if not t_start:
            t_start = self.t_start
        assert self.img_base, "cannot compute .text start without image base"
        assert self.t_start, "cannot compute .text end without .text start"
        assert t_size, "cannot compute .text end without .text size"
        assert self.__is_valid_size(t_size), "invalid .text size value"
        return t_start + t_size
    
    def fill_text_info(self):
        '''fill the module's missing .text start, -end & -size info'''
        t_offset, self.t_size = self.get_toffset_and_tsize()
        self.t_start = self.compute_tstart(t_offset)
        self.t_end = self.compute_tend()



class TdvfModuleTable:
    '''A sorted list of TDVF modules that can be presented in tabular form'''
    def __init__(self, module_list:List[TdvfModule]=[]):
        for m in module_list:
            assert self.__is_valid_module(m), f"invalid module \"{m.name}\""
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

    def __is_valid_module(self, module:TdvfModule):
        '''a valid module is of TdvfModule type and has a non-empty name'''
        if module and isinstance(module, TdvfModule) and module.name:
            return True
        return False

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
            assert self.__is_valid_module(m), f"invalid module \"{m.name}\""
        self.modules = sorted(module_list)

    def add_module(self, module:TdvfModule):
        assert self.__is_valid_module(module), f"invalid module \"{module.name}\""
        self.modules.append(module)
        self.modules.sort()
    
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