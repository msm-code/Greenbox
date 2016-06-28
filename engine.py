import re
import struct

import unicorn as u
import unicorn.x86_const as x86


def int32(i):
    return struct.unpack('<i', i)[0]


class Param(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return '<{}: {}>'.format(repr(self.name), repr(self.value))


class Emulator(object):
    def __init__(self, binary):
        self.binary = binary

    def create_instance(self, func_addr):
        return EmulationInstance(self, func_addr)


class EmulationInstance(object):
    ADDR_DATA = 0x100000
    ADDR_STACK = 0x300000
    ADDR_STUB = 0x3FF000
    ADDR_CODE = 0x400000

    regs = {
        'eax': x86.UC_X86_REG_EAX,
        'ecx': x86.UC_X86_REG_ECX,
        'ebx': x86.UC_X86_REG_EBX,
        'edx': x86.UC_X86_REG_EDX,
        'esi': x86.UC_X86_REG_ESI,
        'edi': x86.UC_X86_REG_EDI,
        'esp': x86.UC_X86_REG_ESP,
        'ebp': x86.UC_X86_REG_EBP,
    }

    def __init__(self, emulator, func_addr):
        self.emulator = emulator
        self.args = []
        self.data_ptr = self.ADDR_DATA

        self.mu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)

        binary = emulator.binary
        binary_pages = (len(binary) / 0x1000) + 1
        self.mu.mem_map(self.ADDR_CODE, binary_pages * 0x1000)
        self.mu.mem_write(self.ADDR_CODE, binary)

        self.mu.mem_map(self.ADDR_DATA, 10 * 0x1000)

        stack_size = 10 * 0x1000
        self.mu.mem_map(self.ADDR_STACK - stack_size, stack_size)

        self.mu.mem_map(self.ADDR_STUB, 1 * 0x1000)
        rel = struct.pack('<I', self.ADDR_CODE - self.ADDR_STUB + func_addr - 5)
        stub = '\xE8' + rel + '\x90'
        self.mu.mem_write(self.ADDR_STUB, stub)

        debug = False
        if debug:
            self.mu.hook_add(u.UC_HOOK_CODE, self.debug_hook_code)

    def debug_hook_code(self, uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = %u" % (address, size))
        eip = uc.reg_read(x86.UC_X86_REG_EIP)
        print(">>> EIP = 0x%x" % eip)

    def push_argument(self, arg):
        self.args += [arg]

    def allocate_string(self, string):
        allocated_addr = self.data_ptr
        self.mu.mem_write(allocated_addr, string)
        self.data_ptr += len(string)
        self.data_ptr += 0x10  # to avoid accidental interferences
        return allocated_addr

    def read_memory(self, addr, length):
        return self.mu.mem_read(addr, length)

    def read_reg(self, reg_name):
        return self.mu.reg_read(self.regs[reg_name])

    def set_reg(self, reg_name, value):
        return self.mu.reg_write(self.regs[reg_name], value)

    def execute(self):
        stack_ptr = self.ADDR_STACK + 0
        for arg in self.args[::-1]:
            stack_ptr -= 4
            raw = struct.pack('<I', arg)
            self.mu.mem_write(stack_ptr, raw)

        self.mu.reg_write(x86.UC_X86_REG_ESP, stack_ptr)

        self.mu.emu_start(self.ADDR_STUB, self.ADDR_STUB+5, count=0x1000)


class Signature(object):
    precondition = []
    postcondition = []

    def check(self, emulator):
        memory = {}
        for param in self.precondition:
            if param.name[0] == '$':
                emulator.set_reg(param.name[1:], param.value)
            elif isinstance(param.value, str):
                addr = emulator.allocate_string(param.value)
                emulator.push_argument(addr)
                memory[param.name] = (addr, len(param.value))
            else:
                emulator.push_argument(param.value)

        emulator.execute()

        results = {}
        for param in self.postcondition:
            if param.name[0] == '$':
                result = emulator.read_reg(param.name[1:])
            else:
                addr, memlen = memory[param.name]
                result = emulator.read_memory(addr, memlen)
            results[param.name] = result

        for param in self.postcondition:
            if results[param.name] != param.value:
                return False
        return True


class MemcpySignature(Signature):
    def __init__(self):
        self.precondition = [
            Param('destination', ' ' * 10),
            Param('source', '12345'),
            Param('num', 5),
        ]
        self.postcondition = [
            Param('destination', '12345     '),
            Param('source', '12345'),
        ]


class StrcpySignature(Signature):
    def __init__(self):
        self.precondition = [
            Param('destination', ' ' * 10),
            Param('source', '12345\0'),
        ]
        self.postcondition = [
            Param('destination', '12345\0    '),
            Param('source', '12345\0'),
        ]


class StrcatSignature(Signature):
    def __init__(self):
        self.precondition = [
            Param('destination', 'abcde\0' + ' ' * 10),
            Param('source', '12345\0'),
        ]
        self.postcondition = [
            Param('destination', 'abcde12345\0' + ' ' * 5),
            Param('source', '12345\0'),
        ]


class StrlenSignature(Signature):
    def __init__(self):
        self.precondition = [
            Param('string', 'a' * 17 + '\0'),
        ]
        self.postcondition = [
            Param('string', 'a' * 17 + '\0'),
            Param('$eax', 17),
        ]


class MemsetSignature(Signature):
    def __init__(self):
        self.precondition = [
            Param('string', 'a' * 17 + '\0'),
            Param('const', 0x62),
            Param('count', 10),
        ]
        self.postcondition = [
            Param('string', 'b' * 10 + 'a' * 7 + '\0'),
        ]


class NoOpSignature(Signature):
    def __init__(self):
        self.precondition = [
            Param('$eax', 0x123434),
        ]
        self.postcondition = [
            Param('$eax', 0x123434),
        ]


def find_all_functions(raw):
    potential_funcs = set({})
    for match in re.finditer('\xE8(....)', raw):
        potential = match.start() + int32(match.group(1)) + 5
        if potential > 0:
            potential_funcs.add(potential)

    for match in re.finditer('\x55\x89\xE5', raw):
        potential_funcs.add(match.start())

    return potential_funcs


def main():
    binary = open('/home/msm/test.out', 'rb').read()
    emu = Emulator(binary)

    potential_funcs = find_all_functions(binary)

    sigs = [
        MemcpySignature(),
        StrcpySignature(),
        StrcatSignature(),
        StrlenSignature(),
        MemsetSignature(),
        NoOpSignature(),
    ]

    for i in sorted(potential_funcs):
        for sig in sigs:
            instance = emu.create_instance(i)
            try:
                if sig.check(instance):
                    print 'signature {} found at offset {:x}'.format(
                        sig.__class__.__name__, i)
            except u.UcError:
                pass

main()