import struct

import unicorn as u
import unicorn.x86_const as x86


class Param(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value


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
        self.mu.mem_map(self.ADDR_STACK - stack_size , stack_size )

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
        return self.mu.reg_read(regs[reg_name])

    def execute(self):
        stack_ptr = self.ADDR_STACK
        for arg in self.args[::-1]:
            stack_ptr -= 4
            raw = struct.pack('<I', arg)
            self.mu.mem_write(stack_ptr, raw)

        self.mu.reg_write(x86.UC_X86_REG_ESP, stack_ptr)

        self.mu.emu_start(self.ADDR_STUB, self.ADDR_STUB+5)


class Signature(object):
    def check(self, emulator):
        memory = {}
        for param in self.precondition:
            if isinstance(param.value, str):
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


def main():
    binary = """
        FF D2 83 C4 10 C9 E9 75  FF FF FF 55 89 E5 83 EC
        10 C7 45 FC 00 00 00 00  EB 04 83 45 FC 01 8B 45
        08 8D 50 01 89 55 08 0F  B6 00 84 C0 75 EC 8B 45
        FC C9 C3 55 89 E5 EB 13  8B 45 0C 0F B6 10 8B 45
        08 88 10 83 45 0C 01 83  45 08 01 8B 45 0C 0F B6
        00 84 C0 75 E3 8B 45 08  C6 00 00 90 5D C3 55 89
        E5 83 EC 10 C7 45 FC 00  00 00 00 EB 19 8B 55 FC
        8B 45 08 01 C2 8B 4D FC  8B 45 0C 01 C8 0F B6 00
        88 02 83 45 FC 01 8B 45  FC 3B 45 10 7C DF 90 C9
        C3 55 89 E5 FF 75 0C E8  6F FF FF FF 83 C4 04 01
        45 08 FF 75 0C FF 75 08  E8 86 FF FF FF 83 C4 08
        90 C9 C3 55 89 E5 B8 00  00 00 00 5D C3 66 90 90
    """
    binary = binary.replace(' ', '').replace('\n', '').decode('hex')
    emu = Emulator(binary)

    sigs = [
        MemcpySignature(),
        StrcpySignature(),
        StrcatSignature(),
        StrlenSignature()
    ]

    for i in range(len(binary)):
        for sig in sigs:
            instance = emu.create_instance(i)
            try:
                if sig.check(instance):
                    print 'signature {} found at offset {}'.format(
                        sig.__class__.__name__, i)
            except u.UcError:
                pass

main()