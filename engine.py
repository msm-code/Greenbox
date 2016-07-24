import re
import sys
import struct
import signatures

import unicorn as u
import unicorn.x86_const as x86


def int32(i):
    return struct.unpack('<i', i)[0]


class Emulator(object):
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

    def __init__(self, binary):
        debug = False
        if debug:
            self.mu.hook_add(u.UC_HOOK_CODE, self.debug_hook_code)

        self.mu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
        binary_pages = (len(binary) / 0x1000) + 1
        self.mu.mem_map(self.ADDR_CODE, binary_pages * 0x1000, u.UC_PROT_EXEC | u.UC_PROT_READ)
        self.mu.mem_write(self.ADDR_CODE, binary)

        self.mu.mem_map(self.ADDR_DATA, 10 * 0x1000)

        stack_size = 10 * 0x1000
        self.mu.mem_map(self.ADDR_STACK - stack_size, stack_size, u.UC_PROT_ALL)

        self.mu.mem_map(self.ADDR_STUB, 1 * 0x1000, u.UC_PROT_ALL)

    def prepare(self, func_addr):
        self.args = []
        self.data_ptr = self.ADDR_DATA

        rel = struct.pack('<I', self.ADDR_CODE - self.ADDR_STUB + func_addr - 5)
        stub = '\xE8' + rel + '\x90'
        self.mu.mem_write(self.ADDR_STUB, stub)


    def execute_and_get_results(self, precondition):
        memory = {}
        for param in precondition:
            if isinstance(param.value, basestring):
                arg_value = self.allocate_string(param.value)
                memory[param.name] = (arg_value, len(param.value))
            else:
                arg_value = param.value

            if param.name == '$retval':
                self.set_reg('eax', arg_value)
            else:
                self.push_argument(arg_value)

        self.execute()

        results = {}
        results['$retval'] = self.read_reg('eax')
        for param in precondition:
            if param.name in memory:
                addr, memlen = memory[param.name]
                result = self.read_memory(addr, memlen)
                results[param.name] = result
        return results

    def check_signature(self, func_addr, sig):
        results = []
        for precondition in sig.preconditions:
            self.prepare(func_addr)
            result = self.execute_and_get_results(precondition)
            precondition_dict = {c.name: c.value for c in precondition}
            results.append((precondition_dict, result))
        return sig.check(results)

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
    binary = open(sys.argv[1], 'rb').read()
    emu = Emulator(binary)

    if len(sys.argv) > 2:
        potential_funcs = [int(sys.argv[2], 16)]
    else:
        potential_funcs = find_all_functions(binary)

    sigs = signatures.db

    for func_addr in sorted(potential_funcs):
        for sig in sigs.signatures:
            try:
                result = emu.check_signature(func_addr, sig)
                if result:
                    print 'signature {} found at offset {:x}'.format(result, func_addr)
                    break
            except u.UcError:
                pass

main()
