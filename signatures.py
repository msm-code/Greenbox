import hashlib
import random
import zlib


INT_1 = 0x42192838
INT_2 = 0x3787211
STRING_50 = 'asifkewrfoerfperkgfergeorasifkewrfoerfperkgfergeor\0'
STRING_15 = '94jfjdoisjfjjfj\0'
STRING_10 = 'xcvwoxcvnw\0'
STRING_NUMERIC = '123543\0'
STRING_HEX = 'a8d3cc\0'
STRING_5 = 'odifd\0'
BYTE_POSITIVE = ord('a')


def int32(n):
    return n % (2**32)


def get_function_arg_names(func):
    argcount = func.func_code.co_argcount
    return func.func_code.co_varnames[:argcount]


class Param(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return '<{}: {}>'.format(repr(self.name), repr(self.value))


class PseudoBinaryData:
    def __init__(self, string):
        self.data = [ord(c) for c in string]

    def __setitem__(self, key, item):
        if key >= len(self.data):
            self.data += [0] * (1 + len(self.data) - key)
        self.data[key] = item

    def __getitem__(self, key):
        if key > len(self.data):
            return 0
        return self.data[key]

    def to_string(self):
        return ''.join(chr(c) for c in self.data)

    def clone(self):
        return PseudoBinaryData(self.to_string())


class SimpleSignature:
    def __init__(self, func_name, precondition, postcondition):
        self.func_name = func_name
        self.precondition = precondition
        self.postcondition = postcondition
        self.preconditions = [precondition]

    def verify(self, results):
        for param in self.postcondition:
            if param.name in results:
                if results[param.name] != param.value:
                    return False
        return True

    def check(self, results):
        for precondition, postcondition in results:
            assert all(c.value == precondition[c.name] for c in self.precondition)
            if not self.verify(postcondition):
                return None
        return self.func_name


class TransformSignature:
    def __init__(self, transformer):
        tries = 3
        self.preconditions = []
        for i in range(tries):
            self.preconditions.append([
                Param('$retval', random.randint(1, 100000)),
                Param('num', random.randint(1, 100000))
            ])
        self.transformer = transformer

    def verify(self, transforms):
        return self.transformer(transforms)

    def check(self, results):
        transforms = []
        for precondition, postcondition in results:
            frm, to = precondition['num'], postcondition['$retval']
            transforms.append((frm, to))
        return self.verify(transforms)


#class ConstValueSignature:
#    def __init__(self):
#        tries = 3
#        self.preconditions = [[Param('$retval', random.randint(0, 1000000))]] * tries
#
#    def check(self, results):
#        const = results[0][1]['$retval']
#        for precondition, postcondition in results:
#            if postcondition['$retval'] != const:
#                return False
#        return 'const_val_' + str(const)


class SignatureDatabase:
    def __init__(self):
        self.signatures = []

    def example(self, *args):
        def decorator(func):
            names = get_function_arg_names(func)
            
            values = [bytearray(arg) if isinstance(arg, basestring) else arg for arg in args]
            return_value = func(*values)

            preconditions = [Param(n, v) for n, v in zip(names, args)]
            postconditions = [Param(n, v) for n, v in zip(names, values)]

            if return_value is not None:
                postconditions.append(Param('$retval', return_value))

            sig = SimpleSignature(func.__name__, preconditions, postconditions)
            self.signatures.append(sig)
            return func
        return decorator

    def transform(self, func):
        sig = TransformSignature(func)
        self.signatures.append(sig)
        return func


db = SignatureDatabase()

db.signatures.append(SimpleSignature('noop', [Param('$retval', INT_1)], [Param('$retval', INT_1)]))
#db.signatures.append(ConstValueSignature())


@db.example(STRING_15)
def strlen(data):
    return data.find('\0')


@db.example(STRING_15, STRING_10, 10)
def memcpy(destination, source, num):
    for i in range(num):
        destination[i] = source[i]


@db.example(STRING_15, STRING_10)
def strcpy(destination, source):
    for i in range(strlen(source) + 1):
        destination[i] = source[i]


@db.example(STRING_5 + STRING_15, STRING_10)
def strcat(destination, source):
    start = strlen(destination)
    for i in range(strlen(source)+1):
        destination[start+i] = source[i]


@db.example(STRING_15, BYTE_POSITIVE, 10)
def memset(destination, value, length):
    for i in range(length):
        destination[i] = value


@db.example(STRING_15, 10)
def memzero(destination, length):
    memset(destination, 0, length)


@db.example(STRING_NUMERIC)
def atoi(num):
    return int(num[:strlen(num)])


@db.example(STRING_HEX)
def hextoi(num):
    return int(str(num[:strlen(num)]), 16)


@db.example(INT_1)
def itoa(num):
    return str(num)


@db.example(INT_1, INT_2)
def add(a, b):
    return int32(a + b)


@db.example(INT_1, INT_2)
def sub(a, b):
    return int32(a - b)


@db.example(INT_1, INT_2)
def mul(a, b):
    return int32(a * b)


@db.example(INT_1, INT_2)
def div(a, b):
    return int32(a / b)


@db.example(STRING_15, 10)
def adler32_b(data, n):
    return int32(zlib.adler32(str(data[:n])))


@db.example(STRING_15)
def adler32_s(data):
    return int32(zlib.adler32(str(data[:strlen(data)])))


@db.example(STRING_15, 10)
def crc32_b(data, n):
    return int32(zlib.crc32(str(data[:n])))


@db.example(STRING_15)
def crc32_s(data):
    return int32(zlib.crc32(str(data[:strlen(data)])))


@db.example(STRING_15, 10, STRING_50)
def md5_b(data, n, out):
    memcpy(out, hashlib.md5(str(data[:n])).digest(), 16)


@db.example(STRING_15, 10, STRING_50)
def hex_md5_b(data, n, out):
    memcpy(out, hashlib.md5(str(data[:n])).hexdigest(), 32)


#@db.example(INT_1)
#def identity(num):
#    return num


@db.transform
def add_const(transforms):
    frm0, to0 = transforms[0]
    diff = to0 - frm0
    for frm, to in transforms:
        if frm + diff != to:
            return False
    return 'add_const_' + str(diff)


@db.transform
def xor_const(transforms):
    frm0, to0 = transforms[0]
    diff = to0 ^ frm0
    for frm, to in transforms:
        if frm ^ diff != to:
            return False
    return 'xor_const_' + str(diff)
