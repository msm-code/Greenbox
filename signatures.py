import hashlib
import random


def int32(n):
    return n & 0xFFFFFFFF


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


INT_1 = 0x42192838
INT_2 = 0x3787211
STRING_25 = 'asifkewrfoerfperkgfergeor\0'
STRING_15 = '94jfjdoisjfjjfj\0'
STRING_10 = 'xcvwoxcvnw\0'
STRING_NUMERIC = '123543\0'
STRING_HEX = 'a8d3cc\0'
STRING_5 = 'odifd\0'
BYTE_POSITIVE = ord('a')

def get_function_arg_names(func):
    argcount = func.func_code.co_argcount
    return func.func_code.co_varnames[:argcount]


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
            assert precondition == self.precondition
            if not self.verify(postcondition):
                return None
        return self.func_name


class ConstValueSignature:
    def __init__(self):
        tries = 3
        self.preconditions = [[Param('$retval', random.randint(0, 1000000))]] * tries

    def check(self, results):
        const = results[0][1]['$retval']
        for precondition, postcondition in results:
            if postcondition['$retval'] != const:
                return False
        return 'const_val_' + str(const)


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

db = SignatureDatabase()

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


db.signatures.append(SimpleSignature('noop', [Param('$retval', INT_1)], [Param('$retval', INT_1)]))

db.signatures.append(ConstValueSignature())

# todo - hexencoded versions
#@db.example(STRING_25)
#def md5(data):
#    return hashlib.md5(data).digest()
#
#
#@db.example(STRING_25)
#def sha1(data):
#    return hashlib.sha1(data).digest()
#
#
#@db.example(STRING_25)
#def sha256(data):
#    return hashlib.sha256(data).digest()
#
#
#@db.example(STRING_15)
#def identity(data):
#    return data

