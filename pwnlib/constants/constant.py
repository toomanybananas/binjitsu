import operator

symbols = {
    operator.add: '+',
    operator.sub: '-',
    operator.xor: '^',
    operator.or_: '|',
    operator.and_: '&',
    operator.lshift: '<<',
    operator.rshift: '>>',
    operator.mod: '%',
    operator.neg: '-',
    operator.invert: '~',
    operator.mul: '*',
    operator.div: '/'
}

def unary(a, op):
    name   = '(%s%s)' % (symbols[op], a)
    value  = op(int(a))
    return Constant(name, value)

def binary(a, b, op):
    name   = '(%s %s %s)' % (a, symbols[op], b)
    value  = op(int(a), int(b))
    return Constant(name, value)

class Constant(int):
    def __new__(cls, s, i):
        obj = super(Constant, cls).__new__(cls, i)
        obj.s = s
        return obj
    def __str__(self):
        return self.s
    def __repr__(self):
        return 'Constant(%r, %#x)' % (self.s,int(self))

    def __add__(A, B):    return binary(A, B, operator.add)
    def __sub__(A, B):    return binary(A, B, operator.sub)
    def __mul__(A, B):    return binary(A, B, operator.mul)
    def __idiv__(A, B):   return binary(A, B, operator.idiv)
    def __or__(A, B):     return binary(A, B, operator.or_)
    def __xor__(A, B):    return binary(A, B, operator.xor)
    def __and__(A, B):    return binary(A, B, operator.and_)
    def __lshift__(A, B): return binary(A, B, operator.lshift)
    def __rshift__(A, B): return binary(A, B, operator.rshift)
    def __mod__(A, B):    return binary(A, B, operator.mod)
    def __neg__(A, B):    return unary(A, operator.neg)
    def __invert__(A, B): return unary(A, operator.invert)

    def __radd__(A, B):    return binary(B, A, operator.add)
    def __rsub__(A, B):    return binary(B, A, operator.sub)
    def __rmul__(A, B):    return binary(B, A, operator.mul)
    def __ridiv__(A, B):   return binary(B, A, operator.idiv)
    def __ror__(A, B):     return binary(B, A, operator.or_)
    def __rxor__(A, B):    return binary(B, A, operator.xor)
    def __rand__(A, B):    return binary(B, A, operator.and_)
    def __rlshift__(A, B): return binary(B, A, operator.lshift)
    def __rrshift__(A, B): return binary(B, A, operator.rshift)
    def __rmod__(A, B):    return binary(B, A, operator.mod)
