class Constant(int):
    def __new__(cls, s, i):
        obj = super(Constant, cls).__new__(cls, i)
        obj.s = s
        return obj
    def __str__(self):
        return self.s
    def __repr__(self):
        return 'Constant(%r, %#x)' % (self.s,int(self))
    def __add__(A, B):
        return Constant('(%s + %s)' % (A, B), int(A)+int(B))
    def __and__(A, B):
        return Constant('(%s & %s)' % (A, B), int(A)&int(B))
    def __sub__(A, B):
        return Constant('(%s - %s)' % (A, B), int(A)-int(B))
    def __xor__(A, B):
        return Constant('(%s ^ %s)' % (A, B), int(A)^int(B))
    def __or__(A, B):
        return Constant('(%s | %s)' % (A, B), int(A)|int(B))
    def __neg__(A):
        return Constant('-(%s)' % A, -int(A))
    def __invert__(A):
        return Constant('~(%s)' % A, ~int(A))
    def __lshift__(A, B):
        return Constant('(%s << %s)' % (A, B), int(A)<<int(B))
    def __rshift__(A, B):
        return Constant('(%s >> %s)' % (A, B), int(A)>>int(B))
    def __mod__(A, B):
        return Constant('(%s %% %s)' % (A, B), int(A)%int(B))

    # Right-hand side operations
    #
    def __radd__(A, B):      return Constant(str(B), B) + A
    def __rand__(A, B):      return Constant(str(B), B) & A
    def __rsub__(A, B):      return Constant(str(B), B) - A
    def __rxor__(A, B):      return Constant(str(B), B) ^ A
    def __ror__(A, B):       return Constant(str(B), B) | A
    def __rlshift__(A, B):   return Constant(str(B), B) << A
    def __rrshift__(A, B):   return Constant(str(B), B) >> A
    def __rmod__(A, B):      return Constant(str(B), B) % A