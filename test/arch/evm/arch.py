import time, os
from miasm2.arch.evm.arch import *

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


def h2i(s):
    return s.replace(' ', '').decode('hex')

reg_tests_msp = [
    ("0000 STOP","00"),
]

ts = time.time()

for s, l in reg_tests_msp:
    print "-" * 80
    s = s[5:]
    b = h2i((l))
    print repr(b)

    mn = mn_evm.dis(b, None)
    print [str(x) for x in mn.args]
    print "---------"
    print [hex(ord(x)) for x in s]
    print [hex(ord(x)) for x in str(mn)]
    assert(str(mn) == s)
    exit()

    # print hex(b)
    # print [str(x.get()) for x in mn.args]
    l = mn_evm.fromstring(s, None)
    # print l
    assert(str(l) == s)
    a = mn_evm.asm(l)
    print [x for x in a]
    print repr(b)
    # print mn.args
    assert(b in a)
