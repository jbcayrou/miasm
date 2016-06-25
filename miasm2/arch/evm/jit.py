from miasm2.jitter.jitload import jitter
from miasm2.core import asmbloc
from miasm2.core.utils import *

import logging

log = logging.getLogger('jit_evm')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_evm(jitter):

    def __init__(self, *args, **kwargs):
        from miasm2.arch.evm.sem import ir_evm
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_evm(sp), *args, **kwargs)
        self.vm.set_little_endian()
        self.ir_arch.jit_pc = self.ir_arch.arch.regs.PC

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc

