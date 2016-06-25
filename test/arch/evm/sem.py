#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest
import logging
import binascii

from miasm2.ir.symbexec import symbexec
from miasm2.arch.evm.arch import mn_evm as mn
from miasm2.arch.evm.sem import ir_evm as ir_arch
from miasm2.arch.evm.regs import *
from miasm2.expression.expression import *
from miasm2.core import parse_asm, asmbloc
from pdb import pm

from miasm2.expression.simplifications import expr_simp

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
EXCLUDE_REGS = set([ir_arch().IRDst])

def M(pos):
    return ExprMem(ExprInt256(pos*256), 256)

def M_sp(pos):
    offset = ExprInt256((pos+1)*256)
    adr = SP-offset

    return ExprMem(SP - offset, 256)

def SP_pos(pos):
    return pos * 256

def compute(asm, inputstate={}, debug=False):
    sympool = dict(regs_init)
    sympool.update({k: ExprInt_from(k, v) for k, v in inputstate.iteritems()})
    interm = ir_arch()
    symexec = symbexec(interm, sympool)
    instr = mn.fromstring(asm)
    code = mn.asm(instr)[0]
    instr = mn.dis(code)
    instr.offset = inputstate.get(PC, 0)
    interm.add_instr(instr)
    symexec.emul_ir_blocs(interm, instr.offset)
    if debug:
        for k, v in symexec.symbols.items():
            if regs_init.get(k, None) != v:
                print k, v
    out = {}
    for k, v in symexec.symbols.items():
        if k in EXCLUDE_REGS:
            continue
        elif regs_init.get(k, None) == v:
            continue
        elif isinstance(v, ExprInt):
            out[k] = v.arg.arg
        else:
            out[k] = v
    return out


def compute_text(asm, inputstate={}, debug=False):

    all_bloc, symbol_pool = parse_asm.parse_txt(mn,0, asm)

    sympool = dict(regs_init)
    sympool.update({k: ExprInt_from(k, v) for k, v in inputstate.iteritems()})

    interm = ir_arch()

    for b in all_bloc:
        print all_bloc
        interm.add_bloc(b)

    symexec = symbexec(interm, sympool)

    symbolic_pc = symexec.emul_ir_blocs(interm, 0, step=False)
    print symbolic_pc

    if debug:
        for k, v in symexec.symbols.items():
            if regs_init.get(k, None) != v:
                print k, v
    out = {}
    for k, v in symexec.symbols.items():
        if k in EXCLUDE_REGS:
            continue
        elif regs_init.get(k, None) == v:
            continue
        elif isinstance(v, ExprInt):
            out[k] = v.arg.arg
        else:
            out[k] = v
    return out

class TestEVMSemantic(unittest.TestCase):

    def _test_push(self, size):
        number = 0x0
        for i in xrange(0, size):
            number = number | (0x12 << (i*8))

        op = "PUSH%d 0x%x" % (size, number)

        self.assertEqual(
            compute(op, {SP: 0}),
            { M(0): number, SP : 1*256}
            )

    def test_push(self):

        for i in xrange(1,33):
            self._test_push(i)

        asm_text = """
PUSH1 0x10
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                           M(0): 0x10,
                           SP: 1*256
                         }
                        )

        asm_text = """
PUSH1 0x10
PUSH1 0x01
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         { M(1): 0x01,
                           M(0): 0x10,
                           SP: 2*256
                         }
                        )

        asm_text = """
PUSH1 0x10
PUSH1 0x01
PUSH4 0x11223344
PUSH12 0x112233445566778899aabbcc 

"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         { 
                           M(3): 0x112233445566778899aabbcc, 
                           M(2): 0x11223344, 
                           M(1): 0x01, 
                           M(0): 0x10,
                           SP: 4*256
                         }
                        )

    def test_swap(self):

        asm_text = """
PUSH1 0x10
PUSH1 0x01
SWAP1
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x01,
                            M(1): 0x10,
                            SP: SP_pos(2),
                          }
                        )

        asm_text = """
PUSH2 0x0123
PUSH2 0x1111
PUSH2 0x2222
PUSH2 0x3210
SWAP3
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(3): 0x0123,
                            M(2): 0x2222,
                            M(1): 0x1111,
                            M(0): 0x3210,
                            SP: SP_pos(4),
                          }
                        )


    def test_add(self):

        asm_text = """
PUSH1 0x10
PUSH1 0x01
ADD
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x11,
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestEVMSemantic)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))