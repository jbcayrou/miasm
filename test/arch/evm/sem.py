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
from miasm2.expression.simplifications import ExpressionSimplifier

from miasm2.core import parse_asm, asmbloc
from pdb import pm

from miasm2.expression.simplifications import expr_simp

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
EXCLUDE_REGS = set([ir_arch().IRDst])

# Add ExprCond resolver 
expr_simp.enable_passes(ExpressionSimplifier.PASS_COND)

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
        #print all_bloc
        interm.add_bloc(b)

    symexec = symbexec(interm, sympool)

    symbolic_pc = symexec.emul_ir_blocs(interm, 0, step=False)
    #print symbolic_pc

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

    def test_mul(self):

        asm_text = """
PUSH1 0x03
PUSH1 0x04
MUL
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x0c, # 3*4 = 12
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_sub(self):

        asm_text = """
PUSH1 0x01
PUSH1 0x08
SUB
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x07, # 3*4 = 12
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_div(self):

        asm_text = """
PUSH1 0x03
PUSH1 0x09
DIV
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x3, # 9/3 = 3
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_div_zero(self):

        asm_text = """
PUSH1 0x00
PUSH1 0x09
DIV
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x0, # 9/3 = 3
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_mod(self):

        asm_text = """
PUSH1 0x10
PUSH1 0x18
MOD
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x8, # 0x18 % 0x10 = 0x08
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_exp(self):

        asm_text = """
PUSH1 0x8
PUSH1 0x2
EXP
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 256, # 2**8 = 256
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_addmod(self):

        asm_text = """
PUSH1 0x10
PUSH1 0x8
PUSH1 0x10
ADDMOD
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x8, # (0x10 + 0x8) % 0x10
                            M(1): 0x0,
                            M(2): 0x0,
                            SP: SP_pos(1)
                          }
                        )


    def test_mulmod(self):

        asm_text = """
PUSH1 0x10
PUSH1 0x8
PUSH1 0x10
MULMOD
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x0, # (0x10 * 0x8) % 0x10
                            M(1): 0x0,
                            M(2): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_lt(self):

        asm_text = """
PUSH1 0x8
PUSH1 0x2
LT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 1, # 2**8 = 256
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

        asm_text = """
PUSH1 0x8
PUSH1 0x2
LT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 1, # 2**8 = 256
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_gt(self):

        asm_text = """
PUSH1 0x8
PUSH1 0x2
GT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0, # 2**8 = 256
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_slt(self):

        asm_text = """
PUSH1 0xf0
NOT
PUSH1 0x01
ADD
PUSH1 0x0
SLT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0, #  ? 0x00 <s 0xffffff...f0 (-15) => no
                            M(1): 0,
                            SP: SP_pos(1)
                          }
                        )
        asm_text = """
PUSH1 0xf0
NOT
PUSH1 0x01
ADD
PUSH1 0x3
SLT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0, #  ? 0x00 <s 0xffffff...f0 (-15) => no
                            M(1): 0,
                            SP: SP_pos(1)
                          }
                        )

        asm_text = """

PUSH1 0x02
NOT
PUSH1 0x01
ADD
PUSH1 0x03
NOT
PUSH1 0x01
ADD
SLT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 1, # -3 < -2 ?
                            M(1): 0x0,
                            M(2): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_sgt(self):

        asm_text = """
PUSH1 0xf0
NOT
PUSH1 0x01
ADD
PUSH1 0x0
SGT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 1, #  ? 0x00 <s 0xffffff...f0 (-15) => no
                            M(1): 0,
                            SP: SP_pos(1)
                          }
                        )
        asm_text = """
PUSH1 0xf0
NOT
PUSH1 0x01
ADD
PUSH1 0x3
SGT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 1, #  ? 0x00 <s 0xffffff...f0 (-15) => no
                            M(1): 0,
                            SP: SP_pos(1)
                          }
                        )

        asm_text = """

PUSH1 0x02
NOT
PUSH1 0x01
ADD
PUSH1 0x03
NOT
PUSH1 0x01
ADD
SGT
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0, # -3 < -2 ?
                            M(1): 0x0,
                            M(2): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_eq(self):

        asm_text = """
PUSH1 0x1234
PUSH1 0x1234
EQ
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 1,
                            M(1): 0,
                            SP: SP_pos(1)
                          }
                        )

        asm_text = """
PUSH1 0x1234
PUSH1 0x4444
EQ
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0,
                            M(1): 0,
                            SP: SP_pos(1)
                          }
                        )


    def test_iszero(self):

        asm_text = """
PUSH1 0x00
ISZERO
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 1,
                            SP: SP_pos(1)
                          }
                        )

        asm_text = """
PUSH1 0x01
ISZERO
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0,
                            SP: SP_pos(1)
                          }
                        )

    def test_and(self):

        asm_text = """
PUSH1 0xF3
PUSH1 0x0F
AND
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x03,
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_or(self):

        asm_text = """
PUSH1 0xF3
PUSH1 0x0F
OR
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0xff,
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_xor(self):

        asm_text = """
PUSH1 0xF0
PUSH1 0xFF
XOR
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x0F,
                            M(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_not(self):

        asm_text = """
PUSH1 0x%x
NOT
"""% (2**256-1)
        res = compute_text(asm_text, {SP: 0})
        print res
        self.assertEqual(res,
                         {
                            M(0): 0,
                            SP: SP_pos(1)
                          }
                        )

    def test_byte(self):

        asm_text = """
PUSH1 0x1234
PUSH1 0x1
BYTE
"""
        res = compute_text(asm_text, {SP: 0})
        print res
        self.assertEqual(res,
                         {
                            M(0): 0x12, # TODO : check Little or big endian ??
                            SP: SP_pos(1)
                          }
                        )

    def test_jump(self):

        asm_text = """
PUSH1 0x5
JUMP
PUSH1 0x42
JUMPDEST
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x00,
                            SP: SP_pos(0)
                          }
                        )

    def test_jumpi(self):
        return

        asm_text = """
PUSH1 0x07
PUSH1 0x0
JUMPI
PUSH1 0xff
JUMPDEST
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(1): 0x00,
                            M(0): 0x00,
                            SP: SP_pos(0)
                          }
                        )


        asm_text = """
PUSH1 0x07
PUSH1 0x1
JUMPI
PUSH1 0x42
JUMPDEST
"""
        res = compute_text(asm_text, {SP: 0})
        print res
        self.assertEqual(res,
                         {
                            M(0): 0x42,
                            SP: SP_pos(1)
                          }
                        )

    def test_pop(self):
        asm_text = """
PUSH1 0x07
POP
"""
        res = compute_text(asm_text, {SP: 0})
        self.assertEqual(res,
                         {
                            M(0): 0x00,
                            SP: SP_pos(0)
                          }
                        )

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestEVMSemantic)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))