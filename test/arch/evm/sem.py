#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest
import logging
import binascii

from miasm2.ir.symbexec import SymbolicExecutionEngine
from miasm2.arch.evm.arch import mn_evm as mn
from miasm2.arch.evm.sem import ir_evm as ir_arch
from miasm2.arch.evm.sem import MEM_BASE_CALLDATA, calldata_sem, mem_sem, storage_sem
from miasm2.arch.evm.regs import *
from miasm2.arch.evm.disasm import dis_evm

from miasm2.expression.expression import *
from miasm2.expression.simplifications import ExpressionSimplifier

from miasm2.core import parse_asm, asmblock
from pdb import pm

from miasm2.expression.simplifications import expr_simp

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
EXCLUDE_REGS = [ir_arch().IRDst, ir_arch().pc]



from miasm2.arch.evm.env import *
import miasm2.expression.expression as m2_expr
ExpressionSimplifier.EVM_PASS = {}
ExpressionSimplifier.EVM_PASS[m2_expr.ExprOp] = [evm_expr_simplification]

# Add ExprCond resolver 
expr_simp.enable_passes(ExpressionSimplifier.PASS_COND)
# Add EVM_PASS to resolve evm_xxx operators
expr_simp.enable_passes(ExpressionSimplifier.EVM_PASS)

def mem_stack(pos):
    return ExprMem(ExprInt256(pos*256), 256)

def mem_memory(pos):
    return ExprMem(mem_sem.prefix + ExprInt(pos, 256), 8)


def mem_storage(pos):
    return ExprMem(storage_sem.prefix + ExprInt(pos, 256), 256)

def M_sp(pos):
    offset = ExprInt256((pos+1)*256)
    adr = SP-offset

    return ExprMem(SP - offset, 256)

def SP_pos(pos):
    return pos * 256

def compute(asm, inputstate={}, debug=False):
    sympool = dict(regs_init)
    sympool.update({k: ExprInt(v, k.size) for k, v in inputstate.iteritems()})
    interm = ir_arch()
    symexec = SymbolicExecutionEngine(interm, sympool)
    instr = mn.fromstring(asm, "l")
    code = mn.asm(instr)[0]
    instr = mn.dis(code, "l")
    instr.offset = inputstate.get(PC, 0)
    interm.add_instr(instr)
    symexec.emul_ir_blocks(instr.offset)
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



def compute_text(asm, inputstate={}, debug=False, exclude = []):

    all_bloc, symbol_pool = parse_asm.parse_txt(mn,0, asm)

    sympool = dict(regs_init)
    sympool.update({k: v if isinstance(v, ExprInt) else  ExprInt(v, k.size) for k, v in inputstate.iteritems()})

    interm = ir_arch()

    for b in all_bloc:
        interm.add_bloc(b)
    print all_bloc

    symexec = SymbolicExecutionEngine(interm, sympool)

    symbolic_pc = symexec.emul_ir_blocks(0, step=False)

    if debug:
        for k, v in symexec.symbols.items():
            if regs_init.get(k, None) != v:
                print k, v
    out = {}
    exclude_symb = EXCLUDE_REGS+exclude
    for k, v in symexec.symbols.items():
        if k in EXCLUDE_REGS:
            continue
        elif regs_init.get(k, None) == v:
            continue
        elif isinstance(v, ExprInt):
            out[k] = v.arg.arg
        else:
            out[k] = v
    return out, symexec


def compute_text_bytecode(asm, inputstate={}, debug=False):
    """
    Take asm code, convert into bytecode and disasemble it
    """

    s=[]
    asm=asm.strip()
    for l in asm.split("\n"):
        s.append(mn.fromstring(l))

    ret = "".join(mn.asm(x)[0] for x in s)

    mdis=dis_evm(ret)

    blks = mdis.dis_multibloc(0)

    sympool = dict(regs_init)
    sympool.update({k: ExprInt(v, k.size) for k, v in inputstate.iteritems()})

    interm = ir_arch()

    for b in blks:
        interm.add_bloc(b)

    symexec = SymbolicExecutionEngine(interm, sympool)

    symbolic_pc = symexec.emul_ir_blocks(0, step=False)

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
    return out, symexec.symbols


class TestEVMSemantic(unittest.TestCase):

    def _test_push(self, size):
        number = 0x0
        for i in xrange(0, size):
            number = number | (0x12 << (i*8))

        op = "PUSH%d 0x%x" % (size, number)

        self.assertEqual(
            compute(op),
            { mem_stack(0): number, SP : 1*256}
            )

    def test_push(self):

        for i in xrange(1,33):
            self._test_push(i)

        asm_text = """
PUSH1 0x10
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                           mem_stack(0): 0x10,
                           SP: 1*256
                         }
                        )

        asm_text = """
PUSH1 0x10
PUSH1 0x01
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         { mem_stack(1): 0x01,
                           mem_stack(0): 0x10,
                           SP: 2*256
                         }
                        )

        asm_text = """
PUSH1 0x10
PUSH1 0x01
PUSH4 0x11223344
PUSH12 0x112233445566778899aabbcc
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         { 
                           mem_stack(3): 0x112233445566778899aabbcc, 
                           mem_stack(2): 0x11223344, 
                           mem_stack(1): 0x01, 
                           mem_stack(0): 0x10,
                           SP: 4*256
                         }
                        )

    def test_swap(self):

        asm_text = """
PUSH1 0x10
PUSH1 0x01
SWAP1
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x01,
                            mem_stack(1): 0x10,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(3): 0x0123,
                            mem_stack(2): 0x2222,
                            mem_stack(1): 0x1111,
                            mem_stack(0): 0x3210,
                            SP: SP_pos(4),
                          }
                        )


    def test_add(self):

        asm_text = """
PUSH1 0x10
PUSH1 0x01
ADD
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x11,
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_mul(self):

        asm_text = """
PUSH1 0x03
PUSH1 0x04
MUL
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x0c, # 3*4 = 12
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_sub(self):

        asm_text = """
PUSH1 0x01
PUSH1 0x08
SUB
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x07, # 3*4 = 12
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_div(self):

        asm_text = """
PUSH1 0x03
PUSH1 0x09
DIV
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x3, # 9/3 = 3
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_div_zero(self):

        asm_text = """
PUSH1 0x00
PUSH1 0x09
DIV
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x0,
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_mod(self):

        asm_text = """
PUSH1 0x10
PUSH1 0x18
MOD
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x8, # 0x18 % 0x10 = 0x08
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_exp(self):

        asm_text = """
PUSH1 0x8
PUSH1 0x2
EXP
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 256, # 2**8 = 256
                            mem_stack(1): 0x0,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x8, # (0x10 + 0x8) % 0x10
                            mem_stack(1): 0x0,
                            mem_stack(2): 0x0,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x0, # (0x10 * 0x8) % 0x10
                            mem_stack(1): 0x0,
                            mem_stack(2): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_lt(self):

        asm_text = """
PUSH1 0x8
PUSH1 0x2
LT
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 1, # 2**8 = 256
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

        asm_text = """
PUSH1 0x8
PUSH1 0x2
LT
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 1, # 2**8 = 256
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_gt(self):

        asm_text = """
PUSH1 0x8
PUSH1 0x2
GT
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0, # 2**8 = 256
                            mem_stack(1): 0x0,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0, #  ? 0x00 <s 0xffffff...f0 (-15) => no
                            mem_stack(1): 0,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0, #  ? 0x00 <s 0xffffff...f0 (-15) => no
                            mem_stack(1): 0,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 1, # -3 < -2 ?
                            mem_stack(1): 0x0,
                            mem_stack(2): 0x0,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 1, #  ? 0x00 <s 0xffffff...f0 (-15) => no
                            mem_stack(1): 0,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 1, #  ? 0x00 <s 0xffffff...f0 (-15) => no
                            mem_stack(1): 0,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0, # -3 < -2 ?
                            mem_stack(1): 0x0,
                            mem_stack(2): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_eq(self):

        asm_text = """
PUSH1 0x1234
PUSH1 0x1234
EQ
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 1,
                            mem_stack(1): 0,
                            SP: SP_pos(1)
                          }
                        )

        asm_text = """
PUSH1 0x1234
PUSH1 0x4444
EQ
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0,
                            mem_stack(1): 0,
                            SP: SP_pos(1)
                          }
                        )


    def test_iszero(self):

        asm_text = """
PUSH1 0x00
ISZERO
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 1,
                            SP: SP_pos(1)
                          }
                        )

        asm_text = """
PUSH1 0x01
ISZERO
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0,
                            SP: SP_pos(1)
                          }
                        )

    def test_and(self):

        asm_text = """
PUSH1 0xF3
PUSH1 0x0F
AND
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x03,
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_or(self):

        asm_text = """
PUSH1 0xF3
PUSH1 0x0F
OR
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0xff,
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_xor(self):

        asm_text = """
PUSH1 0xF0
PUSH1 0xFF
XOR
"""
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x0F,
                            mem_stack(1): 0x0,
                            SP: SP_pos(1)
                          }
                        )

    def test_not(self):

        asm_text = """
PUSH1 0x%x
NOT
"""% (2**256-1)
        res,_ = compute_text(asm_text)
        print res
        self.assertEqual(res,
                         {
                            mem_stack(0): 0,
                            SP: SP_pos(1)
                          }
                        )

    def test_byte(self):

        asm_text = """
PUSH1 0x1234
PUSH1 0x1
BYTE
"""
        res,_ = compute_text(asm_text)
        print res
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x12, # TODO : check Little or big endian ??
                            SP: SP_pos(1)
                          }
                        )

    def test_jump(self):

        asm_text = """
PUSH1 0x7
JUMP
PUSH1 0x42
PUSH1 0xff
JUMPDEST
"""
        res,_ = compute_text_bytecode(asm_text)

        self.assertEqual(res,
                         {
                            mem_stack(0): 0x0,
                          }
                        )


    def test_jump2(self):

        asm_text = """
PUSH1 0x5
JUMP
PUSH1 0x01
PUSH1 0x02
PUSH1 0x03
"""
        res,_ = compute_text_bytecode(asm_text)

        self.assertEqual(res,
                         {
                            mem_stack(1): 0x03,
                            mem_stack(0): 0x02,
                            SP: SP_pos(2),
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
        res,_ = compute_text_bytecode(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(1): 0x00,
                            mem_stack(0): 0x00,
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
        res,_ = compute_text(asm_text)
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x42,
                            SP: SP_pos(1)
                          }
                        )

    def test_jumpi_sem(self):

        asm_text = """
CALLDATASIZE
ISZERO
PUSH1 0x07
JUMPI
PUSH1 0x01
PUSH1 0x02
"""
        res,_ = compute_text_bytecode(asm_text)
        print res
        return
        self.assertEqual(res,
                         {
                            mem_stack(0): 0x42,
                            SP: SP_pos(1)
                          }
                        )

    def test_pop(self):
        asm_text = """
PUSH1 0x07
POP
"""
        res, sb = compute_text(asm_text)

        self.assertEqual(res,
                         {
                            mem_stack(0): 0x00,
                          }
                        )


###################################
# Tests with the blockchain
###################################

    def test_address(self):
        asm_text = """
ADDRESS
"""
        res,_ = compute_text(asm_text, {SP: 0, R_ADDRESS: 0x4f35f119145b8d599d2b70b37c73086f71cd416b })

        self.assertEqual(res,
                         {
                            mem_stack(0): 0x4f35f119145b8d599d2b70b37c73086f71cd416b,
                            R_ADDRESS: 0x4f35f119145b8d599d2b70b37c73086f71cd416b,
                            SP: SP_pos(1)
                          }
                        )

    def test_balance(self):
        asm_text = """
PUSH32 0x4f35f119145b8d599d2b70b37c73086f71cd416b
BALANCE
"""
        # Random ethereum account https://etherscan.io/address/0x4f35f119145b8d599d2b70b37c73086f71cd416b

        res,_ = compute_text(asm_text)

        self.assertEqual(res,
                         {
                            mem_stack(0): int(1.50390625e+21),
                            SP: SP_pos(1)
                          }
                        )

    def test_origin(self):
        asm_text = """
ORIGIN
"""
        res,_ = compute_text(asm_text, {SP: 0, R_ORIGIN: 0x4f35f119145b8d599d2b70b37c73086f71cd416b })

        self.assertEqual(res,
                         {
                            mem_stack(0): 0x4f35f119145b8d599d2b70b37c73086f71cd416b,
                            R_ORIGIN: 0x4f35f119145b8d599d2b70b37c73086f71cd416b,
                            SP: SP_pos(1)
                          }
                        )

    def test_caller(self):
        asm_text = """
CALLER
"""
        res,_ = compute_text(asm_text, {SP: 0, R_CALLER: 0x4f35f119145b8d599d2b70b37c73086f71cd416b })

        self.assertEqual(res,
                         {
                            mem_stack(0): 0x4f35f119145b8d599d2b70b37c73086f71cd416b,
                            R_CALLER: 0x4f35f119145b8d599d2b70b37c73086f71cd416b,
                            SP: SP_pos(1)
                          }
                        )

    def test_callvalue(self):
        asm_text = """
CALLVALUE
"""
        res,_ = compute_text(asm_text, {SP: 0, R_CALLVALUE: 0x1337 })

        self.assertEqual(res,
                         {
                            mem_stack(0): 0x1337,
                            R_CALLVALUE: 0x1337,
                            SP: SP_pos(1)
                          }
                        )

    def test_calldataload(self):
        """
        TODO !
        """
        asm_text = """
PUSH1 0x0
CALLDATALOAD
"""

        # User data input is at MEM_BASE_CALLDATA address
        symb_call = calldata_sem.set("\x01"+"\x00"*31)
        res, sb = compute_text(asm_text, symb_call)



        symbols = sb.symbols
        self.assertEqual(symbols[mem_stack(0)], ExprInt(0x01,256))
        self.assertEqual(symbols[SP], ExprInt(SP_pos(1), 256))


        asm_text = """
PUSH1 0x01
CALLDATALOAD
"""
        symb_call = calldata_sem.set("\x01"+"\x02"+ "\x00"*31)
        # User data input is at MEM_BASE_CALLDATA address
        res, sb = compute_text(asm_text, symb_call)


        symbols = sb.symbols
        self.assertEqual(symbols[mem_stack(0)], ExprInt(0x02, 256))
        self.assertEqual(symbols[SP], ExprInt(SP_pos(1), 256))


    def test_calldatasize(self):
        asm_text = """
CALLDATASIZE
"""
        # User data input is at MEM_BASE_CALLDATA address
        res,_ = compute_text(asm_text, {SP: 0 , R_CALLDATASIZE: 0x12})

        self.assertEqual(res,
                         {
                            mem_stack(0): 0x12,
                            R_CALLDATASIZE: 0x12,
                            SP: SP_pos(1)
                          }
                        )


    def test_calldatacopy(self):
        """
        TODO !
        """

        asm_text = """
PUSH1 0x1
PUSH1 0x1
PUSH1 0x0
CALLDATACOPY
"""
        symb_call = calldata_sem.set("\x01"+"\x02"+ "\x00"*31)
        res, sb = compute_text(asm_text, symb_call)

        symbols = sb.symbols
        print sb.dump_mem()
        
        self.assertEqual(symbols[mem_memory(0)], ExprInt(0x01,8))
        self.assertEqual(symbols[SP], ExprInt(SP_pos(1), 256))


    def test_extcodesize(self):
        asm_text = """
PUSH32 0x7011f3edc7fa43c81440f9f43a6458174113b162
EXTCODESIZE
"""
#https://etherscan.io/address/0x7011f3edc7fa43c81440f9f43a6458174113b162

        res,_ = compute_text(asm_text)
        print res

        self.assertEqual(res,
                         {
                            mem_stack(0): 3238,
                            SP: SP_pos(1)
                          }
                        )


    def test_extcodecopy(self):
        asm_text = """
PUSH32 0x7011f3edc7fa43c81440f9f43a6458174113b162

EXTCODECOPY
"""
#https://etherscan.io/address/0x7011f3edc7fa43c81440f9f43a6458174113b162

        res,_ = compute_text(asm_text)
        print res

        self.assertEqual(res,
                         {
                            mem_stack(0): 3238,
                            SP: SP_pos(1)
                          }
                        )


    def test_mstore(self):
        asm_text = """
PUSH1 0x10
PUSH1 0x1
MSTORE8
"""


        res,sb = compute_text(asm_text)
        symbols = sb.symbols
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(1,256),8)], ExprInt(0x10,8))

        asm_text = """
PUSH1 0x11
PUSH1 0x0
MSTORE8
"""


        res,sb = compute_text(asm_text)
        symbols = sb.symbols
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256),8)], ExprInt(0x11,8))

        asm_text = """
PUSH32 0x0011223344556677
PUSH1 0x0
MSTORE
"""


        res,sb = compute_text(asm_text)
        symbols = sb.symbols
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256),8)], ExprInt(0x77,8))
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(1,256),8)], ExprInt(0x66,8))
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(2,256),8)], ExprInt(0x55,8))
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(3,256),8)], ExprInt(0x44,8))
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(4,256),8)], ExprInt(0x33,8))
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(5,256),8)], ExprInt(0x22,8))
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(6,256),8)], ExprInt(0x11,8))
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(7,256),8)], ExprInt(0x00,8))

        asm_text = """
PUSH2 0xBABE
PUSH1 0x0
MSTORE
PUSH2 0xCA
PUSH1 0x1
MSTORE
"""


        res,sb = compute_text(asm_text)
        symbols = sb.symbols

        self.assertEqual(symbols[ExprMem(ExprId("MEM",256),8)], ExprInt(0xBE,8))
        self.assertEqual(symbols[ExprMem(ExprId("MEM",256)+ExprInt(1,256),8)], ExprInt(0xCA,8))


if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestEVMSemantic)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))