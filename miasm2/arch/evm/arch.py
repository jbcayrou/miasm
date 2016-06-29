#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""
Implementation of Ethereum EVM architecture
Doc : http://gavwood.com/paper.pdf
"""

import logging

from pyparsing import *
from miasm2.core.cpu import *
from miasm2.expression.expression import *
from collections import defaultdict
import miasm2.arch.evm.regs as regs_module
from miasm2.arch.evm.regs import *
from miasm2.core.asmbloc import asm_label


log = logging.getLogger("evmdis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)



# For text assembly parsing.
# Parameters have 256 bits
def ast_id2expr(a):
    return m2_expr.ExprId(a, 256)

def ast_int2expr(a):
    return m2_expr.ExprInt256(a)

my_var_parser = parse_ast(ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)


class instruction_evm(instruction):
    """
    Ethereum EVM instruction
    """
    delayslot = 0
    offset = 0 # By default the offset to zero
    l = 15 # By default need a size

    def __init__(self, *args, **kargs):
        super(instruction_evm, self).__init__(*args, **kargs)

    @staticmethod
    def arg2str(e, pos = None):
        """
        Return a string representation of the argument.

        Need to be implemented.
        """

        return e

    def breakflow(self):
        """
        Check if the instruction break the desasembly flow.

        Need to be implemented.
        """

        return self.name in ['CALL', 'JUMP','JUMPI', 'SUICIDE', 'STOP']

    def splitflow(self):
        """
        When the instruciton break check here if we could continue.
        At this time we only know one of the JUMPI instr.
        Other destination resolution are done in disas.py file by checking the stack

        Need to be implemented.
        """
        return self.name in ['JUMPI']

    def dstflow(self):
        """
        Because JUMP
        """
        return False

    """
    def getdstflow(self, symbol_pool):
        return

    def dstflow2label(self, symbol_pool):
        return "test"
    """
    def is_subcall(self):
        return self.name in ["CALL"]

    def fixDstOffset(self):
        print "fixDstOFfset"


class additional_info:

    def __init__(self):
        self.except_on_instr = False


class mn_evm(cls_mn):
    """
    Ethereum EVM mnemo class
    """

    name = "evm"
    bintree = {}
    regs = regs_module
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    pc = PC
    sp = SP
    delayslot = 0  # unit is instruction instruction
    instruction = instruction_evm

    def additional_info(self):
        """
        Additional information to attach to the current instruction

        Need to be implemented.
        """

        info = additional_info()
        return info

    @classmethod
    def getmn(cls, name):
        """
        Return the mnemo name in upper case
        """

        return name.upper()

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        """
        Need to be implemented.
        """

        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    @classmethod
    def getpc(cls, attrib):
        """
        Return the program counter register.

        Need to be implemented.
        """

        return PC

    @classmethod
    def getsp(cls, attrib):
        """
        Return the stack pointer register.

        Need to be implemented.
        """

        return SP


class evm_imm256(imm_noarg, m_arg):
    """
    Class to store PUSHX argument
    """
    parser = base_expr
    intsize = 256

    def int2expr(self, v):
        if v & ~self.intmask != 0:
            return None
        return ExprInt(v, self.intsize)

    def decode(self, v):
        self.expr = ExprInt256(v)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        self.value = self.expr.arg.arg
        return True


def addop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_evm,), dct)



# Stop and Arithmetic Operations

addop("stop",          [bs8(0x00)])
addop("add",           [bs8(0x01)])
addop("mul",           [bs8(0x02)])
addop("sub",           [bs8(0x03)])
addop("div",           [bs8(0x04)])
addop("sdiv",          [bs8(0x05)])
addop("mod",           [bs8(0x06)])
addop("smod",          [bs8(0x07)])
addop("addmod",        [bs8(0x08)])
addop("mulmod",        [bs8(0x09)])
addop("exp",           [bs8(0x0a)])
addop("sigextend",     [bs8(0x0b)])
addop("lt",            [bs8(0x10)])
addop("gt",            [bs8(0x11)])
addop("slt",           [bs8(0x12)])
addop("sgt",           [bs8(0x13)])
addop("eq",            [bs8(0x14)])
addop("iszero",        [bs8(0x15)])
addop("and",           [bs8(0x16)])
addop("or",            [bs8(0x17)])
addop("xor",           [bs8(0x18)])
addop("not",           [bs8(0x19)])
addop("byte",          [bs8(0x1a)])

#  SHA3

addop("sha3",          [bs8(0x20)])

# Environmental Information

addop("address",       [bs8(0x30)])
addop("balance",       [bs8(0x31)])
addop("origin",        [bs8(0x32)])
addop("caller",        [bs8(0x33)])
addop("callvalue",     [bs8(0x34)])
addop("calldataload",  [bs8(0x35)])
addop("calldatasize",  [bs8(0x36)])
addop("calldatacopy",  [bs8(0x37)])
addop("codesize",      [bs8(0x38)])
addop("codecopy",      [bs8(0x39)])
addop("gasprice",      [bs8(0x3a)])
addop("extcodesize",   [bs8(0x3b)])
addop("extcodecopy",   [bs8(0x3c)])

# Block Information
addop("blockhash",     [bs8(0x40)])
addop("coinbase",      [bs8(0x41)])
addop("timestamp",     [bs8(0x42)])
addop("number",        [bs8(0x43)])
addop("difficulty",    [bs8(0x44)])
addop("gaslimit",      [bs8(0x45)])

#Stack, Memory, Storage and Flow Operation
addop("pop",           [bs8(0x50)])
addop("mload",         [bs8(0x51)])
addop("mstore",        [bs8(0x52)])
addop("mstore8",       [bs8(0x53)])
addop("sload",         [bs8(0x54)])
addop("sstore",        [bs8(0x55)])
addop("jump",          [bs8(0x56)])
addop("jumpi",         [bs8(0x57)])
addop("pc",            [bs8(0x58)])
addop("msize",         [bs8(0x59)])
addop("gas",           [bs8(0x5a)])
addop("jumpdest",      [bs8(0x5b)])

def gen_op_nargs(name, start_opcode, start, end):
    for i in xrange(start, end+1):
        addop("%s%d"%(name, i), [bs8(start_opcode+i-1), bs(l=8*i, cls=(evm_imm256,))])

def gen_op(name, start_opcode, start, end):
    for i in xrange(start, end+1):
        addop("%s%d"%(name,i), [bs8(start_opcode+i-1)])

# Push operations (PUSH1 -> PUSH32)
gen_op_nargs("push",0x60, 1, 32)

# Duplication Operations (DUP1 -> DUP16)
gen_op("dup",0x80, 1, 16)

# Exchange Operations (SWAP1 -> SWAP16)
gen_op("swap",0x90, 1, 16)

#LOG
gen_op("log",0xa0, 1, 4)

# System operations
addop("create",      [bs8(0xf0)])
addop("call",        [bs8(0xf1)])
addop("callcode",    [bs8(0xf2)])
addop("return",      [bs8(0xf3)])
addop("delegatecall",[bs8(0xf4)])
addop("suicide",     [bs8(0xf5)])
addop("callcode",    [bs8(0xf2)])
