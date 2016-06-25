#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""
Implementation of sementic instructions.
"""

from miasm2.expression.expression import *
from miasm2.arch.evm.regs import *
from miasm2.arch.evm.arch import mn_evm
from miasm2.ir.ir import ir

SIZE_WORD = 256

def op_push(ir, instr, a):
    e = []

    e.append(ExprAff(ExprMem(SP , SIZE_WORD), a.zeroExtend(SIZE_WORD)))
    e.append(ExprAff(SP, SP + ExprInt256(1*SIZE_WORD)))

    return e, []

def op_dup(ir, instr, element_id):
    e = []
    toto = element_id

    elem_to_dup = ExprMem(SP - ExprInt256( element_id *SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP, SIZE_WORD), elem_to_dup))
    e.append(ExprAff(SP, SP + ExprInt256(1*SIZE_WORD)))

    return e, []

def op_log(ir, instr, num_topic):
    
    e = []
    logs = ""

    for i in xrange(2,num_topic+2):
        logs += str(ExprMem(SP - ExprInt256(i*SIZE_WORD)))
    print "LOG[%d]" % num_topic
    
    e.append(ExprAff(SP, SP - ExprInt256((num_topic+2)*SIZE_WORD)))
    
    return e, []

def op_swap(ir, instr, element_id):

    e = []

    arg1 = ExprMem(SP - ExprInt256((element_id+1) * SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(1 * SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(arg1, arg2))
    e.append(ExprAff(arg2, arg1))

    return e, []


def op_add(ir, isntr):
    """
    SP[O] = SP[0] + SP[1]
    """
    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('+', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_mul(ir, isntr):
    """
    SP[O] = SP[0] * SP[1]
    """
    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('*', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_sub(ir, isntr):
    """
    SP[O] = SP[0] - SP[1]
    """
    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('-', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_div(ir, isntr):
    """
    SP[O] = SP[0] / SP[1]
    """
    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    res = ExprCond( ExprOp("==",arg1, ExprInt256(0)),
                    ExprInt256(0),
                    ExprOp("/", arg1, arg2) )

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), res))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]


def op_sdiv(ir, isntr):
    """
    SP[O] = SP[0] /. SP[1]
    """
    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    res = ExprCond( ExprOp("==",arg1, ExprInt256(0)),
                    ExprInt256(0),
                    ExprOp("/", arg1, arg2) )

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), res.signExtend))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

def op_mod(ir, instr):

    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    res = ExprCond( ExprOp("==",arg1, ExprInt256(0)),
                    ExprInt256(0),
                    ExprOp("%", arg1, arg2) )
    
    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), res))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_smod(ir, instr):

    raise Exception("smod to implement ...")

    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    res = ExprCond( ExprOp("==",arg1, ExprInt256(0)),
                    ExprInt256(0),
                    ExprOp("%", arg1, arg2) )

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), res))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_addmod(ir, instr):

    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)



    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('%', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_exp(ir, instr):
    """
    Exponential operation
    """
    e = []

    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('pow', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_lt(ir, instr):
    """
    Less-than comparison
    """
    e = []

    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('<', arg1, arg2).zeroExtend(256)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_gt(ir, instr):
    """
    Greater-than comparison
    """
    e = []

    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('>', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_slt(ir, instr):
    """
    Signed less-than comparison
    """
    e = []
    raise NotImplementedError('%s' % instr.name)
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('<', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_sgt(ir, instr):
    """
    Signed greather-than comparison
    """
    e = []
    raise NotImplementedError('%s' % instr.name)
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('>', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_eq(ir, instr):
    """
    Equality comparision
    """
    e = []

    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('==', arg1, arg2).zeroExtend(256)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []


def op_iszero(ir, instr):
    """
    Equality comparision
    """
    e = []

    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('==', arg1, ExprInt256(0)).zeroExtend(256)))

    return e, []


def op_and(ir, instr):
    """
    Bitwise AND operation
    """
    e = []

    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg2 = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), ExprOp('&', arg1, arg2)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))


    return e, []

def op_not(ir, instr):
    """
    Bitwise NOT operation
    """
    e = []

    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    arg1 = ~ arg1
    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), arg1))


    return e, []

def op_sha3(ir, instr):
    """
    Compute Keccak-256 block_hash
    """
    e = []

    start = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    stop = ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD)

    stor_mem_id = ExprId("storage_%s_%s" % (start, stop), SIZE_WORD)
    stor_mem = ExprOp("storage",stor_mem_id)

    sha = ExprOp('sha', stor_mem)

    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD), sha.zeroExtend(256)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_jump(ir, instr):
    e = []
    dst_addr = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))

    print dst_addr
    e.append(ExprAff(ir.IRDst, dst_addr))

    return e, []

def op_stop(ir, instr):

    e = []

    return e, []

def op_jumpdest(ir, instr):
    e = []
    # Do nothing, just a label
    return e, []

def undef(ir, instr):
    raise NotImplementedError('%s' % instr.name)


def op_jumpi(ir, instr):
    e = []
    dst_addr = ExprId("dst",256)
    cond = ExprId("cond",256)
    dst_addr = ExprAff( dst_addr, ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD))
    cond = ExprAff( cond, ExprMem(SP - ExprInt256(2*SIZE_WORD), SIZE_WORD))
    new_pc = ExprCond( ExprOp("==", cond, ExprInt256(0)),
                       ir.IRDst + ExprInt256(1),
                       dst_addr )
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    e.append(ExprAff(ir.IRDst, new_pc))

    return e, []

def op_address(ir, instr):
    """
    Get address of currently executing account
    """
    e = []

    e.append(ExprAff(ExprMem(SP , SIZE_WORD), ir.address))
    e.append(ExprAff(SP, SP + ExprInt256(1*SIZE_WORD)))

    return e, []

def op_balance(ir, instr):
    """
    Get balance of currently executing account
    """
    e = []
    arg1 = ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD)

    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), 
                     ExprId("balance_%s"%arg1, SIZE_WORD)))

    return e, []


def op_caller(ir, instr):
    """
    Get caller address
    """
    e = []

    e.append(ExprAff(ExprMem(SP , SIZE_WORD), ir.caller))
    e.append(ExprAff(SP, SP + ExprInt256(1*SIZE_WORD)))

    return e, []

def op_callvalue(ir, instr):
    """
    Get deposited value by the instruction/transaction responsible for this execution
    """
    e = []

    e.append(ExprAff(ExprMem(SP , SIZE_WORD), ir.callvalue))
    e.append(ExprAff(SP, SP + ExprInt256(1*SIZE_WORD)))

    return e, []

def op_calldata(ir, instr):
    """
    Get input data in current environment to memory
    """
    e = []
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ir.calldata))

    return e, []


def op_calldatasize(ir, instr):
    """
    Get size of input data in current environment to memory
    """
    e = []

    return e, []

def op_sload(ir, instr):
    """
    Load word from storage
    """
    e = []

    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD),
                     ExprId("storage_%s" % ExprMem(SP , SIZE_WORD), SIZE_WORD))
            )

    return e, []

def op_mstore(ir, instr):
    """
    Load word from storage
    """
    e = []

    print "TODO  mstore"

    return e, []

def op_call(ir, instr):
    """
    Message-call into an account
    """
    e = []
    print "TO IMPLEMENT ! " 
    return e, []

def op_blockhash(ir, instr):
    """
    Get the block's number
    """
    e = []
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ir.block_hash))

    return e, []

def op_number(ir, instr):
    """
    Get the block's number
    """
    e = []
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ir.block_number))

    return e, []

def op_timestamp(ir, instr):
    """
    Get the block's timestamp
    """
    e = []
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD), SIZE_WORD), ir.block_timestamp))

    return e, []


mnemo_func = {
    "STOP"         : op_stop,
    "ADD"          : op_add,
    "MUL"          : op_mul,
    "SUB"          : op_sub,
    "DIV"          : op_div,
    "SDIV"         : op_sdiv,
    "MOD"          : op_mod,
    "ADDMOD"       : undef,
    "MULMOD"       : undef,
    "EXP"          : op_exp,
    "SIGNEXTEND"   : undef,
    "LT"           : op_lt,
    "GT"           : op_gt,
    "SLT"          : op_slt,
    "SGT"          : op_sgt,
    "EQ"           : op_eq,
    "ISZERO"       : op_iszero,
    "AND"          : op_and,
    "OR"           : undef,
    "XOR"          : undef,
    "NOT"          : op_not,
    "BYTE"         : undef,

    "SHA3"         : op_sha3,
    "ADDRESS"      : op_address,
    "BALANCE"      : op_balance,
    "ORIGIN"       : undef,
    "CALLER"       : op_caller,
    "CALLVALUE"    : op_callvalue,
    "CALLDATALOAD" : op_calldata,
    "CALLDATASIZE" : op_calldatasize,
    "CALLDATACOPY" : undef,
    "CODESIZE"     : undef,
    "CODECOPY"     : undef,
    "GASPRICE"     : undef,
    "EXTCODESIZE"  : undef,
    "EXTCODECOPY"  : undef,

    "BLOCKHASH"    : op_blockhash,
    "COINBASE"     : undef,
    "TIMESTAMP"    : op_timestamp,
    "NUMBER"       : op_number,
    "DIFFICULTY"   : undef,
    "GASLIMIT"     : undef,

    "POP"          : undef,
    "MLOAD"        : undef,
    "MSTORE"       : op_mstore,
    "MSTORES"      : undef,
    "SLOAD"        : op_sload,
    "SSTORE"       : undef,
    "JUMP"         : op_jump,
    "JUMPI"        : op_jumpi,
    "PC"           : undef,
    "MSIZE"        : undef,
    "GAS"          : undef,
    "JUMPDEST"     : op_jumpdest,

    # PUSH are defined bellow

    # DUP are defined bellow

    # SWAP are defined bellow

    # LOG are defined bellow

    "CREATE"        : undef,
    "CALL"          : op_call,
    "CALLCODE"      : undef,
    "RETURN"        : undef,
    "DELEGATECALL"  : undef,
    "SUICIDE"       : undef,

}

import copy

for i in xrange(1, 33):
    mnemo_func["PUSH%d"%i] = op_push

for i in range(1, 17):
    mnemo_func["DUP%d"%i] = lambda ir, instr,element_id=i : op_dup(ir, instr, element_id)

for i in xrange(1, 17):
    mnemo_func["SWAP%d"%i] = lambda ir, instr,element_id=i : op_swap(ir, instr, element_id)

for i in xrange(0, 5):
    mnemo_func["LOG%d"%i] = lambda ir, instr, num_topic=i : op_log(ir, instr, num_topic)


class ir_evm(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_evm, None, symbol_pool)
        self.pc = PC
        self.sp = SP
        self.gas = GAS
        self.IRDst = ExprId('IRDst', 256)

        self.callvalue = R_CALLVALUE
        self.caller = R_CALLER
        self.address = R_ADDRESS
        self.calldata = R_CALLDATA

        self.block_number = R_BLOCK_NUMBER
        self.block_hash = R_BLOCK_HASH
        self.block_timestamp = R_BLOCK_TIMESTAMP

    def mod_pc(self, instr, instr_ir, extra_ir):
        pass

    def get_ir(self, instr):
        #print instr#, args

        args = instr.args
        instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)

        return instr_ir, extra_ir