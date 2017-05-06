#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""
Implementation of semantic instructions.
"""

from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp
from miasm2.expression.simplifications_cond import ExprOp_inf_signed, ExprOp_inf_unsigned, ExprOp_equal
from miasm2.arch.evm.regs import *
from miasm2.arch.evm.arch import mn_evm
from miasm2.ir.ir import IntermediateRepresentation
from miasm2.arch.evm.env import *

SIZE_WORD = 256
MEM_BASE_CALLDATA = 0xffff0000 # Base address where are store the input data.


class EvmCallDataSem:
    prefix = ExprId("CALLDATA",256)

    def copy_to_expr256(self, src_addr, dst_expr):
        """
        Read 32 bytes of CALLDATA from src_addr and copy them into dst_expr (256 bits)
        """
        e = []
        total = ExprInt(0,256)

        for i in xrange(0,32):
            expr_i = ExprInt(i,256)
            
            tmp_e = ExprMem(self.prefix + src_addr + expr_i, 8).zeroExtend(256) << (expr_i*ExprInt(8,256))
            total = total | tmp_e

        e.append(ExprAff(dst_expr, total))

        return e

    def set(self, data, offset=0):
        """
        To set calldata to a specific value.
        This function can be used for symb pool initialization 

        Example :
            symb_calldata = calldata_sem.set("HELLO")
            symb = machine.mn.regs.regs_init
            symb.update(symb_calldata)
            sb = symbexec(ira, symb)
        """

        mem = {}
        start = 0
        if offset == 0: # Should not add +0x0 
            val = ExprInt(ord(data[0]),8)
            mem[ExprMem(ExprId("CALLDATA",256), 8)]= val
            start = 1
        
        size = len(data)

        for i in xrange(start, size):
            val = ExprInt(ord(data[i]),8)
            mem[ExprMem(ExprId("CALLDATA",256)+ExprInt(i+offset,256), 8)] = val

        return mem


class EvmMemSem:
    prefix = ExprId("MEM",256)

    def memory_to_expr256(self, src_addr, dst_expr):
        """
        Read 32 bytes of MEM from src_addr and copy them into dst_expr (256 bits)
        """
        e = []
        total = ExprInt(0,256)

        for i in xrange(0,32):
            expr_i = ExprInt(i,256)
            
            tmp_e = ExprMem(self.prefix + (src_addr + expr_i), 8).zeroExtend(256)<< (expr_i*ExprInt(8,256))
            total = total + tmp_e

        e.append(ExprAff(dst_expr, total))


        return e

    def store(self, src_addr, value_expr):
        e = []
        for i in xrange(0,32):
            expr_i = ExprInt(i,256)
            e.append(ExprAff(ExprMem(self.prefix + (src_addr + expr_i), 8), value_expr[i*8: (i+1)*8]))
        return e

    def store8(self, src_addr, value_expr):
        e = []
        tmp = value_expr % ExprInt(256,256)

        e.append(ExprAff(ExprMem(self.prefix + src_addr, 8), tmp[0:8]))
        return e

class EvmStorageSem:
    prefix = ExprId("STORAGE",256)

    def storage_to_expr256(self, src_addr_expr, dst_expr):
        """
        Read 32 bytes of MEM from src_addr and copy them into dst_expr (256 bits)
        """
        e = []
        e.append(ExprAff(dst_expr, ExprMem(self.prefix + src_addr_expr, 256)))

        return e

    def store(self, addr_expr, value_expr):
        e = []
        e.append(ExprAff(ExprMem(self.prefix + addr_expr, 256),value_expr))

        return e

storage_sem = EvmStorageSem()
calldata_sem = EvmCallDataSem()
mem_sem = EvmMemSem()

def _stack_item(pos):
    """
    SP point to the next element to store.
    The last item pushed is SP - 1
    """ 
    return ExprMem(SP - ExprInt256( (pos +1) * SIZE_WORD), SIZE_WORD)

def _stack_push(item, e):
    e.append(ExprAff(ExprMem(SP, SIZE_WORD), item))
    e.append(ExprAff(SP, SP + ExprInt256(1*SIZE_WORD)))

def _stack_pop(e):
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

def op_push(ir, instr, a):
    e = []

    _stack_push(a,e)

    return e, []

def op_dup(ir, instr, element_id):
    e = []
    toto = element_id

    _stack_push(_stack_item(element_id-1),e)

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


def op_add(ir, irntr):
    """
    SP[O] = SP[0] + SP[1]
    """
    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    e.append(ExprAff(_stack_item(1), ExprOp('+', arg1, arg2)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_mul(ir, isntr):
    """
    SP[O] = SP[0] * SP[1]
    """
    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    e.append(ExprAff(_stack_item(1), ExprOp('*', arg1, arg2)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_sub(ir, isntr):
    """
    SP[O] = SP[0] - SP[1]
    """
    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    e.append(ExprAff(_stack_item(1), ExprOp('-', arg1, arg2)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_div(ir, isntr):
    """
    SP[O] = SP[0] / SP[1] or 0 if SP[1] == 0
    """
    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    res = ExprCond( ExprOp_equal(arg2, ExprInt256(0)),
             ExprInt256(0),
             arg1/arg2
            )

    e.append(ExprAff(_stack_item(1), res) )
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_sdiv(ir, isntr):
    """
    SP[O] = SP[0] /. SP[1]
    """
    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)
    raise Exception("sdiv to implement ...")

    res = ExprCond( ExprOp_equal(arg2, ExprInt256(0)),
                    ExprInt256(0),
                    ExprOp("idiv", arg1, arg2)
                   )

    e.append(ExprAff(_stack_item(1), res))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

def op_mod(ir, instr):

    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    res = ExprCond( arg2,
                    arg1 % arg2,
                    ExprInt256(0))
    
    e.append(ExprAff(_stack_item(1), res))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_smod(ir, instr):
    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    res = ExprCond( ExprOp_equal(arg1, ExprInt256(0)),
                    ExprInt256(0),
                    ExprOp("imod", arg1, arg2)
                   )

    e.append(ExprAff(_stack_item(1), res))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e,[]

def op_addmod(ir, instr):

    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)
    arg3 = _stack_item(2)

    res = ExprCond( ExprOp_equal(arg3, ExprInt256(0)),
                    ExprInt256(0),
                    (arg1 + arg2) % arg3
                    )

    e.append(ExprAff(_stack_item(2), res))
    e.append(ExprAff(_stack_item(1), ExprInt256(0)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))

    e.append(ExprAff(SP, SP - ExprInt256(2*SIZE_WORD)))

    return e,[]

def op_mulmod(ir, instr):

    e = []
    arg1 = _stack_item(0)
    arg2 = _stack_item(1)
    arg3 = _stack_item(2)

    res = ExprCond( ExprOp_equal(arg3, ExprInt256(0)),
                    ExprInt256(0),
                    (arg1 * arg2) % arg3
                    )

    e.append(ExprAff(_stack_item(2), res))
    e.append(ExprAff(_stack_item(1), ExprInt256(0)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))

    e.append(ExprAff(SP, SP - ExprInt256(2*SIZE_WORD)))

    return e,[]

def op_exp(ir, instr):
    """
    Exponential operation
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    e.append(ExprAff(_stack_item(1), ExprOp('**', arg1, arg2)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_signextend(ir, instr):
    """
    Extend length of 2 complement signed integer
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    raise Exception("Currently ExprSlice can not take ExprInt :(")

    e.append(ExprAff(_stack_item(1), ExprOp('**', arg1, arg2)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_lt(ir, instr):
    """
    Less-than comparison
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    if compare_exprs(arg1,arg2) == -1:
        res = ExprInt256(1)
    else:
        res =  ExprInt256(0)

    e.append(ExprAff(_stack_item(1), res))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_gt(ir, instr):
    """
    Greater-than comparison
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    if compare_exprs(arg1,arg2) == 1:
        res = ExprInt256(1)
    else:
        res =  ExprInt256(0)

    e.append(ExprAff(_stack_item(1), res))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_slt(ir, instr):
    """
    Signed less-than comparison
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    res = ExprOp_inf_signed(arg1, arg2).zeroExtend(256)

    e.append(ExprAff(_stack_item(1), res))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))

    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_sgt(ir, instr):
    """
    Signed greather-than comparison
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    res = ExprOp_inf_signed(arg2, arg1).zeroExtend(256)

    e.append(ExprAff(_stack_item(1), res))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))

    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_eq(ir, instr):
    """
    Equality comparision
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    res = ExprOp_equal(arg2, arg1).zeroExtend(256)

    e.append(ExprAff(_stack_item(1), res))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []


def op_iszero(ir, instr):
    """
    Equality comparision
    """
    e = []
    arg1 = _stack_item(0)

    res = ExprOp_equal(arg1, ExprInt256(0)).zeroExtend(256)
    e.append(ExprAff(_stack_item(0), res))

    return e, []


def op_and(ir, instr):
    """
    Bitwise AND operation
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    e.append(ExprAff(_stack_item(1), ExprOp('&', arg1, arg2)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_or(ir, instr):
    """
    Bitwise OR operation
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    e.append(ExprAff(_stack_item(1), ExprOp('|', arg1, arg2)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_xor(ir, instr):
    """
    Bitwise XOR operation
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    e.append(ExprAff(_stack_item(1), ExprOp('^', arg1, arg2)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_not(ir, instr):
    """
    Bitwise NOT operation
    """
    e = []

    e.append(ExprAff(_stack_item(0), ~ _stack_item(0)))


    return e, []

def op_byte(ir, instr):
    """
    Retrieve single byte from word

    Currently Slice can not take ExprInt :(
    """
    e = []

    arg1 = _stack_item(0)
    arg2 = _stack_item(1)

    raise Exception("Currently ExprSlice can not take ExprInt :(")

    res = ExprSlice(arg2, arg2, arg1 + ExprInt256(8))

    e.append(ExprAff(_stack_item(1), res ))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_sha3(ir, instr):
    """
    Compute Keccak-256 block_hash
    """
    e = []

    start = _stack_item(0)
    stop = _stack_item(1)

    stor_mem_id = ExprId("storage_%s_%s" % (start, stop), SIZE_WORD)
    stor_mem = ExprOp("storage",stor_mem_id)

    sha = ExprOp('sha', stor_mem)

    e.append(ExprAff(_stack_item(1), sha.zeroExtend(256)))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))
    return e, []

def op_jump(ir, instr):
    e = []

    dst_addr = _stack_item(0)

    e.append(ExprAff(ir.IRDst, dst_addr))
    e.append(ExprAff(PC, dst_addr))
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

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
    """
    Conditionnal jump.
    Jump if stack[0] == 0 else PC++
    """

    e = []

    dst_addr = _stack_item(0)
    cond = _stack_item(1)

    new_pc = ExprCond( cond,
                       dst_addr,
                       ir.IRDst + ExprInt256(1)  # if 0
                       )

    e.append(ExprAff(ir.IRDst, new_pc))
    e.append(ExprAff(ir.pc, new_pc))

    # Set zero in the two first stack elements
    e.append(ExprAff(_stack_item(0), ExprInt256(0)))
    e.append(ExprAff(_stack_item(1), ExprInt256(0)))
    # SP = SP - 2
    e.append(ExprAff(SP, SP - ExprInt256(2*SIZE_WORD)))


    return e, []

def op_address(ir, instr):
    """
    Get address of currently executing account
    """
    e = []

    _stack_push(ir.address, e)

    return e, []

def op_origin(ir, instr):
    """
    Get execution origination address.
    """
    e = []

    _stack_push(ir.origin, e)

    return e, []

def op_balance(ir, instr):
    """
    Get balance of currently executing account.
    """
    e = []
    arg1 = _stack_item(0)

    v = ExprOp("evm_balance", arg1)
    e.append(ExprAff(_stack_item(0), v))

    return e, []


def op_caller(ir, instr):
    """
    Get caller address
    """
    e = []

    _stack_push(ir.caller, e)

    return e, []

def op_callvalue(ir, instr):
    """
    Get deposited value by the instruction/transaction responsible for this execution
    """
    e = []

    _stack_push(ir.callvalue, e)

    return e, []

def op_calldata(ir, instr):
    """
    Get input data in current environment to memory
    """
    e = []


    e = calldata_sem.copy_to_expr256(_stack_item(0), _stack_item(0))
    #e.append(ExprAff(_stack_item(0), ExprMem(ExprInt256(MEM_BASE_CALLDATA * SIZE_WORD)+arg * ExprInt256(SIZE_WORD), SIZE_WORD)))

    return e, []


def op_calldatasize(ir, instr):
    """
    Get size of input data in current environment to memory
    """
    e = []

    _stack_push(ir.calldatasize, e)

    return e, []

def op_calldatacopy(ir, instr):
    """
    Copy input data in current environment to memory
    """
    warnings.warn('EVM WARNING: CALLDATACOPY not implemented')
    e = []
    """


    mem_addr = _stack_item(0)
    call_off = _stack_item(1)
    size = _stack_item(2)

    for i in xrange(0, size.arg):
        i_expr = ExprInt(i, 256)

        tmp_e = ExprAff(ExprMem(mem_sem.prefix + i_expr, 8), ExprMem(calldata_sem.prefix + call_off + i_expr))
        e.append(tmp_e)

    e.append(ExprAff(SP, SP - ExprInt256(3*SIZE_WORD)))

    """
    return e, []

def op_call(ir, instr):
    """
    Message-call into an account
    """
    e = []
    print "TO IMPLEMENT ! " 
    return e, []

def op_extcodesize(ir, instr):
    """
    Load word from storage
    """
    e = []

    e.append(ExprAff(_stack_item(0), ExprOp("evm_extcodesize", _stack_item(0))))

    return e, []

def op_extcodecopy(ir, instr):
    """
    Copy an account's code to memory.
    """
    e = []

    e.append(ExprOp("evm_extcodecopy", _stack_item(0),_stack_item(1),_stack_item(2),_stack_item(3)))
    e.append(ExprAff(SP, SP - ExprInt256(4*SIZE_WORD)))

    return e, []

def op_blockhash(ir, instr):
    """
    Get the block's number
    """
    e = []

    _stack_push(ir.block_hash, e)

    return e, []

def op_number(ir, instr):
    """
    Get the block's number
    """
    e = []

    _stack_push(ir.block_number, e)

    return e, []

def op_pop(ir, instr):
    """
    Remove item from stack
    """
    e = []

    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD),SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_mload(ir, instr):
    """
    Load word from memory
    """

    e = []
    e = mem_sem.memory_to_expr256( _stack_item(0),  _stack_item(0))

    return e, []

def op_mstore(ir, instr):
    """
    Save word to memory
    """
    e = mem_sem.store( _stack_item(0),  _stack_item(1))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD),SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD),SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(2*SIZE_WORD)))
    return e, []

def op_mstore8(ir, instr):
    """
    Save byte to memory
    """
    e = mem_sem.store8( _stack_item(0),  _stack_item(1))
    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD),SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(ExprMem(SP - ExprInt256(2*SIZE_WORD),SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(2*SIZE_WORD)))
    return e, []

def op_sload(ir, instr):
    """
    Load word from storage
    """
    e = []
    e = storage_sem.storage_to_expr256(_stack_item(0),  _stack_item(0))

    return e, []

def op_sstore(ir, instr):
    """
    Save word to memory
    """
    e = []
    e = storage_sem.store(_stack_item(0),  _stack_item(1))
    e.append(ExprAff(SP, SP - ExprInt256(2*SIZE_WORD)))

    return e, []


def op_timestamp(ir, instr):
    """
    Get the block's timestamp
    """
    e = []
    _stack_push(ir.block_timestamp, e)

    return e, []

def op_gas(ir, instr):
    """
    Get the amount of available gas,including the corresponding reduction for the cost of this instruction.
    """
    e = []
    _stack_push(ir.gas, e)
    return e, []
#mnemo_func = sbuild.functions

mnemo_func = {
#mnemo_func.update({
    "STOP"         : op_stop,
    "ADD"          : op_add,
    "MUL"          : op_mul,
    "SUB"          : op_sub,
    "DIV"          : op_div,
    "SDIV"         : op_sdiv,
    "MOD"          : op_mod,
    "ADDMOD"       : op_addmod,
    "MULMOD"       : op_mulmod,
    "EXP"          : op_exp,
    "SIGNEXTEND"   : op_signextend,
    "LT"           : op_lt,
    "GT"           : op_gt,
    "SLT"          : op_slt,
    "SGT"          : op_sgt,
    "EQ"           : op_eq,
    "ISZERO"       : op_iszero,
    "AND"          : op_and,
    "OR"           : op_or,
    "XOR"          : op_xor,
    "NOT"          : op_not,
    "BYTE"         : op_byte,

    "SHA3"         : op_sha3,
    "ADDRESS"      : op_address,
    "BALANCE"      : op_balance,
    "ORIGIN"       : op_origin,
    "CALLER"       : op_caller,
    "CALLVALUE"    : op_callvalue,
    "CALLDATALOAD" : op_calldata,
    "CALLDATASIZE" : op_calldatasize,
    "CALLDATACOPY" : op_calldatacopy,
    "CODESIZE"     : undef,
    "CODECOPY"     : undef,
    "GASPRICE"     : undef,
    "EXTCODESIZE"  : op_extcodesize,
    "EXTCODECOPY"  : op_extcodecopy,

    "BLOCKHASH"    : op_blockhash,
    "COINBASE"     : undef,
    "TIMESTAMP"    : op_timestamp,
    "NUMBER"       : op_number,
    "DIFFICULTY"   : undef,
    "GASLIMIT"     : undef,

    "POP"          : op_pop,
    "MLOAD"        : op_mload,
    "MSTORE"       : op_mstore,
    "MSTORE8"      : op_mstore8,
    "SLOAD"        : op_sload,
    "SSTORE"       : op_sstore,
    "JUMP"         : op_jump,
    "JUMPI"        : op_jumpi,
    "PC"           : undef,
    "MSIZE"        : undef,
    "GAS"          : op_gas,
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

#})
}

for i in xrange(1, 33):
    mnemo_func["PUSH%d"%i] = op_push

for i in range(1, 17):
    mnemo_func["DUP%d"%i] = lambda ir, instr,element_id=i : op_dup(ir, instr, element_id)

for i in xrange(1, 17):
    mnemo_func["SWAP%d"%i] = lambda ir, instr,element_id=i : op_swap(ir, instr, element_id)

for i in xrange(0, 5):
    mnemo_func["LOG%d"%i] = lambda ir, instr, num_topic=i : op_log(ir, instr, num_topic)


def get_mnemo_expr(ir, instr, *args):
    instr, extra_ir = mnemo_func[instr.name.upper()](ir, instr, *args)
    return instr, extra_ir

class ir_evm(IntermediateRepresentation):

    def __init__(self, symbol_pool=None):
        IntermediateRepresentation.__init__(self, mn_evm, None, symbol_pool)
        self.pc = PC
        self.sp = SP
        self.gas = GAS
        self.IRDst = ExprId('IRDst', 256)

        self.callvalue = R_CALLVALUE
        self.caller = R_CALLER
        self.address = R_ADDRESS
        self.origin = R_ORIGIN
        self.calldatasize = R_CALLDATASIZE

        self.block_number = R_BLOCK_NUMBER
        self.block_hash = R_BLOCK_HASH
        self.block_timestamp = R_BLOCK_TIMESTAMP


    def mod_pc(self, instr, instr_ir, extra_ir):
        pass

    def get_ir(self, instr):

        args = instr.args
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)

        for i, x in enumerate(instr_ir):
            x = ExprAff(x.dst, x.src.replace_expr(
                {self.pc: ExprInt256(instr.offset + instr.l)}))

            instr_ir[i] = x
        for b in extra_ir:
            for irs in b.irs:
                for i, x in enumerate(irs):
                    x = ExprAff(x.dst, x.src.replace_expr(
                        {self.pc: ExprInt256(instr.offset + instr.l)}))
                    irs[i] = x

        return instr_ir, extra_ir