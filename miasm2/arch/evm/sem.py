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
from miasm2.ir.ir import ir

SIZE_WORD = 256

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

    e.append(ExprAff(ExprMem(SP , SIZE_WORD), ir.address))
    e.append(ExprAff(SP, SP + ExprInt256(1*SIZE_WORD)))

    return e, []

def op_balance(ir, instr):
    """
    Get balance of currently executing account
    """
    e = []
    arg1 = _stack_item(0)

    e.append(ExprAff(_stack_item(0), 
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
    e.append(ExprAff(_stack_item(0), ir.calldata))

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

    e.append(ExprAff(_stack_item(0),
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
    e.append(ExprAff(_stack_item(0), ir.block_hash))

    return e, []

def op_number(ir, instr):
    """
    Get the block's number
    """
    e = []
    e.append(ExprAff(_stack_item(0), ir.block_number))

    return e, []

def op_pop(ir, instr):
    """
    Remove item from stack
    """
    e = []

    e.append(ExprAff(ExprMem(SP - ExprInt256(1*SIZE_WORD),SIZE_WORD), ExprInt256(0)))
    e.append(ExprAff(SP, SP - ExprInt256(1*SIZE_WORD)))

    return e, []

def op_timestamp(ir, instr):
    """
    Get the block's timestamp
    """
    e = []
    e.append(ExprAff(_stack_item(0), ir.block_timestamp))

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

    "POP"          : op_pop,
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

        args = instr.args
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)

        # TODO : PC incrementation is not always +1 (when PUSH xxx )
        for i, x in enumerate(instr_ir):
            x = ExprAff(x.dst, x.src.replace_expr(
                {self.pc: ExprInt256(instr.offset + 1)}))
            instr_ir[i] = x
        for b in extra_ir:
            for irs in b.irs:
                for i, x in enumerate(irs):
                    x = ExprAff(x.dst, x.src.replace_expr(
                        {self.pc: ExprInt256(instr.offset + 1)}))
                    irs[i] = x

        return instr_ir, extra_ir