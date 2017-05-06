#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.core.cpu import reg_info, gen_reg, gen_regs

"""
Ethereum EVM is a stack-based architecture with 256-bits words.
Standard Registers are :
PC = Program Counter
SP = Stack Pointer

For this implementation we add the following variables in registers

GAS = Gas remaining for the contract execution
STORAGE = Storage Pointer
ST = Status register to raise execption (I.e out-of-gas etc)

From Ethereum yellow paper:

I_a : address of the account which owns the code that is executed
I_o : the sender address of the transaction that originated this execution
I_p : the price of gas in the transaction that originated this execution
I_d : the byte array that is the input data to this execution
I_s : the address of the account wich caused the code to be executing.
I_v : the deposited value in Wei pased to this account
I_b : the byte array that is the machine code to be executed
I_h : the block header of the present block
I_e : the depth of the present message-call or contract-creation. 
"""

regs256_str = [ "PC", "PC_init",
                "SP", "SP_init",
                "GAS", "GAS_init",
                "STORAGE", "STORAGE_init",
                "ST", "ST_init",
                "R_CALLVALUE", "R_CALLER", "R_ADDRESS", "R_ORIGIN",
                "R_BLOCK_NUMBER", "R_BLOCK_HASH", "R_BLOCK_TIMESTAMP",
                "R_CALLDATASIZE"]

R_CALLDATALOAD = ""

# Foreach regs256_str elements generate a ExprId of 256 bits
gen_regs(regs256_str, globals(), 256)


regs_init = {PC : ExprInt(0,256), SP:ExprInt(0,256)}


# EVM has memory initialized to zero
for i in xrange(0,32):
	regs_init[ExprMem(ExprId("MEM",256)+ExprInt(i,256),8)] = ExprInt(0,8)
regs_init[ExprMem(ExprId("MEM",256),8)] = ExprInt(0,8) # MEM+0x0 does not work correctly,need to set MEM