#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.ir.ir import IntermediateRepresentation, irbloc, AssignBlock
from miasm2.ir.analysis import ira
from miasm2.arch.evm.sem import ir_evm
from miasm2.arch.evm.regs import *
# from miasm2.core.graph import DiGraph


class ir_a_evm_base(ir_evm, ira):

    def __init__(self, symbol_pool=None):
        ir_evm.__init__(self, symbol_pool)

class ir_a_evm(ir_a_evm_base):

    def __init__(self, symbol_pool=None):
        ir_a_evm_base.__init__(self, symbol_pool)

    def post_add_bloc(self, bloc, ir_blocs):
        IntermediateRepresentation.post_add_bloc(self, bloc, ir_blocs)
