from miasm2.core.asmbloc import asm_constraint, disasmEngine
from miasm2.arch.evm.arch import mn_evm
import miasm2.expression.expression as m2_expr


# Callback function list
cb_evm_funcs = []


def cb_evm_disasm(*args, **kwargs):
    for func in cb_evm_funcs:
        func(*args, **kwargs)



def jump_resolver(cur_bloc, symbol_pool, offsets_to_dis, *args, **kwargs):
    """
    dis bloc callback of dis_evm.

    Find following pattern:
    PUSHXX @to_jump
    JUMP/JUMPI
    """

    if len(cur_bloc.lines) < 2:
        return

    last_instr = cur_bloc.lines[-1]
    if last_instr.name not in ["JUMPI", "JUMP"]:
        return

    jump_offset = cur_bloc.lines[-2]
    if not jump_offset.name.startswith("PUSH"):
        return

    offset = jump_offset.args[0]

    if last_instr.name == "JUMP" :
        cur_bloc.bto.clear()
        l = symbol_pool.getby_offset_create(int(str(offset),16))
        cur_bloc.add_cst(l, asm_constraint.c_next, symbol_pool)
        offsets_to_dis.add(l.offset)

    else:
        next = cur_bloc.get_next()
        cur_bloc.bto.clear()
        l = symbol_pool.getby_offset_create(int(str(offset),16))
        cur_bloc.add_cst(l, asm_constraint.c_to, symbol_pool)
        cur_bloc.add_cst(next, asm_constraint.c_next, symbol_pool)
        offsets_to_dis.add(l.offset)

class dis_evm(disasmEngine):
    """
    Disasembly Engine for Ethereum evm.

    jump_resolver callback is by default enabled.
    """
    attrib = None

    def __init__(self, bs=None, **kwargs):
        super(dis_evm, self).__init__(mn_evm, self.attrib, bs, **kwargs)
        self.dis_bloc_callback = cb_evm_disasm

        cb_evm_funcs.append(jump_resolver)
