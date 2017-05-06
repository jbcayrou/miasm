from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp

import requests



class EVMEnvironment:

    URL_BASE = "https://etherchain.org/api/"

    def __init__(self):
        pass

    def __get_page(self, sub_url):
        r =requests.get("%s/%s" % (self.URL_BASE, sub_url))
        return r.json()

    def balance(self, address):
        r = self.__get_page("account/0x%x"%address)
        v = r["data"][0]["balance"]
        return int(v)

    def code(self, address):
        r = self.__get_page("account/0x%x"%address)
        v = r["data"][0]["code"]
        return v

evm_env = EVMEnvironment()


def evm_expr_simplification(self, e):

    if e.op == "evm_balance":
        addr = int(expr_simp(e.args[0]).arg)
        return ExprInt256(evm_env.balance(addr))
    elif e.op == "evm_extcodesize":
        addr = int(expr_simp(e.args[0]).arg)
        code = str(evm_env.code(addr))[2:] # Remove the '0x'...
        code_sz = len(code)/2
        if code_sz % 2 != 0:
            code_sz+=1
        return ExprInt256(code_sz)

    elif e.op == "evm_extcodecopy":
        pass
    elif e.op == "evm_calldatacopy":
        pass
    elif e.op == "evm_blockhash":
        pass
    elif e.op == "evm_timestamp":
        pass
    elif e.op == "evm_number":
        pass
    elif e.op == "evm_difficulty":
        pass
    elif e.op == "evm_gaslimit":
        pass

    # Memory operators

    elif e.op == "evm_mload":
        pass
    elif e.op == "evm_mstore":
        pass
    elif e.op == "evm_mstores":
        pass

    # Storage operators

    elif e.op == "evm_sload":
        pass
    elif e.op == "evm_sstore":
        pass

    return e