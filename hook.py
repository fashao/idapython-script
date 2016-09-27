from idaapi import *
from idautils import *
from idc import  *

class Hooktest(DBG_Hooks):
    def dbg_bpt(self, tid, pc):
        print 'pc:%x LR:%x str: %s ' % (pc,GetRegValue('LR'),GetString(GetRegValue('R0'),-1,ASCSTR_C))
        continue_process()
        return 1
# Remove an existing debug hook
try:
    if debug:
        print("Removing previous hook ...")
        debug.unhook()
except:
    pass

debug = Hooktest()
debug.hook()
func = LocByName("strlen")
print 'func:',hex(func)
AddBpt(func)
SetBptAttr(func,BPTATTR_FLAGS,BPT_ENABLED|BPT_TRACE)
num_bp = GetBptQty()
print "[*] Set %d breakpoints." % num_bp

