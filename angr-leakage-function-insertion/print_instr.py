import capstone
#import capstone.X86
import angr
import argparse
def to_hex(s, prefix_0x = True):
    if prefix_0x:
        return " ".join("0x{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    else:
        return " ".join("{0:02x}".format(c) for c in s)  # <-- Python 3 is OK

def to_hex2(s):
    r = "".join("{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    while r[0] == '0': r = r[1:]
    return r

def to_x(s):
    from struct import pack
    if not s: return '0'
    x = pack(">q", s)
    while x[0] in ('\0', 0): x = x[1:]
    return to_hex2(x)

def to_x_32(s):
    from struct import pack
    if not s: return '0'
    x = pack(">i", s)
    while x[0] in ('\0', 0): x = x[1:]
    return to_hex2(x)
 
parser = argparse.ArgumentParser(description ='Pretty print binary')
 
parser.add_argument('-b', dest ='binary_path', required=True)
args = parser.parse_args()

#md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
#md.detail = True

# Load the binary
binary_path = args.binary_path
project = angr.Project(binary_path, auto_load_libs=False)

# Get the entry point of the binary
args = [binary_path]
# args.append('2')
entry_state = project.factory.entry_state(args=args)

# Create a CFG (Control Flow Graph)
cfg = project.analyses.CFGFast()

# Iterate through all the basic blocks in the binary
for addr, func in cfg.kb.functions.items():
    print(f"\nFunction: {func.name} at {hex(addr)}")
    for block in func.blocks:
        print(f"\nBasic Block at {hex(block.addr)}")
        for insn in block.capstone.insns:
            print(f"{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}")
            if insn.mnemonic == "imul":
                c = 0
                for o in insn.operands:
                    i = o
                    if i.type == capstone.x86.X86_OP_REG:
                        print("\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(i.reg)))
                    if i.type == capstone.x86.X86_OP_IMM:
                        print("\t\toperands[%u].type: IMM = 0x%s" % (c, to_x(i.imm)))
                    if i.type == capstone.x86.X86_OP_MEM:
                        print("\t\toperands[%u].type: MEM" % c)
                        if i.mem.segment != 0:
                            print("\t\t\toperands[%u].mem.segment: REG = %s" % (c, insn.reg_name(i.mem.segment)))
                        if i.mem.base != 0:
                            print("\t\t\toperands[%u].mem.base: REG = %s" % (c, insn.reg_name(i.mem.base)))
                        if i.mem.index != 0:
                            print("\t\t\toperands[%u].mem.index: REG = %s" % (c, insn.reg_name(i.mem.index)))
                        if i.mem.scale != 1:
                            print("\t\t\toperands[%u].mem.scale: %u" % (c, i.mem.scale))
                        if i.mem.disp != 0:
                            print("\t\t\toperands[%u].mem.disp: 0x%s" % (c, i.mem.disp))
                    c += 1
