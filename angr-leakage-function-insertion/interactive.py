import math
from collections import defaultdict
import bitwuzla as bz
import shutil
import datetime
import time 
import capstone
import angr
import claripy as cl
import re
import sys, os
import argparse
import subprocess
from random import randbytes
import leakage_quant_lib
import initialize

args = leakage_quant_lib.parseArgs() 
args.single_insn_search = True

# Load the binary
full_bin_path = args.binary_path
bin_dir_path = os.path.dirname(full_bin_path)
bin_basename = os.path.basename(full_bin_path)
output_dir_path = f"results_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
if args.output_dir_label is not None:
    output_dir_path += "_" + args.output_dir_label
output_dir = os.path.join(bin_dir_path, output_dir_path)
os.makedirs(output_dir)
shutil.copy(full_bin_path, output_dir)

print(f"Start time: {datetime.datetime.now()}") 
proj = angr.Project(full_bin_path, auto_load_libs=False)
print(proj.arch)

# Define leakage functions
#insns = ["imul", "mul"]
insns = ["imul", "mul", "add"]
#insns = ["mul", "imul", "add", "sub", "xor", "shl", "shr", "sar", "or", "and"]
#insns = ["add"]

# Hook instructions with leakage functions
cfg = proj.analyses.CFGFast()
insn_addr_dict = leakage_quant_lib.getInstructionsOfType(insns, cfg)
assembly_fp = output_dir + "/" + os.path.basename(full_bin_path) + ".instr"
leakage_quant_lib.printAssembly(cfg, assembly_fp)

init_state = None
initial_cons = list()
if bin_basename == "mul_shift_add":
    proj, argv, symb_list, initial_cons = initialize.mul_shift_add_init(proj)
elif bin_basename == "simple_prog_example":
    proj, argv, symb_list, initial_cons = initialize.simple_prog_example_init(proj)
elif bin_basename == "helium_eval_chacha20_poly1305":
    proj, argv = initialize.helium_eval_poly1305(proj)
elif bin_basename == "600.perlbench_s":
    proj, argv = initialize.helium_eval_perl_bench(proj)
elif bin_basename == "arith_test":
    proj, argv = initialize.helium_eval_arith_test(proj)
elif bin_basename == "harness":
    proj, argv, init_state = initialize.libjpeg_harness(proj)
elif bin_basename == "harness_small":
    proj, argv, init_state = initialize.libjpeg_harness_small(proj)
elif bin_basename == "colorspace_matrix_3x3":
    proj, argv = initialize.colorspace_matrix_3x3(proj)
elif bin_basename == "image_processing_kernels2":
    proj, argv = initialize.default(proj)
elif bin_basename == "image_processing_kernels":
    proj, argv = initialize.default(proj)
elif bin_basename == "firefox_harness":
    proj, argv = initialize.default(proj)
elif bin_basename == "helium_firefox_convolve":
    proj, argv, symb_list, initial_cons = initialize.feconvolve_init2(proj)
elif bin_basename == "firefox_harness_box_blur" or  bin_basename == "firefox_harness_box_blur_2":
    proj, argv, initial_cons = initialize.firefox_box_blur(proj)
elif bin_basename == "firefox_harness_laplacian":
    proj, argv, initial_cons = initialize.firefox_laplacian(proj)
else:
    print(f"Add initializer for binary {bin_basename}")
    sys.exit(1)


initial_state = proj.factory.entry_state(args=argv, add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
})

simgr = proj.factory.simulation_manager(initial_state)

initial_constraint_state = initial_state.copy()
initial_constraint_state.globals["path"] = "p"
for c in initial_cons:
    initial_constraint_state.solver.add(c)
s_list = [initial_constraint_state] 

# Symbolically execute the program
simgr.populate("constraints",  s_list)
simgr.populate("full_paths", list())
if args.enable_symb_ex:
    print("Symbolic execution enabled")

if args.fast_forward_until is not None:
    simgr.explore(find=args.fast_forward_until)
    simgr.move("found", "active")

#addr = [0x401d34, 0x401da9, 0x401e1e, 0x401e95, 0x401f0d, 0x401f8c, 0x40200b, 0x40208a, 0x4020fe, 0x40217a, 0x4021ef, 0x402283, 0x4022f5, 0x40237f, 0x402406, 0x40247b]
conslist = list()
varlist = list()
i = 0
step = 0

#simgr, conslist = leakage_quant_lib.generatePaths(simgr=simgr,
#                                block_insn_dict=insn_addr_dict,
#                                enable_leakage_functions=args.enable_symb_ex,
#                                output_dir=output_dir, 
#                                leakage_function=args.leakage_function,
#                                num_steps=None,
#                                single_insn_search=args.single_insn_search,
#                                stop_addr=args.generate_paths_until,
#                                simulate=False,
#                                conslist=list(),
#                                refresh_rate=0)

#for x in range(num):
#    a = addr[x]
#    print(a)
#    args.generate_paths_until = a
#    simgr = leakage_quant_lib.generatePaths(simgr, insn_addr_dict, args.enable_symb_ex, output_dir, args.leakage_function, None, args.single_insn_search, args.generate_paths_until)
#
#    constraints = simgr.constraints.copy()
#    for c in constraints:
#        b, p = leakage_quant_lib.bitwuzla(c, additional_cons=conslist)
#        if not b:
#            simgr.drop(filter_func=lambda s: s==c, stash="constraints")
#
#    print(f"After generating paths {step}: {simgr.active[0]}")
#    step += 1
#    simgr.drop(stash="full_paths")
#    if x != num-1:
#        simgr, conslist, varlist, i = leakage_quant_lib.replace_all_registers(simgr, conslist, varlist, i)
#print(simgr)
#
#for c in simgr.constraints:
#    for con in conslist:
#        c.solver.add(con)
#simgr.populate("full_paths", simgr.constraints)
#print(simgr)
#leakage_quant_lib.writeResults(simgr, output_dir, args.no_mc, args.bin_dir)
