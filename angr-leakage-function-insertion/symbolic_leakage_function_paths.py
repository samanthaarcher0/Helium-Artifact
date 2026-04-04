import cProfile
import pstats
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
import smt_tracking

def main():
    profiler = cProfile.Profile()
    profiler.enable()
    begin = time.time()
    args = leakage_quant_lib.parseArgs() 

    # Load the binary
    full_bin_path = args.binary_path
    bin_basename = os.path.basename(full_bin_path)

    output_dir_name = f"results"
    if args.output_dir_label is not None:
        output_dir_name += "_" + args.output_dir_label
    symb_output_dir_name = output_dir_name + "_latest"
    output_dir_name += f"_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    if args.output_dir is not None:
        output_dir = os.path.join(os.getcwd(), args.output_dir)
        output_dir = os.path.join(output_dir, output_dir_name)
        symb_output_dir = os.path.join(os.getcwd(), args.output_dir)
        symb_output_dir = os.path.join(symb_output_dir, symb_output_dir_name)
    else:
        output_dir = os.path.join(os.getcwd(), output_dir_name)
        symb_output_dir = os.path.join(os.getcwd(), symb_output_dir_name)

    os.makedirs(output_dir)
    if os.path.lexists(symb_output_dir):
        os.remove(symb_output_dir)
    os.symlink(os.path.abspath(output_dir), os.path.abspath(symb_output_dir))
    shutil.copy(full_bin_path, output_dir)
   
    print(f"Start time: {datetime.datetime.now()}") 
    proj = angr.Project(full_bin_path, auto_load_libs=False)
    print(proj.arch)


    # Define instructions on which to track in order to include leakage function constraints
    insns = list()
    if args.leakage_function_json is not None:
        insns = list(args.leakage_function_json.keys())
    elif args.leakage_function is not None:
        insns = ["mul", "imul", "mulps", "mulpd"]
        # insns = ["add", "adc", "inc", "xadd", "adcx", "adox"]
        args.leakage_function_json = dict()
        for i in insns:
            args.leakage_function_json[i] = args.leakage_function


    # Write out assembly
    cfg = proj.analyses.CFGFast(
        resolve_indirect_jumps=False,
#        normalize=True,
    )
    #cfg = proj.analyses.CFGFast(    resolve_indirect_jumps=False)
    insn_addr_dict = leakage_quant_lib.getInstructionsOfType(insns, cfg)
    assembly_fp = output_dir + "/" + os.path.basename(full_bin_path) + ".instr"
    assembly_fp_functions_only = output_dir + "/" + os.path.basename(full_bin_path) + ".functions_only.instr"
    leakage_quant_lib.printAssembly(cfg, assembly_fp)
    leakage_quant_lib.printAssembly(cfg, assembly_fp_functions_only, True)

    print("CFG functions:", len(cfg.kb.functions))
    initial_cons = list()
    # Initialize pased on program and create initial state
    init_state = None
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
    elif bin_basename == "firefox_harness_box_blur" or bin_basename == "firefox_harness_box_blur_2":
        proj, argv, symb_list, initial_cons = initialize.firefox_box_blur(proj)
    elif bin_basename == "firefox_harness_laplacian":
        proj, argv = initialize.firefox_laplacian(proj) 
    elif bin_basename == "firefox_harness_gaussian_blur":
        proj, argv = initialize.firefox_gaussian_blur(proj)
    elif bin_basename == "firefox_harness_box_blur_2x2":
        proj, argv, symb_list, initial_cons = initialize.firefox_box_blur_2x2(proj)
    elif bin_basename == "helium_eval_firefox_boxblur":
        if len(args.pass_args)==0:
            print(f"Specify size of image")
            sys.exit(1)
        proj, argv, symb_list, initial_cons = initialize.firefox_box_blur_general(proj, args.pass_args[0])
    elif bin_basename == "bitwise_pixel4":
        if len(args.pass_args)==0:
            print(f"Specify size of image")
            sys.exit(1)
        proj, argv, symb_list, initial_cons = initialize.firefox_bitwise(proj, args.pass_args[0])
    elif bin_basename == "helium_eval_img_transform_kernels":
        if len(args.pass_args)==0:
            print(f"Specify size of image")
            sys.exit(1)
        proj, argv, symb_list, initial_cons = initialize.img_transform_kernels(proj, args.pass_args[0])
    else:
        print(f"Add initializer for binary {bin_basename}")
        sys.exit(1)
    #proj, argv = initialize.ed25519_keygen_init(proj)
    #proj, argv = initialize.poly1305_init(proj)
    #proj, argv, symb_list, initial_cons = initialize.feconvolve_init2(proj)
    #proj, argv, symb_list = initialize.small_function_init2(proj)
    #proj, argv, symb_list = initialize.mod_div_init(proj)

    if init_state == None:
        initial_state = proj.factory.entry_state(args=argv, add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.LAZY_SOLVES # This was meant to cause angr to so fewer z3 solved, but it didn't. 
        })
    else:
        initial_state = init_state

    for c in initial_cons:
        initial_state.solver.add(c)

    # Create simulation manager and initialize constraint states
    simgr = proj.factory.simulation_manager(initial_state)
    initial_constraint_state = initial_state.copy()
    initial_constraint_state.globals["path"] = "p"
    s_list = [initial_constraint_state] 
    
    simgr.populate("constraints",  s_list)
    simgr.populate("full_paths", list())
    if args.enable_symb_ex:
        print("Symbolic execution enabled")
    
    # If passed as an argument, fast forward to specific address before beginning to collect constraint states
    # This still symbolically tracks the state, but does not include the leakage functions paths of the instructions
    if args.fast_forward_until is not None:
        simgr.explore(find=args.fast_forward_until)
        simgr.move("found", "active")

    # Symbolically execute the program and generate leakage function global mupaths
    simgr, conslist = leakage_quant_lib.generatePaths(simgr, insn_addr_dict, args.enable_symb_ex, output_dir, args.leakage_function_json, None, args.single_insn_search, args.generate_paths_until, refresh_rate=args.refresh_rate)

    # Print and model count paths
    if args.enable_symb_ex:
        leakage_quant_lib.writeResults(simgr, output_dir, args.no_mc, args.bin_dir, conslist, not args.model_count_approx)
    end = time.time()
    profiler.disable()
    if args.enable_symb_ex:
        print("\nSMT stats:")
        print(f"    Total runtime: {end-begin}")
        print(f"    Number of queries: {smt_tracking.num_smt_queries}")
        print(f"    Average SMT query time: {sum(smt_tracking.smt_query_times)}/{len(smt_tracking.smt_query_times)}={sum(smt_tracking.smt_query_times)/len(smt_tracking.smt_query_times)}")
        print(f"    Maximum SMT query time: {max(smt_tracking.smt_query_times)}")
        print(f"    Maximum vars per SMT query: {smt_tracking.max_var_per_clause}")
        print(f"    Variables: {smt_tracking.vars}")

    stats = pstats.Stats(profiler)
    stats.sort_stats('tottime')
    stats.print_stats(20) 

if __name__ == "__main__":
    main()
