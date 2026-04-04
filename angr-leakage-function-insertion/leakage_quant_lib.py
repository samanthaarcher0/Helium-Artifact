import json
import io
import math
import pickle
import multiprocessing
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
import random
import smt_tracking
from claripy.backends.backend_z3 import z3_expr_to_smt2
import z3

def print_symb_regs(state):
    num = 0
    for reg in state.arch.register_names.values():
        value = getattr(state.regs, reg)
        if value.symbolic:
            print(f"{reg} = {value}")
            #print(state.eval(value))
            num +=1 
    return num


def checkSymbRegs(state, regex, unmatch=1):
    names = list()
    for reg in state.arch.register_names.values():
        value = getattr(state.regs, reg)
        if value.symbolic:
            for v in value.variables:
                match = re.search(regex, v)
                if unmatch:
                    if match==None:
                        names.append(v)
                else:
                    if match is not None:
                        names.append(v)
    return names


def step_with_timer(simgr):
    start = time.time()
    simgr.step()
    end = time.time()
    print(end-start)
    return simgr


def replace_mem_fresh_var(simgr, addr, i, size=32):
    var = cl.BVS(f"var{i}", size)
    size_bytes = int(size/8)
    constraint = (simgr.active[0].memory.load(addr, size_bytes).reversed == var)
    simgr.active[0].memory.store(addr, var.reversed)
    #print(f"New var stored at addr {hex(simgr.active[0].solver.eval(addr))} with new constraint {constraint}")
    return simgr, constraint, var


def replace_all_registers(simgr, conslist, varlist, i):
    state = simgr.active[0]
    for reg in state.arch.register_names.values():
        value = getattr(state.regs, reg)
        if value.symbolic:
            if value.depth > 2 or (value.depth==2 and (not (value.op == "Concat"))):
                size = value.size() 
                new_var = cl.BVS(f"var{i}", size)
                varlist.append(new_var)
                conslist.append(new_var == value)
                setattr(state.regs, reg, new_var)
                i += 1
    return simgr, conslist, varlist, i


def parseArgs():
    parser = argparse.ArgumentParser(description ='Symbolically execute binary with leakage functions')
    parser.add_argument('-b', dest='binary_path', required=True)
    parser.add_argument('-f', dest='function', default='main')
    parser.add_argument('--symbex', dest='enable_symb_ex', action='store_true')
    parser.add_argument('-l', dest='output_dir_label')
    parser.add_argument('-o', dest='output_dir')    
    parser.add_argument('--bin_dir', dest='bin_dir', default=os.path.dirname(os.path.abspath(__file__)) + "/../bins")
    parser.add_argument("--no_mc", dest="no_mc", action="store_true")
    parser.add_argument("--no_vals", dest="no_vals", action="store_true")
    parser.add_argument('-ff', "--fast_forward_until")
    parser.add_argument('-u', "--generate_paths_until")
    parser.add_argument('-s', "--single_insn_search", dest="single_insn_search", action="store_true")
    parser.add_argument("-lf", dest="leakage_function")
    parser.add_argument("-lfd", dest="leakage_function_json")
    parser.add_argument("--max_num_insn", dest="max_num_insn", default=None)
    parser.add_argument("-rr", "--refresh_rate", dest="refresh_rate", type=int, default=0)
    parser.add_argument("-apmc", "--model_count_approx", action='store_true', default=False)
    parser.add_argument("--pass_args", nargs="+", default=list())
    args = parser.parse_args()
    
    full_bin_path = os.path.abspath(args.binary_path)
    if not os.path.isfile(full_bin_path) or not os.access(full_bin_path, os.X_OK):
        print("Binary does not exist")
        sys.exit(1)
    else:
        args.binary_path = full_bin_path

    possible_leakage_functions = ["zs_op1", "zs_op2", "zs_op1_op2", "ds_op2", "zos_op1_op2", "zaos_op1_op2", "shift_arith", "ds_op2_1bit", "ds_op2_2bit", "ds_op2_4bit", "ds_op2_8bit"]
    if args.leakage_function_json is not None:
        with open(args.leakage_function_json, 'r') as file:
            data = json.load(file)
        args.leakage_function_json = data
        for lf in data.values():
            if lf not in possible_leakage_functions:
                print(f"Invalid leakage function: {lf}")
                sys.exit(1)
        print(f"Applying leakage functions according to specified dict: {args.leakage_function_json}")
    elif args.leakage_function is not None:
        if args.leakage_function not in possible_leakage_functions and args.enable_symb_ex:
            print(f"Invalid leakage function: {args.leakage_function}")
            sys.exit(1)
        else:
            print(f"Appling leakage function {args.leakage_function}")
    
    if args.fast_forward_until is not None:
        args.fast_forward_until = int(args.fast_forward_until, 16)

    if args.generate_paths_until is not None:
        args.generate_paths_until = int(args.generate_paths_until, 16)
    
    if args.enable_symb_ex is False:
        args.no_mc = True
        args.no_vals = True

    return args


def oneStepSimgr(proj, state):
    simgr = proj.factory.simgr(state)
    simgr.step()
    return simgr


def oneInstStepSimgr(proj, state):
    simgr = proj.factory.simgr(state)
    simgr.step(num_inst=1)
    return simgr


def get_reg(state, reg):
    x = getattr(state.regs, reg)
    print(x)
    return(x)


def get_mem(state, addr, size=4):
    x = state.memory.load(state.regs.rsp + addr, size)
    print(x)
    return(x)


def runWithTimeout(func, args=(), timeout=3):
    p = multiprocessing.Process(target=func, args=args)
    p.start()
    p.join(timeout=timeout)  # Wait 3 seconds
    if p.is_alive():
        print("Still running... killing it.")
        p.terminate()  # Force kill
        p.join()       # Cleanup
        return False
    return True


def stepUntilTimeout(func, proj, state):
    a = state
    print(f"active state: {a}")
    x = runWithTimeout(func, args=(proj, a))
    for i in range(100):
        if x:
            simgr = proj.factory.simgr(a)
            simgr.step()
            print(f"active state: {simgr.active}")
            a = simgr.active[0]
            x = runWithTimeout(func, args=(proj, a))
        else:
            break
    return simgr


def setSymb(state, ptr, l, index, n=32, log=True, label="symb"):
    print(f"in setSymb hook: ptr={ptr}, l={l}")
    l = l*8
    num_symb_var = math.ceil(l/n)
    mem_index = int(n/8)
    if isSymbolic(ptr, state):
        print("symbolic pointer: {ptr}")
        return
    for i in range(num_symb_var):
        symb_var_name = f"{label}{index + i}"
        symb_var = cl.BVS(symb_var_name, n)
        state.memory.store(ptr + mem_index*i, symb_var)
        symb_in.append(symb_var)
    for i in range(num_symb_var):
        print(state.memory.load(ptr + mem_index*i, mem_index))
    return


# Hook for rand function (this is not used)
class rand(angr.SimProcedure):
   def run(self):
       print("random number generated")
       return


# Dump CNF using csb BV solver and then model count CNF usuing Ganak
def modelCount(bin_dir, smt_fp="temp.smt2", exact=True):
    split_smt_fp = os.path.splitext(smt_fp)
    cnf_fp_copy = split_smt_fp[0] + ".cnf"
    mc_stdout_fp = split_smt_fp[0] + ".txt"
    mc_res = 0

    # Run SMT solver to dump CNF
    sp = ' '
    csb = True
    if csb:
        csb_executable = bin_dir + "/csb"
        smt_args = [csb_executable, "--output-CNF", "--exit-after-CNF", "-c", smt_fp]
        print(f"Running CSB to dump CNF file...")
        print(f"command: {sp.join(smt_args)}")
        smt_p = subprocess.run(smt_args, stdout=subprocess.DEVNULL, check=True)
    else:
        smt_args = ["bitwuzla", "--write-cnf", "output_0.cnf", smt_fp]
        print(f"Running Bitwuzla to dump CNF file...")
        print(f"command: {sp.join(smt_args)}")
        smt_p = subprocess.run(smt_args, stdout=subprocess.DEVNULL, check=True)

    # Model count CNF
    mc_args = list()
    if exact:
        mc_executable = bin_dir + "/ganak-2.5.2"
        mc_args.append(mc_executable)
        mc_args.append("--appmct")
        mc_args.append("120")
        mc_args.append("--delta")
        mc_args.append(".05")
    else:
        mc_executable = bin_dir + "/approxmc-linux-amd64"
        mc_args.append(mc_executable)
    cnf_fp = "output_0.cnf"
    shutil.copy(cnf_fp, cnf_fp_copy)
    mc_args.append(cnf_fp_copy)
    print(f"Running model counter...")
    print(f"command: {sp.join(mc_args)}")
    mc_start_time = time.time()
    with open(mc_stdout_fp, "wb") as out:
        mc_p = subprocess.Popen(mc_args, stdout=out, stderr=subprocess.STDOUT)
        mc_p.wait()
    smt_tracking.model_count_times.append(time.time()-mc_start_time)

    # Write Ganak output
    with open(mc_stdout_fp, "r", errors="replace") as f:
        mc_out_lines = f.read().splitlines()
    mc_res = 0
    exact_res = 0
    for l in mc_out_lines:
        if "arb int" in l:
            mc_res = l.split(" ")[-1]
            if "exact" in l:
                exact_res = 1
    if mc_res == 0:
        print("ERROR: did not find MC result")
    return mc_res, exact_res


def writeResults(simgr, output_dir, no_mc, bin_dir, additional_cons=list(), exact_mc=True):
    print(f'Writing results. Found {len(simgr.full_paths)} constraint paths')
    start_time = time.time()
    counter = 0
    bz_results = [True] * len(simgr.full_paths)
    for state in simgr.full_paths:
        base_fp = f"{output_dir}/path{counter}"
        smt_fp = f"{base_fp}.smt2"
        bz_result = bitwuzla(state, additional_cons, write_smt=smt_fp)[0]
        if not bz_result:
            print(f"State is unsat")
            bz_results[counter] = False
        counter += 1
        #f.write(f"Solver constraints: {state.solver.constraints}\n")
            
    # Model count the CNF
    counter = 0
    bad_results = list()
    with open(f"{output_dir}/results.log", "w") as f:
        print(1)
        for state in simgr.full_paths:
            if not bz_results[counter]:
                continue

            f.write("\n")
            path = state.globals['path']
            f.write(f"Path {counter}: {path}\n")
            if no_mc:
                mc_res = 0
            else:
                base_fp = f"{output_dir}/path{counter}"
                smt_fp = f"{base_fp}.smt2"
                print(f"Model counting {smt_fp}")
                mc_res, exact_res = modelCount(bin_dir, smt_fp, exact_mc)
                f.write(f"Model count: {mc_res}\n")
                if exact_res:
                    f.write("Result exact\n")
                else:
                    f.write("Result approximate\n")
                if int(mc_res) > 0:
                    f.write(f"Log of model count: {math.log2(int(mc_res))}\n")
                else:
                    bad_results.append(counter)
            counter += 1

        for e in simgr.errored:
            f.write(f"error: {e.error}\n")
            f.write(f"State Address: {hex(e.state.addr)}\n")

        print(f"\nNumber of paths: {counter}\n")
        print(f"Time writing output: {time.time() - start_time}\n")
        # print(f"Finished model counting time: {datetime.datetime.now()}\n")
        if not no_mc:
            print(F"Total model count time: {sum(smt_tracking.model_count_times)}")
            if len(smt_tracking.model_count_times) > 0:
                print(f"Average model count time: {sum(smt_tracking.model_count_times)}/{len(smt_tracking.model_count_times)}={sum(smt_tracking.model_count_times)/len(smt_tracking.model_count_times)}\n")
        print(f"Outputs written to dir: {output_dir}\n")
        if len(bad_results) > 0:
            print(f"ERROR: BAD MC RESULTS: {bad_results}\n")

    return


# Use Bitwuzla to solve the constraints for the current state with a state as input
def bitwuzla(state, additional_cons=list(), write_smt=None):
    tm = bz.TermManager()
    options = bz.Options()
    # options.set(bz.Option.PRODUCE_UNSAT_CORES, True)
    # options.set(bz.Option.VERBOSITY, 0)
    parser = bz.Parser(tm, options)

    constraints = state.solver.constraints + additional_cons
    conj = cl.And(*constraints) if len(constraints) > 1 else constraints[0]
    z3_expr = cl.backends.z3.convert(conj)
    smt2_string = z3_expr_to_smt2(z3_expr)

    for c in constraints:
        v = len(c.variables)
        if v > smt_tracking.max_var_per_clause:
            smt_tracking.max_var_per_clause = v
            smt_tracking.vars = c.variables
     
    if write_smt is not None:
        with open(write_smt, "w") as f:
            f.write(smt2_string)

    parser.parse(smt2_string, parse_only=True, parse_file=False)
    bzla = parser.bitwuzla()
    start = time.time()
    result = bzla.check_sat().value
    end = time.time()
    solver_time = end-start
    smt_tracking.num_smt_queries += 1
    smt_tracking.smt_query_times.append(solver_time)
    if result == 10:
        return True, parser, solver_time
    elif result == 20:
        return False, parser, solver_time
    else:
        raise Exception("Unknown result from Bitwuzla")

# Use Bitwuzla to solve a list of constraints 
def bitwuzla_constraints(constraints=list(), write_smt=None):
    tm = bz.TermManager()
    options = bz.Options()
    # options.set(bz.Option.PRODUCE_UNSAT_CORES, True)
    # options.set(bz.Option.VERBOSITY, 0)
    parser = bz.Parser(tm, options)

    conj = cl.And(*constraints) if len(constraints) > 1 else constraints[0]
    z3_expr = cl.backends.z3.convert(conj)
    smt2_string = z3_expr_to_smt2(z3_expr)

    for c in constraints:
        v = len(c.variables)
        if v > smt_tracking.max_var_per_clause:
            smt_tracking.max_var_per_clause = v
            smt_tracking.vars = c.variables
     
    if write_smt is not None:
        with open(write_smt, "w") as f:
            f.write(smt2_string)

    parser.parse(smt2_string, parse_only=True, parse_file=False)
    bzla = parser.bitwuzla()
    start = time.time()
    result = bzla.check_sat().value
    end = time.time()
    solver_time = end-start
    smt_tracking.num_smt_queries += 1
    smt_tracking.smt_query_times.append(solver_time)
    if result == 10:
        return True, parser, solver_time
    elif result == 20:
        return False, parser, solver_time
    else:
        raise Exception("Unknown result from Bitwuzla")


# Use Bitwuzla to solve the constraints for the current state with a solver as input
def bitwuzla_solver(solver, additional_cons=list(), write_smt=None):
    solver.add(additional_cons)

    tm = bz.TermManager()
    options = bz.Options()
    options.set(bz.Option.PRODUCE_UNSAT_CORES, True)
    options.set(bz.Option.VERBOSITY, 0)

    for c in solver.constraints + additional_cons:
        v = len(c.variables)
        if v > smt_tracking.max_var_per_clause:
            smt_tracking.max_var_per_clause = v
            smt_tracking.vars = c.variables

    smt2_string = solver._get_solver().to_smt2()

    if write_smt is not None:
        with open(write_smt, "w") as f:
            f.write(smt2_string)

    parser = bz.Parser(tm, options)
    parser.parse(smt2_string, parse_only=True, parse_file=False)
    bzla = parser.bitwuzla()
    start = time.time()
    result = bzla.check_sat().value
    end = time.time()
    solver_time = end-start
    smt_tracking.num_smt_queries += 1
    smt_tracking.smt_query_times.append(solver_time)
    if result == 10:
        return True, parser, solver_time
    elif result == 20:
        return False, parser, solver_time
    else:
        raise Exception("Unknown result from Bitwuzla")


# Functions for printing and converting hex
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


# Solve for concrete value of symbolic variable at current state
def getModelOfSymbVars(symb_vars, state):
    #if not state.solver.satisfiable():
    #    return None
    concrete_vals = list()
    for a in symb_vars:
        concrete_val = state.solver.eval(a)
        concrete_vals.append(concrete_val)
        name = list(a.variables)[0]
        print(f"Evaluated arg {name}: {concrete_val}")
    print(state.posix.dumps(1))
    return concrete_vals


# Infer register size
def getRegisterSize(reg_id):
    #reg_name = md.reg_name(reg_id)
    reg_name = reg_id

    # Map register names to sizes (based on common x86-64 registers)
    #if reg_name.startswith("r") and reg_name[1:].isdigit():
    if reg_name.startswith("r"):
        return 8  # 64-bit registers (rax, rbx, etc.)
    elif reg_name.startswith("e"):
        return 4  # 32-bit registers (eax, ebx, etc.)
    elif reg_name.endswith("h") or reg_name.endswith("l"):
        return 1  # 8-bit registers (ah, al, bh, bl, etc.)
    elif len(reg_name) == 2 and reg_name[1] in "x":
        return 2  # 16-bit registers (ax, bx, cx, dx)
    elif reg_name.startswith("xmm"):
        return 16  # XMM registers (128-bit)
    elif reg_name.startswith("ymm"):
        return 32  # YMM registers (256-bit)
    elif reg_name.startswith("zmm"):
        return 64  # ZMM registers (512-bit)
    return None  # Unknown register size


def getOperands(insn, state):
    i = 0
    op_vals = list()
    sym_op_flag = False
    num_reg_ops = 0
    for op in insn.operands:
        val, symb, reg_flag, size = getValueOfOperand(op, insn, state, i)
        i+=1
#        print(f"Op value {i}: {isSymbolic(val, state)}")
        if not symb:
            print(f"Val={hex(state.solver.eval(val))}")
        else:
            print(f"Op value {i} -- {val.symbolic} -- {val.variables}")
        op_vals.append(val)
        if not sym_op_flag and symb:
            sym_op_flag = True
        if reg_flag:
            num_reg_ops += 1

    if len(insn.operands) == 1 and insn.mnemonic == "mul":
        implicit_reg = None
        if size == 1:
            implicit_reg = "al"
        elif size == 2:
            implicit_reg = "ax"
        elif size == 4:
            implicit_reg = "eax"
        elif size == 8:
            implicit_reg = "rax"
        else:
            print("Error -- implicit register size greater than 64 bits.")
            sys.exit(1)
        if hasattr(state.regs, implicit_reg):
            implicit_reg_val = getattr(state.regs, implicit_reg)
            op_vals.insert(0, implicit_reg_val)
            print(f"Implicit op value -- {implicit_reg_val.symbolic} -- {implicit_reg_val.variables}")
            if not implicit_reg_val.symbolic:
                print(f"Val={hex(state.solver.eval(implicit_reg_val))}")
            #num_reg_ops += 1

        if not sym_op_flag and isSymbolic(implicit_reg_val, state):
            sym_op_flag = True

    return (op_vals, sym_op_flag, num_reg_ops)


# Get the value of an instruction's operand
def getValueOfOperand(op, insn, state, i):
    symb = 0
    val = None
    size = None
    op_str = insn.op_str.split(", ")
    reg_flag = 0
    if op.type == capstone.x86.X86_OP_REG:
        #print("\t\toperands[%u].type: REG = %s" % (i, insn.reg_name(op.reg)))
        if hasattr(state.regs, insn.reg_name(op.reg)):
            val = getattr(state.regs, insn.reg_name(op.reg))
            size = getRegisterSize(insn.reg_name(op.reg))
            reg_flag = 1
    elif op.type == capstone.x86.X86_OP_IMM:
        #print("\t\toperands[%u].type: IMM = 0x%s" % (i, op.imm))
        val = op.imm
    elif op.type == capstone.x86.X86_OP_MEM:
        #print("\t\toperands[%u].type: MEM" % i)
        mem_addr = 0
        size_match = re.search(r"\b(dword|qword|word|byte)\s+ptr\b", op_str[i], re.IGNORECASE)
        mem_size = size_match.group(1) if size_match else None
        if op.mem.segment != 0:
            #print("\t\t\toperands[%u].mem.segment: REG = %s" % (i, insn.reg_name(op.mem.segment)))
            mem_addr += getattr(state.regs, insn.reg_name(op.mem.segment))
        if op.mem.base != 0:
            #print("\t\t\toperands[%u].mem.base: REG = %s" % (i, insn.reg_name(op.mem.base)))
            mem_addr += getattr(state.regs, insn.reg_name(op.mem.base))
        if op.mem.index != 0:
            #print("\t\t\toperands[%u].mem.index: REG = %s" % (i, insn.reg_name(op.mem.index)))
            if op.mem.scale != 1:
                #print("\t\t\toperands[%u].mem.scale: %u" % (i, op.mem.scale))
                mem_addr += op.mem.scale*getattr(state.regs, insn.reg_name(op.mem.index))
        if op.mem.disp != 0:
            #print("\t\t\toperands[%u].mem.disp: 0x%s" % (i, to_x(op.mem.disp)))
            mem_addr += op.mem.disp
        if mem_size == "byte":
            size = 1
            val = state.mem[mem_addr].uint8_t.resolved
        elif mem_size == "word":
            size = 2
            val = state.mem[mem_addr].uint16_t.resolved
        elif mem_size == "dword":
            size = 4
            val = state.mem[mem_addr].uint32_t.resolved
        elif mem_size == "qword":
            size = 8
            val = state.mem[mem_addr].uint64_t.resolved
        else:
            print(f"oh no in else branch: {mem_size}")
            val = state.mem[mem_addr].uint32_t.resolved

    symb = isSymbolic(val, state)
    return (val, symb, reg_flag, size)


# Check if a value is symbolic or concrete
def isSymbolic(val, state):
    if val is not None and state.solver.symbolic(val):
        return True
    else:
        return False


# SHIFT ARITH Zero/FF...F skip leakage function
def shiftSkipConstraints(op1, op2, state, output_dir, simulate, conslist=list()):
    number_new_states = 0
    expected_new_states = 2

    new_state1 = state.copy()
    new_state2 = state.copy()
    new_state_list = list()

    if isSymbolic(op1, state):
        size = op1.size()
        all_ones = ~cl.BVV(0, size)
    elif isSymbolic(op2, state):
        size = op2.size()
        all_ones = ~cl.BVV(0, size)
    else:
        all_ones = -1

    # Fast path
    if simulate or ((not isSymbolic(op1, state)) and (not isSymbolic(op2, state))):
        op1_val = state.solver.eval(op1)
        op2_val = state.solver.eval(op2)
        if op1_val == 0 or op1_val == all_ones or op2_val == 0:
            new_state1.globals["path"] = state.globals["path"] + "0"
            print(f"path 0")
        else:
            new_state1.globals["path"] = state.globals["path"] + "1"
            print(f"path 1")
        return [new_state1], expected_new_states, number_new_states

    # Fast path
    skip_next = 0
    unsat = 0
    prev_len1 = len(new_state1.solver.constraints)
    constraint1 = cl.Or(op1==0, op2 == 0, op1 == all_ones)
    sat = bitwuzla_constraints([constraint1])[0]
    new_state1.globals["path"] = state.globals["path"] + "0"
    new_state1.solver.add(constraint1)
    if sat and (prev_len1 - len(new_state1.solver.constraints) == 0):
        skip_next = 1
        new_state_list.append(new_state1)
    else:
        if bitwuzla(new_state1, conslist)[0]:
            new_state_list.append(new_state1)
        else:
            unsat = 1

    # Slow path
    if not skip_next:
        prev_len2 = len(new_state2.solver.constraints)
        new_state2.globals["path"] = state.globals["path"] + "1"
        new_state2.solver.add(cl.And(op1!=0, op2!=0, op1!=all_ones))
        if unsat or bitwuzla(new_state2)[0]:
            new_state_list.append(new_state2)

    return new_state_list, expected_new_states, number_new_states


# Zero/FF...F skip leakage function
def twoOpZeroAllOneSkipConstraints(op1, op2, state, output_dir, simulate, conslist=list()):

    number_new_states = 0
    expected_new_states = 2

    new_state1 = state.copy()
    new_state2 = state.copy()
    new_state_list = list()

    if isSymbolic(op1, state):
        size = op1.size()
        all_ones = ~cl.BVV(0, size)
    elif isSymbolic(op2, state):
        size = op2.size()
        all_ones = ~cl.BVV(0, size)
    else:
        all_ones = -1
        
    if simulate or ((not isSymbolic(op1, state)) and (not isSymbolic(op2, state))):
        op1_val = state.solver.eval(op1)
        op2_val = state.solver.eval(op2)
        if op1_val == 0 or op2_val == 0 or op1_val == all_ones or op2_val == all_ones:
            new_state1.globals["path"] = state.globals["path"] + "0"
            print(f"path 0")
        else:
            new_state1.globals["path"] = state.globals["path"] + "1"
            print(f"path 1")
        return [new_state1], expected_new_states, number_new_states

    # Fast path
    skip_next = 0
    unsat = 0
    prev_len1 = len(new_state1.solver.constraints)
    constraint1 = cl.Or(op1==0, op2 == 0, op1 == all_ones, op2 == all_ones)
    sat = bitwuzla_constraints([constraint1])[0]
    new_state1.globals["path"] = state.globals["path"] + "0"
    new_state1.solver.add(constraint1)
    if sat:
        new_state1.solver.add(constraint1)
        new_state1.globals["path"] = state.globals["path"] + "0"
        if (prev_len1 - len(new_state1.solver.constraints) == 0):
            skip_next = 1
            new_state_list.append(new_state1)
        else:
            if bitwuzla(new_state1, conslist)[0]:
                new_state_list.append(new_state1)
            else:
                unsat = 1

    # Slow path
    if not skip_next:
        new_state2.solver.add(cl.And(op1!=0, op2!=0, op1!=all_ones, op2!=all_ones))
        if unsat or bitwuzla(new_state2, conslist)[0]:
            new_state2.globals["path"] = state.globals["path"] + "1"
            new_state_list.append(new_state2)

    return new_state_list, expected_new_states, number_new_states


# Zero/One skip leakage function
def twoOpZeroOneSkipConstraints(op1, op2, state, output_dir, simulate, conslist=list()):
    number_new_states = 0
    expected_new_states = 2

    new_state1 = state.copy()
    new_state2 = state.copy()
    new_state_list = list()
        
    if simulate or ((not isSymbolic(op1, state)) and (not isSymbolic(op2, state))):
        op1_val = state.solver.eval(op1)
        op2_val = state.solver.eval(op2)
        if op1_val == 0 or op2_val == 0 or op1_val == 1 or op2_val == 1:
            new_state1.globals["path"] = state.globals["path"] + "0"
            print(f"path 0")
        else:
            new_state1.globals["path"] = state.globals["path"] + "1"
            print(f"path 1")
        return [new_state1], expected_new_states, number_new_states

    # Fast path
    skip_next = 0
    unsat = 0
    prev_len1 = len(new_state1.solver.constraints)
    constraint1 = cl.Or(op1==0, op2 == 0, op1 == 1, op2 == 1)
    sat = bitwuzla_constraints([constraint1])[0]
    new_state1.globals["path"] = state.globals["path"] + "0"
    new_state1.solver.add(constraint1)
    if sat:
        new_state1.solver.add(constraint1)
        new_state1.globals["path"] = state.globals["path"] + "0"
        if (prev_len1 - len(new_state1.solver.constraints) == 0):
            skip_next = 1
            new_state_list.append(new_state1)
        else:
            if bitwuzla(new_state1, conslist)[0]:
                new_state_list.append(new_state1)
            else:
                unsat = 1

    # Slow path
    if not skip_next:
        new_state2.solver.add(cl.And(op1!=0, op2!=0, op1!=1, op2!=1))
        if unsat or bitwuzla(new_state2, conslist)[0]:
            new_state2.globals["path"] = state.globals["path"] + "1"
            new_state_list.append(new_state2)

    return new_state_list, expected_new_states, number_new_states


# Zero skip leakage function
def twoOpZeroSkipConstraints(op1, op2, state, output_dir, simulate, conslist=list()):
    number_new_states = 0
    expected_new_states = 2

    new_state1 = state.copy()
    new_state2 = state.copy()
    new_state_list = list()

    # Fast path
    if simulate or ((not isSymbolic(op1, state)) and (not isSymbolic(op2, state))):
        op1_val = state.solver.eval(op1)
        op2_val = state.solver.eval(op2)
        if op1_val == 0 or op2_val == 0:
            new_state1.globals["path"] = state.globals["path"] + "0"
            print(f"path 0")
        else:
            new_state1.globals["path"] = state.globals["path"] + "1"
            print(f"path 1")
        return [new_state1], expected_new_states, number_new_states

    # Fast path
    skip_next = 0
    unsat = 0
    prev_len1 = len(new_state1.solver.constraints)
    constraint1 = cl.Or(op1==0, op2 == 0)
    sat = bitwuzla_constraints([constraint1])[0]
    new_state1.globals["path"] = state.globals["path"] + "0"
    new_state1.solver.add(constraint1)
    if sat:
        new_state1.solver.add(constraint1)
        new_state1.globals["path"] = state.globals["path"] + "0"
        if (prev_len1 - len(new_state1.solver.constraints) == 0):
            skip_next = 1
            new_state_list.append(new_state1)
        else:
            if bitwuzla(new_state1, conslist)[0]:
                new_state_list.append(new_state1)
            else:
                unsat = 1

    # Slow path
    if not skip_next:
        new_state2.solver.add(cl.And(op1!=0, op2!=0))
        if unsat or bitwuzla(new_state2, conslist)[0]:
            new_state2.globals["path"] = state.globals["path"] + "1"
            new_state_list.append(new_state2)

    return new_state_list, expected_new_states, number_new_states


# Zero skip leakage function
def oneOpZeroSkipConstraints(op, state, output_dir, simulate, conslist=list()):
    number_new_states = 0
    expected_new_states = 2

    new_state1 = state.copy()
    new_state2 = state.copy()
    new_state_list = list()

    # Operand value is concrete
    if simulate or (not isSymbolic(op, state)):
        op_val = state.solver.eval(op)
        if op_val == 0:
            new_state1.globals["path"] = state.globals["path"] + "0"
            print(f"path 0")
        else:
            new_state1.globals["path"] = state.globals["path"] + "1"
            print(f"path 1")
        print(new_state1.globals["path"])
        return [new_state1], expected_new_states, number_new_states

    # Fast path
    skip_next = 0
    prev_len1 = len(new_state1.solver.constraints)
    constraint1 = (op==0)
    sat = bitwuzla_constraints([constraint1])[0]
    unsat = 0

    if sat:
        new_state1.solver.add(constraint1)
        new_state1.globals["path"] = state.globals["path"] + "0"
        if (prev_len1 - len(new_state1.solver.constraints) == 0):
            skip_next = 1
            new_state_list.append(new_state1)
        else:
            if bitwuzla(new_state1, conslist)[0]:
                new_state_list.append(new_state1)
            else:
                unsat = 1

    # Slow path
    if not skip_next:
        new_state2.solver.add(op != 0)
        if unsat or bitwuzla(new_state2, conslist)[0]:
            new_state2.globals["path"] = state.globals["path"] + "1"
            new_state_list.append(new_state2)
    
    return new_state_list, expected_new_states, number_new_states


def oneOpDigitSerialConstraintsPerBit(op, constraint_state, output_dir, simulate, conslist=list(), length_bv=4):

    def helper(constraint_state, i, total_num_states):
        prev_path = constraint_state.globals["path"]
        new_state = constraint_state.copy()
        b = chunks[i]
        symb = isSymbolic(b, constraint_state)

        if not symb:
            val = constraint_state.solver.eval(b)
            prev_len = len(new_state.solver.constraints)
        else:
            val = 0
            for j in range(i):
                new_state.solver.add(chunks[j] == 0)
            prev_len = len(new_state.solver.constraints)
            new_state.solver.add(cl.Not(b == 0))

        is_valid = (not symb and val != 0) or (symb and len(new_state.solver.constraints) > 0 and bitwuzla(new_state)[0])
        if is_valid:
            new_state.globals["path"] = prev_path + str(total_num_states - i)
            new_state_list.append(new_state)

        should_continue = (not symb and val == 0) or (len(new_state.solver.constraints) - prev_len) != 0
        return should_continue

    new_state_list = []
    prev_path = constraint_state.globals["path"]

    print(op.length//8-1)
    op2 = op.get_byte(op.length//8-1)
    expected_new_states = int(op2.length/length_bv)
    num_bytes = int(op2.length/length_bv)
    chunks = op2.chop(length_bv)

    if simulate:
        new_state = constraint_state.copy()
        op_val = constraint_state.solver.eval(op2)
        for l in range(num_bytes):
            if op_val < 2 ** (length_bv * (l + 1)):
                print(f"val: {op_val}, path: {l}")
                new_state.globals["path"] = prev_path + str(l)
                print(f"path {l}")
                break
        return [new_state], expected_new_states, 0

    for i in range(num_bytes - 1):
        should_continue = helper(constraint_state, i, expected_new_states)
        if not should_continue:
            break
    else:
        # Only reached if all num_bytes-1 iterations continued (no break)
        new_state1 = constraint_state.copy()
        for j in range(num_bytes - 1):
            new_state1.solver.add(chunks[j] == 0)
        if bitwuzla(new_state1)[0]:
            new_state1.globals["path"] = prev_path + "1"
            new_state_list.append(new_state1)

    return new_state_list, expected_new_states, 0

def oneOpDigitSerialConstraintsOptimized(op, constraint_state, output_dir, simulate, conslist=list()):

    def helper(constraint_state, i, total_num_states):
        prev_path = constraint_state.globals["path"]
        new_state = constraint_state.copy()
        b = op.get_byte(i)
        symb = isSymbolic(b, constraint_state)

        if not symb:
            val = constraint_state.solver.eval(b)
            prev_len = len(new_state.solver.constraints)
        else:
            val = 0
            for j in range(i):
                new_state.solver.add(op.get_byte(j) == 0)
            prev_len = len(new_state.solver.constraints)
            new_state.solver.add(cl.Not(b == 0))

        is_valid = (not symb and val != 0) or (symb and len(new_state.solver.constraints) > 0 and bitwuzla(new_state)[0])
        if is_valid:
            new_state.globals["path"] = prev_path + str(total_num_states - i)
            new_state_list.append(new_state)

        should_continue = (not symb and val == 0) or (len(new_state.solver.constraints) - prev_len) != 0
        return should_continue

    new_state_list = []
    prev_path = constraint_state.globals["path"]

    if op.length == 64:
        expected_new_states = 8
        num_bytes = 8
    elif op.length == 32:
        expected_new_states = 4
        num_bytes = 4
    else:
        print("ERROR: UNSUPPORTED LENGTH")
        return [], 0, 0

    if simulate:
        new_state = constraint_state.copy()
        op_val = constraint_state.solver.eval(op)
        for l in range(num_bytes):
            if op_val < 2 ** (8 * (l + 1)):
                print(f"val: {op_val}, path: {l}")
                new_state.globals["path"] = prev_path + str(l)
                print(f"path {l}")
                break
        return [new_state], expected_new_states, 0

    for i in range(num_bytes - 1):
        should_continue = helper(constraint_state, i, expected_new_states)
        if not should_continue:
            break
    else:
        # Only reached if all num_bytes-1 iterations continued (no break)
        new_state1 = constraint_state.copy()
        for j in range(num_bytes - 1):
            new_state1.solver.add(op.get_byte(j) == 0)
        if bitwuzla(new_state1)[0]:
            new_state1.globals["path"] = prev_path + "1"
            new_state_list.append(new_state1)

    return new_state_list, expected_new_states, 0

# Digit serial leakage function optimized
def oneOpDigitSerialConstraints(op, constraint_state, output_dir, simulate, conslist=list()):

    def helper(constraint_state, i, output_dir, total_num_states):
        prev_path = constraint_state.globals["path"]
        new_state = constraint_state.copy()
        b = op.get_byte(i)
        symb = isSymbolic(b, constraint_state)
        if not symb:
            val = constraint_state.solver.eval(b)
            prev_len = len(new_state.solver.constraints)
            #print(f"Byte {i+1} not symbolic {val}")
        else:
            #print(f"Byte {i+1} symbolic {b}")
            val = 0
            for j in range(i):
                new_state.solver.add(op.get_byte(j) == 0)
            prev_len = len(new_state.solver.constraints)
            new_state.solver.add(cl.Not(b == 0))
        if (not symb and val!=0) or (symb and len(new_state.solver.constraints)>0 and bitwuzla(new_state)[0]):
            new_state.globals["path"] = prev_path + str(total_num_states-i)
            #print(f"new_state{total_num_states-i}: {new_state.globals['path']}")
            new_state_list.append(new_state)
        return new_state, new_state_list, symb, val, prev_len

    number_new_states = 0
    new_state_list = list()
    prev_len = len(constraint_state.solver.constraints)
    prev_path = constraint_state.globals["path"]

    #print(f"op length {op.length}")
    if op.length == 64:
        
        expected_new_states = 8
        if simulate:
            new_state = constraint_state.copy()
            op_val = constraint_state.solver.eval(op)
            for l in range(8):
                if op_val < 2**(8*(l+1)):
                    print(f"val: {op_val}, path: {l}")
                    new_state.globals["path"] = prev_path + str(l)
                    print(f"path {l}")
                    break
            return [new_state], expected_new_states, number_new_states

        # Path8
        new_state8, new_state_list, symb, val, prev_len = helper(constraint_state, 0, output_dir, expected_new_states)
        if (not symb and val==0) or (len(new_state8.solver.constraints) - prev_len) != 0:
            # Path7
            new_state7, new_state_list, symb, val, prev_len = helper(constraint_state, 1, output_dir, expected_new_states)
            if (not symb and val==0) or (len(new_state7.solver.constraints) - prev_len) != 0:
                # Path6
                new_state6, new_state_list, symb, val, prev_len = helper(constraint_state, 2, output_dir, expected_new_states)
                if (not symb and val==0) or (len(new_state6.solver.constraints) - prev_len) != 0:
                    # Path5
                    new_state5, new_state_list, symb, val, prev_len = helper(constraint_state, 3, output_dir, expected_new_states)
                    if (not symb and val==0) or (len(new_state5.solver.constraints) - prev_len) != 0:
                        # Path 4
                        new_state4, new_state_list, symb, val, prev_len = helper(constraint_state, 4, output_dir, expected_new_states)
                        if (not symb and val==0) or (len(new_state4.solver.constraints) - prev_len) != 0:
                            # Path 3
                            new_state3, new_state_list, symb, val, prev_len = helper(constraint_state, 5, output_dir, expected_new_states)
                            if (not symb and val==0) or (len(new_state3.solver.constraints) - prev_len) != 0:
                                # Path 2
                                new_state2, new_state_list, symb, val, prev_len = helper(constraint_state, 6, output_dir, expected_new_states)
                                if (not symb and val==0) or (len(new_state2.solver.constraints) - prev_len) != 0:
                                    # Path1
                                    new_state1 = constraint_state.copy()
                                    for j in range(7):
                                        new_state1.solver.add(op.get_byte(j) == 0)
                                    #if (len(new_state1.solver.constraints)>0 and bitwuzla(new_state1)[0]):
                                    if bitwuzla(new_state1)[0]:
                                        new_state1.globals["path"] = prev_path + "1"
                                        new_state_list.append(new_state1)
                                        #print(f"new_state1: {new_state1.globals['path']}")

    elif op.length == 32:
        expected_new_states = 4
        # Path 4
        new_state4, new_state_list, symb, val, prev_len = helper(constraint_state, 0, output_dir, expected_new_states)
        if (not symb and val==0) or (len(new_state4.solver.constraints) - prev_len) != 0:
            # Path 3
            new_state3, new_state_list, symb, val, prev_len = helper(constraint_state, 1, output_dir, expected_new_states)
            if (not symb and val==0) or (len(new_state3.solver.constraints) - prev_len) != 0:
                # Path 2
                new_state2, new_state_list, symb, val, prev_len = helper(constraint_state, 2, output_dir, expected_new_states)
                if (not symb and val==0) or (len(new_state2.solver.constraints) - prev_len) != 0:
                    # Path1
                    new_state1 = constraint_state.copy()
                    for j in range(3):
                        new_state1.solver.add(op.get_byte(j) == 0)
                    print(f"L = {len(new_state1.solver.constraints)}")
                    #if (len(new_state1.solver.constraints)>0 and bitwuzla(new_state1)[0]):
                    if bitwuzla(new_state1)[0]:
                        new_state1.globals["path"] = prev_path + "1"
                        new_state_list.append(new_state1)
                        #print(f"new_state1: {new_state1.globals['path']}")

    else:
        print("ERROR: UNSUPPORTED LENGTH")

    return new_state_list, expected_new_states, number_new_states


# Print assembly to a file
def printAssembly(cfg, file, functions_only=False):
    with open(file, "w") as f:
        for addr, func in cfg.kb.functions.items():
            f.write(f"\nFunction: {func.name} at {hex(addr)}\n")
            if functions_only:
                num_blocks = 0
                total_inst = 0
                for block in func.blocks:
                    num_blocks += 1
                    num_inst = len(block.capstone.insns)
                    total_inst += num_inst
                    f.write(f"\nBasic Block at {hex(block.addr)} with {num_inst} instructions\n")
                f.write(f"\n {num_blocks} basic blocks with total {total_inst} instructions \n")
                continue
            for block in func.blocks:
                f.write(f"\nBasic Block at {hex(block.addr)}\n")
                for insn in block.capstone.insns:
                    f.write(f"{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}\n")
                    if insn.mnemonic == "imul" or insn.mnemonic == "mul":
                        c = 0
                        for o in insn.operands:
                            i = o
                            if i.type == capstone.x86.X86_OP_REG:
                                f.write("\t\toperands[%u].type: REG = %s\n" % (c, insn.reg_name(i.reg)))
                            if i.type == capstone.x86.X86_OP_IMM:
                                f.write("\t\toperands[%u].type: IMM = 0x%s\n" % (c, to_x(i.imm)))
                            if i.type == capstone.x86.X86_OP_MEM:
                                f.write("\t\toperands[%u].type: MEM\n" % c)
                                if i.mem.segment != 0:
                                    f.write("\t\t\toperands[%u].mem.segment: REG = %s\n" % (c, insn.reg_name(i.mem.segment)))
                                if i.mem.base != 0:
                                    f.write("\t\t\toperands[%u].mem.base: REG = %s\n" % (c, insn.reg_name(i.mem.base)))
                                if i.mem.index != 0:
                                    f.write("\t\t\toperands[%u].mem.index: REG = %s\n" % (c, insn.reg_name(i.mem.index)))
                                if i.mem.scale != 1:
                                    f.write("\t\t\toperands[%u].mem.scale: %u\n" % (c, i.mem.scale))
                                if i.mem.disp != 0:
                                    f.write("\t\t\toperands[%u].mem.disp: 0x%s\n" % (c, i.mem.disp))
                            c += 1
    return


# Generate dict of instructions of specified types
def getInstructionsOfType(insn_types, cfg):
    insn_addr_dict = defaultdict(list)
    for func in cfg.kb.functions.values():
        for block in func.blocks:
            for insn in block.capstone.insns:
                insn_name = insn.mnemonic
                if insn_name in insn_types:
                    print(f"Found instruction in {func.name} to track: {insn} in block {hex(block.addr)}")
                    block_addr = block.addr
                    insn_addr_dict[block_addr].append((insn.address, insn, func.name))
    return insn_addr_dict


def generateNewStates(num_reg_ops, leakage_function, op_vals, constraint_state, output_dir, simulate, conslist):
    if num_reg_ops == 2:
        if leakage_function == "zs_op1_op2":
            new_states, num_expected, num_new = twoOpZeroSkipConstraints(op_vals[1], op_vals[0], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "zs_op1":
            new_states, num_expected, num_new = oneOpZeroSkipConstraints(op_vals[1], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "zs_op2":
            new_states, num_expected, num_new = oneOpZeroSkipConstraints(op_vals[0], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "ds_op2":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsOptimized(op_vals[0], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "ds_op2_1bit":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsPerBit(op_vals[0], constraint_state, output_dir, simulate, conslist, 1)
        elif leakage_function == "ds_op2_2bit":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsPerBit(op_vals[0], constraint_state, output_dir, simulate, conslist, 2)
        elif leakage_function == "ds_op2_4bit":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsPerBit(op_vals[0], constraint_state, output_dir, simulate, conslist, 4)
        elif leakage_function == "ds_op2_8bit":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsPerBit(op_vals[0], constraint_state, output_dir, simulate, conslist, 8)
        elif leakage_function == "zos_op1_op2":
            new_states, num_expected, num_new = twoOpZeroOneSkipConstraints(op_vals[1], op_vals[0], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "zaos_op1_op2":
            new_states, num_expected, num_new = twoOpZeroAllOneSkipConstraints(op_vals[1], op_vals[0], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "shift_arith":
            new_states, num_expected, num_new = shiftSkipConstraints(op_vals[1], op_vals[0], constraint_state, output_dir, simulate, conslist)
    else:
        if leakage_function == "zs_op1_op2":
            new_states, num_expected, num_new = twoOpZeroSkipConstraints(op_vals[0], op_vals[1], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "zs_op1":
            new_states, num_expected, num_new = oneOpZeroSkipConstraints(op_vals[0], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "zs_op2":
            new_states, num_expected, num_new = oneOpZeroSkipConstraints(op_vals[1], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "ds_op2":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsOptimized(op_vals[1], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "ds_op2_1bit":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsPerBit(op_vals[1], constraint_state, output_dir, simulate, conslist, 1)
        elif leakage_function == "ds_op2_2bit":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsPerBit(op_vals[1], constraint_state, output_dir, simulate, conslist, 2)
        elif leakage_function == "ds_op2_4bit":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsPerBit(op_vals[1], constraint_state, output_dir, simulate, conslist, 4)
        elif leakage_function == "ds_op2_8bit":
            new_states, num_expected, num_new = oneOpDigitSerialConstraintsPerBit(op_vals[1], constraint_state, output_dir, simulate, conslist, 8)
        elif leakage_function == "zos_op1_op2":
            new_states, num_expected, num_new = twoOpZeroOneSkipConstraints(op_vals[0], op_vals[1], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "zaos_op1_op2":
            new_states, num_expected, num_new = twoOpZeroAllOneSkipConstraints(op_vals[0], op_vals[1], constraint_state, output_dir, simulate, conslist)
        elif leakage_function == "shift_arith":
            new_states, num_expected, num_new = shiftSkipConstraints(op_vals[0], op_vals[1], constraint_state, output_dir, simulate, conslist)
    return new_states, num_expected, num_new


def checkVars(value, vars_list):
    if len(vars_list) == 0:
        return True
    if isSymbolic(value, state):
        for s in value.variables():
            if s in vars_list:
                return True
    return False


def generatePaths(simgr, block_insn_dict, enable_leakage_functions, output_dir, leakage_function_dict=dict(), num_steps=None, single_insn_search=False, stop_addr=None, simulate=False, conslist=list(), refresh_rate=0, vars_list=list()):
    steps_taken = 0
    varlist = list()
    var_index = 0
    refresh_index = 0
    refresh = True if refresh_rate > 0 else False
    if refresh:
        print(f"Refresh rate is {refresh_rate}")

    if stop_addr is not None:
        print(f"Stop address is {stop_addr}")

    if num_steps is not None:
        num_steps = int(num_steps)
        print(f"num steps: {num_steps}")

    # Initialize stack for DFS
    stack = list()
    active_copy = simgr.active.copy()
    for a in active_copy:
        stack.append((a, simgr.constraints.copy()))

    insn_dict = dict()
    if single_insn_search:
        single_insn_dict = dict()
        for l in block_insn_dict.values():
            for (addr, insn, func) in l:
                insn_dict[addr] = [(addr, insn, func)]
    else:
        insn_dict = block_insn_dict

    # While stack is non-empty
    while len(stack) > 0:
        print(f"\nStep {steps_taken}")
        print(simgr.active)

        if len(simgr.active) > 1:
             print(f"WARNING: Symbolic control flow divergence!!!")

        # Get active state and accompanying constraint states
        active_state, constraints_states = stack.pop()
        simgr.drop(stash="constraints")
        simgr.drop(stash="active")
        simgr.populate("constraints", constraints_states)
        simgr.populate("active", [active_state])
        print(f"Simgr after populating stashes: {simgr}")

        # Add path condition
        if insn_dict.get(active_state.addr) is not None:
            print(f"Found block at address {active_state.addr} with tracked addresses: {block_insn_dict.get(active_state.addr)}")
            for (addr, insn, func) in insn_dict.get(active_state.addr):
                smt_tracking.total_instrumented_instr += 1
                constraint_states = simgr.constraints.copy()
                print(f"\n{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}\tin {func}")
                print(f"num_insn_found: {smt_tracking.total_instrumented_instr}")
                leakage_function = leakage_function_dict.get(insn.mnemonic)
                if leakage_function == None:
                    print("invalid leakage function dict, exiting")
                    leakage_function = ""
                    sys.exit(1)

                # Find next target instruction
                if not single_insn_search:
                    start_time = time.time()
                    simgr.explore(find=addr)
                    print(f"Time exploring states: {time.time() - start_time}")
                    print(f"After explore with target address: {addr:#x} with {len(simgr.active)} active states and simgr: {simgr}")
                    if len(simgr.found) > 1:
                        print(f"More than 1 instruction found! Something wrong with CFG")
                        sys.exit(1)
                    found_state = simgr.found[0]
                    #simgr.move("found", "active")
                else:
                    found_state = active_state

                # Get operand values from the found state
                start_time = time.time()
                op_vals, sym_op_flag, num_reg_ops = getOperands(insn, found_state)
                #print(f"{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}\t{op_vals}")

                # If atleast one operand is symbolic, add constraints
                if simulate:
                    sym_op_flag = True
                    enable_leakage_functions = True
                if sym_op_flag:
                    smt_tracking.symb_instrumented_instr += 1
                    if enable_leakage_functions:
                        for constraint_state in constraint_states:
                            new_states, num_expected, num_new = generateNewStates(num_reg_ops, leakage_function, op_vals, constraint_state, output_dir, simulate, conslist)

                            # Add new constraint states to stash
                            simgr.drop(filter_func=lambda s: s==constraint_state, stash="constraints")
                            for s in new_states:
                                simgr.constraints.append(s)
                                #print(f"Adding constraint state: {s} with constraints {s.solver.constraints}")

                if (num_steps != None and num_steps == smt_tracking.total_instrumented_instr):
                    print(f"breaking out of for loop {smt_tracking.total_instrumented_instr} insn found")
                    break

                if not single_insn_search:
                    simgr.populate("active", [active_state])
                    #simgr.move("found", "old_found")
                    simgr.drop(stash="found")
                print(f"Time adding constraint states: {time.time() - start_time}")
                
        # Manage simulation: step active state
        path_condition = active_state.solver.constraints
        start_time = time.time()
        print(f"Before step: with {len(simgr.active)} active states, {simgr.active} and simgr: {simgr}")
        if single_insn_search:
            simgr.step(num_inst=1)
        else:
            #simgr.drop(filter_func=lambda s: s==found_state)
            #simgr.populate("active", [active_state])
            #addr_before = active_state.addr
            simgr.step()
            #if addr_before == simgr.active[0].addr:
            #    simgr.step()
        steps_taken += 1
        refresh_index += 1
        if refresh and refresh_index > refresh_rate:
            simgr, conslist, varlist, var_index = replace_all_registers(simgr, conslist, varlist, var_index)
            refresh_index = 0
            print("Refreshing vars")
        print(f"Time stepping states: {time.time() - start_time}")

        # If no active state remains, this symbex path is complete.
        # Add path condition of this path to the constraint states, and then move constraint states to full path stash
        constraint_states = simgr.constraints.copy()
        if len(simgr.active) == 0:
            print(f"End of path: moving contraint states to full_paths: {simgr}")
            new_full_paths = list()
            for c in constraint_states:
                c_new = c.copy()
                for pc in path_condition:
                    c_new.solver.add(pc)
                c_new.globals["path"] = c.globals["path"]
                new_full_paths.append(c_new)
            simgr.populate("full_paths", new_full_paths)
        # If there are remaining active states, push each of them to the stack
        else:
            active_copy = simgr.active.copy()
            for a in active_copy:
                if not ((num_steps != None and num_steps == smt_tracking.total_instrumented_instr) or (stop_addr != None and a.addr == stop_addr)):
                #if not ((num_steps != None and num_steps == steps_taken) or (stop_addr != None and a.addr == stop_addr)):
                    # This is needed when lazy solves is enabled for the simulation manager, othersiwe satisfiability is checked automatically by angr
                    if a.solver.satisfiable():
                        stack.append((a, constraint_states))
                else:
                    print("stopping execution early")
                    new_full_paths = list()
                    for c in constraint_states:
                        c_new = c.copy()
                        for pc in path_condition:
                            c_new.solver.add(pc)
                        c_new.globals["path"] = c.globals["path"]
                        new_full_paths.append(c_new)
                    simgr.populate("full_paths", new_full_paths)

        print(f"Simgr after adding states: {simgr}\nstack: {stack}\n")
        print("-" * 40)
    print(f"Found {smt_tracking.total_instrumented_instr} instructions ({smt_tracking.symb_instrumented_instr} with symbolic operands) after stepping {steps_taken} times.\nExiting")
    print(f"Simgr {simgr}")
    return simgr, conslist
