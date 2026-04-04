#include "pin.H"
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <iostream>

KNOB<std::string> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "start", "crypto_sign",
                            "function name that enables tracing on entry");
KNOB<std::string> KnobOut  (KNOB_MODE_WRITEONCE, "pintool", "o", "TracerSim.log",
                            "output file for operand trace + counts");
KNOB<BOOL> KnobInstrumentMul64(KNOB_MODE_WRITEONCE, "pintool",
    "mul64", "0", "Instrument multiply 64 bit instructions only");
KNOB<BOOL> KnobInstrumentCS64other(KNOB_MODE_WRITEONCE, "pintool",
    "cs64", "0", "Instrument other (non-64b mul) cs 64 bit instructions only");
KNOB<BOOL> KnobInstrumentCS32other(KNOB_MODE_WRITEONCE, "pintool",
    "cs32", "0", "Instrument other (non-64b mul) cs 32 bit instructions only");

static std::ofstream g_out;
//static UINT64 g_mul_count = 0;

static TLS_KEY g_tls_key;
struct TState { INT32 depth = 0; };
static inline TState* TS() { return static_cast<TState*>(PIN_GetThreadData(g_tls_key, PIN_ThreadId())); }

static std::unordered_map<std::string, const char*> g_intern;
static std::vector<std::unique_ptr<std::string>> g_store;
static const char* Intern(const std::string& s){
    auto it = g_intern.find(s);
    if (it != g_intern.end()) return it->second;
    g_store.emplace_back(std::make_unique<std::string>(s));
    const char* p = g_store.back()->c_str();
    g_intern.emplace(*g_store.back(), p);
    return p;
}

static ADDRINT ShouldTrace() { return TS()->depth > 0; }

static VOID LogOp2R(const char* rtnName, ADDRINT ip, const char* op,
                    UINT64 a, UINT64 b, UINT32 wbits)
{
    if (wbits == 8)      { a &= 0xff;            b &= 0xff; }
    else if (wbits == 16){ a &= 0xffff;          b &= 0xffff; }
    else if (wbits == 32){ a &= 0xffffffffu;     b &= 0xffffffffu; }
    // your output stream; adapt to your format
    //g_out << rtnName << "  ip=0x" << std::hex << ip
    //      << "  " << op << "(" << std::dec << a << ", " << b << ")  w=" << wbits << "\n";
    if (!((std::strcmp(rtnName, ".text") == 0) || (std::strncmp(rtnName, "__", 2) == 0))) {
      g_out << rtnName << " " << std::dec << wbits << " " << op << " " << std::hex << a << " " << b << "\n";
    }
      //g_out << std::dec << wbits << " " << op << " " << std::hex << a << " " << b << "\n";
    //}
    // optional counters per op if you keep them
}

static UINT64 LoadMemLE(ADDRINT ea, UINT32 size) {
    UINT8 buf[8] = {0};
    if (size > 8) size = 8;
    PIN_SafeCopy(buf, (void*)ea, size);
    UINT64 v=0; for (UINT32 i=0;i<size;i++) v |= (UINT64)buf[i] << (8*i);
    return v;
}

static VOID LogOpRMem(const char* rtnName, ADDRINT ip, const char* op,
                      UINT64 regv, ADDRINT ea, UINT32 msz, UINT32 wbits)
{
    UINT64 memv = LoadMemLE(ea, msz);
    LogOp2R(rtnName, ip, op, regv, memv, wbits);
}

static VOID LogOpRI(const char* rtnName, ADDRINT ip, const char* op,
                    UINT64 regv, UINT64 imm, UINT32 wbits)
{
    LogOp2R(rtnName, ip, op, regv, imm, wbits);
}

static VOID LogOpMemI(const char* rtnName, ADDRINT ip, const char* op,
                      ADDRINT ea, UINT32 msz, UINT64 imm, UINT32 wbits)
{
    UINT64 memv = LoadMemLE(ea, msz);
    LogOp2R(rtnName, ip, op, memv, imm, wbits);
}

static VOID StartExtent() {
    if (TS()->depth == 0) {
        g_out << "Started tracing at " << KnobStart.Value().c_str() << "\n";
        TS()->depth = 1;
    } else {
        TS()->depth++;
    }
}
static VOID OnAnyCall() { if (TS()->depth > 0) TS()->depth++; }
static VOID OnAnyRet()  { if (TS()->depth > 0) TS()->depth--; }

static inline BOOL IsMul(OPCODE opc) {return opc == XED_ICLASS_IMUL || opc == XED_ICLASS_MUL; }
static inline BOOL IsAdd(OPCODE opc) { return opc == XED_ICLASS_ADD; }
static inline BOOL IsSub(OPCODE opc) { return opc == XED_ICLASS_SUB; }
static inline BOOL IsXor(OPCODE opc) { return opc == XED_ICLASS_XOR; }
static inline BOOL IsAnd(OPCODE opc) { return opc == XED_ICLASS_AND; }
static inline BOOL IsOr(OPCODE opc) { return opc == XED_ICLASS_OR;  }
static inline BOOL IsShr(OPCODE opc) { return opc == XED_ICLASS_SHR; }
static inline BOOL IsSar(OPCODE opc) { return opc == XED_ICLASS_SAR; }
static inline BOOL IsCmp(OPCODE opc) {return opc == XED_ICLASS_CMP; }
static inline BOOL IsShl(OPCODE opc) {return opc == XED_ICLASS_SHL; }
static inline BOOL IsSal(OPCODE opc) {
#ifdef XED_ICLASS_SAL
    return opc == XED_ICLASS_SAL;
#else
    return opc == XED_ICLASS_SHL;
#endif
}
static inline BOOL IsTest(OPCODE opc) { return opc == XED_ICLASS_TEST; }

static const char* OpNameFor(OPCODE opc) {
    if (IsMul(opc))    return "mul";
    if (IsAdd(opc))    return "add";
    if (IsSub(opc) || IsCmp(opc)) return "sub";
    if (IsXor(opc))    return "xor";
    if (IsAnd(opc) || IsTest(opc)) return "and";
    if (IsOr(opc))     return "or";
    if (IsSal(opc))    return "sal";
    if (IsShl(opc))    return "shl";
    if (IsSar(opc))    return "sar";
    if (IsShr(opc))    return "shr";
    return nullptr;
}

static VOID InstrumentALUINS(INS ins, bool instrument_mul64, bool instrument_cs64, bool instrument_cs32)
{
    const OPCODE opc = INS_Opcode(ins);
    const char* opname = OpNameFor(opc);
    if (!opname) return; // not a targeted instruction

    // Determine operand width (bits)
    UINT32 wbits = 64;
    if (INS_OperandCount(ins) > 0) {
        UINT32 w = INS_OperandWidth(ins, 0);
        if (w == 8 || w == 16 || w == 32 || w == 64) wbits = w;
    }

    bool is_mul = (opc == XED_ICLASS_IMUL || opc == XED_ICLASS_MUL);
    #ifdef XED_ICLASS_SAL	
    bool is_logic = (opc == XED_ICLASS_ADD || opc == XED_ICLASS_SUB ||
                     opc == XED_ICLASS_AND || opc == XED_ICLASS_OR ||
                     opc == XED_ICLASS_XOR || opc == XED_ICLASS_CMP ||
                     opc == XED_ICLASS_SHR || opc == XED_ICLASS_SAR ||
		     opc == XED_ICLASS_SHL || opc == XED_ICLASS_SAL);
    #else
    bool is_logic = (opc == XED_ICLASS_ADD || opc == XED_ICLASS_SUB ||
                     opc == XED_ICLASS_AND || opc == XED_ICLASS_OR ||
                     opc == XED_ICLASS_XOR || opc == XED_ICLASS_CMP ||
                     opc == XED_ICLASS_SHR || opc == XED_ICLASS_SAR ||
                     opc == XED_ICLASS_SHL );
    
    #endif
    bool is_test = (opc == XED_ICLASS_TEST);

    // Only instrument 64 bit mul
    if (instrument_mul64 && ((wbits!=64) || (!is_mul)))
	return;

    // Only instrument 64 bit CS (non-mul) instructions
    if (instrument_cs64 && ((wbits!=64) || (!is_logic)))
	return;

    // Only instrument <32 bit CS instructions
    if (instrument_cs32 && ((wbits==64) || (!is_logic && !is_mul && !is_test)))
        return;

    RTN rtn = INS_Rtn(ins);
    //const std::string& rtnName = RTN_Name(rtn);
    const char* rtnName = RTN_Valid(rtn)
        ? Intern(PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_NAME_ONLY))
        : Intern(std::string("<noroutine>"));


    // (A) reg, reg   e.g., add r64, r64
    if (INS_OperandCount(ins) >= 2 &&
        INS_OperandRead(ins,0) && INS_OperandRead(ins,1) &&
        INS_OperandIsReg(ins,0) && INS_OperandIsReg(ins,1) &&
        !IsMul(opc)) // (mul has its own special encodings handled later)
    {
        REG rdst = INS_OperandReg(ins,0);
        REG rsrc = INS_OperandReg(ins,1);
        INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOp2R),
                           IARG_PTR, rtnName,
                           IARG_INST_PTR,
                           IARG_PTR,  Intern(opname),
                           IARG_REG_VALUE, rdst,
                           IARG_REG_VALUE, rsrc,
                           IARG_UINT32, wbits,
                           IARG_END);
        return;
    }

    // (B) reg, mem   e.g., xor r32, [mem]
    if (INS_OperandCount(ins) >= 2 &&
        INS_OperandRead(ins,0) && INS_OperandRead(ins,1) &&
        INS_OperandIsReg(ins,0) && INS_OperandIsMemory(ins,1) &&
        !IsMul(opc))
    {
        REG rdst = INS_OperandReg(ins,0);
        INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRMem),
                           IARG_PTR, rtnName,
                           IARG_INST_PTR,
                           IARG_PTR,  Intern(opname),
                           IARG_REG_VALUE, rdst,
                           IARG_MEMORYREAD_EA,
                           IARG_MEMORYREAD_SIZE,
                           IARG_UINT32, wbits,
                           IARG_END);
        return;
    }

    // (B2) mem, reg  e.g., cmp [mem], r32  or  test [mem], r64
    if (INS_OperandCount(ins) >= 2 &&
        INS_OperandRead(ins,0) && INS_OperandRead(ins,1) &&
        INS_OperandIsMemory(ins,0) && INS_OperandIsReg(ins,1) &&
        !IsMul(opc))
    {
        REG rsrc = INS_OperandReg(ins,1);
        INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
        // Reuse LogOpRMem by passing (reg, mem) in that order for logging
        INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRMem),
                           IARG_PTR,  rtnName,
                           IARG_INST_PTR,
                           IARG_PTR,  Intern(opname),
                           IARG_REG_VALUE, rsrc,         // reg operand
                           IARG_MEMORYREAD_EA,           // mem EA (operand 0)
                           IARG_MEMORYREAD_SIZE,
                           IARG_UINT32, wbits,
                           IARG_END);
        return;
    }

    // (C) reg, imm   e.g., or r16, imm16
    if (INS_OperandCount(ins) >= 2 &&
        INS_OperandRead(ins,0) &&
        INS_OperandIsReg(ins,0) && INS_OperandIsImmediate(ins,1) &&
        !IsShl(opc) && !IsShr(opc) && !IsMul(opc))
    {
        REG rdst = INS_OperandReg(ins,0);
        UINT64 imm = (UINT64)INS_OperandImmediate(ins,1);
        INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRI),
                           IARG_PTR, rtnName,
                           IARG_INST_PTR,
                           IARG_PTR,  Intern(opname),
                           IARG_REG_VALUE, rdst,
                           IARG_UINT64, imm,
                           IARG_UINT32, wbits,
                           IARG_END);
        return;
    }

    // (C2) mem, imm   e.g., cmp [mem], imm8/16/32  or  test [mem], imm8/32
    if (INS_OperandCount(ins) >= 2 &&
        INS_OperandIsMemory(ins,0) && INS_OperandIsImmediate(ins,1) &&
        !IsShl(opc) && !IsShr(opc) && !IsMul(opc))
    {
        UINT64 imm = (UINT64)INS_OperandImmediate(ins,1);
        INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpMemI),
                           IARG_PTR,  rtnName,
                           IARG_INST_PTR,
                           IARG_PTR,  Intern(opname),
                           IARG_MEMORYREAD_EA,
                           IARG_MEMORYREAD_SIZE,
                           IARG_UINT64, imm,
                           IARG_UINT32, wbits,
                           IARG_END);
        return;
    }

    // encodings: r/m, 1  |  r/m, imm8  |  r/m, CL
    if (IsShl(opc) || IsShr(opc)) {
        const char* shname = opname; // "shl"/"shr"
        // r/m, 1 (implicit)
        if (INS_OperandCount(ins) >= 1 && INS_OperandIsReg(ins,0)) {
            REG rdst = INS_OperandReg(ins,0);
            // If there is an explicit src operand, handle below; otherwise implicit 1
            if (INS_OperandCount(ins) == 1) {
                INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRI),
                                   IARG_PTR, rtnName,
                                   IARG_INST_PTR,
                                   IARG_PTR,  Intern(shname),
                                   IARG_REG_VALUE, rdst,
                                   IARG_UINT64, 1,
                                   IARG_UINT32, wbits,
                                   IARG_END);
                return;
            }
        }
        // r/m, imm8 or r/m, CL
        if (INS_OperandCount(ins) >= 2 && INS_OperandIsReg(ins,0)) {
            REG rdst = INS_OperandReg(ins,0);
            if (INS_OperandIsImmediate(ins,1)) {
                UINT64 imm = (UINT64)INS_OperandImmediate(ins,1) & 0xff;
                INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRI),
                                   IARG_PTR, rtnName,
                                   IARG_INST_PTR,
                                   IARG_PTR,  Intern(shname),
                                   IARG_REG_VALUE, rdst,
                                   IARG_UINT64, imm,
                                   IARG_UINT32, wbits,
                                   IARG_END);
                return;
            }
            if (INS_OperandIsReg(ins,1) && INS_OperandReg(ins,1) == REG_CL) {
                INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOp2R),
                                   IARG_PTR, rtnName,
                                   IARG_INST_PTR,
                                   IARG_PTR,  Intern(shname),
                                   IARG_REG_VALUE, rdst,
                                   IARG_REG_VALUE, REG_CL,
                                   IARG_UINT32, wbits,
                                   IARG_END);
                return;
            }
        }
        // r/m (mem), 1/imm/CL — you can add similar mem-dst handling if needed.
        // For brevity, skipping mem-as-dst to avoid writing memory twice.
    }

    if (IsMul(opc)) {
        // Case 1: IMUL reg, reg
        if (opc == XED_ICLASS_IMUL &&
            INS_OperandCount(ins) >= 2 &&
            INS_OperandRead(ins,0) && INS_OperandRead(ins,1) &&
            INS_OperandIsReg(ins,0) && INS_OperandIsReg(ins,1))
        {
            REG r1 = INS_OperandReg(ins,0), r2 = INS_OperandReg(ins,1);
            INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOp2R),
                               IARG_PTR, rtnName,
                               IARG_INST_PTR,
                               IARG_PTR,  Intern("mul"),
                               IARG_REG_VALUE, r1,
                               IARG_REG_VALUE, r2,
                               IARG_UINT32, wbits,
                               IARG_END);
            return;
        }
        // Case 2: IMUL reg, mem
        if (opc == XED_ICLASS_IMUL &&
            INS_OperandCount(ins) >= 2 &&
            INS_OperandRead(ins,0) && INS_OperandRead(ins,1) &&
            INS_OperandIsReg(ins,0) && INS_OperandIsMemory(ins,1))
        {
            REG r1 = INS_OperandReg(ins,0);
            INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRMem),
                               IARG_PTR, rtnName,
                               IARG_INST_PTR,
                               IARG_PTR,  Intern("mul"),
                               IARG_REG_VALUE, r1,
                               IARG_MEMORYREAD_EA,
                               IARG_MEMORYREAD_SIZE,
                               IARG_UINT32, wbits,
                               IARG_END);
            return;
        }
        // Case 3: IMUL reg, imm
        if (opc == XED_ICLASS_IMUL &&
            INS_OperandCount(ins) >= 2 &&
            INS_OperandRead(ins,0) &&
            INS_OperandIsReg(ins,0) &&
            INS_OperandIsImmediate(ins,1))
        {
            REG r1 = INS_OperandReg(ins,0);
            UINT64 imm = (UINT64)INS_OperandImmediate(ins,1);
            INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRI),
                               IARG_PTR, rtnName,
                               IARG_INST_PTR,
                               IARG_PTR,  Intern("mul"),
                               IARG_REG_VALUE, r1,
                               IARG_UINT64, imm,
                               IARG_UINT32, wbits,
                               IARG_END);
            return;
        }
        // Case 4: IMUL reg, r/m, imm (3-operand)
        if (opc == XED_ICLASS_IMUL &&
            INS_OperandCount(ins) >= 3 &&
            INS_OperandIsReg(ins,0) && INS_OperandIsImmediate(ins,2))
        {
            // Log "src * imm" (dst updated later by ISA)
            UINT64 imm = (UINT64)INS_OperandImmediate(ins,2);
            if (INS_OperandIsReg(ins,1)) {
                REG src = INS_OperandReg(ins,1);
                INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRI),
                                   IARG_PTR, rtnName,
                                   IARG_INST_PTR,
                                   IARG_PTR,  Intern("mul"),
                                   IARG_REG_VALUE, src,
                                   IARG_UINT64, imm,
                                   IARG_UINT32, wbits,
                                   IARG_END);
            } else if (INS_OperandIsMemory(ins,1)) {
                // If you want exact (mem * imm), add a dedicated logger; here we log (dst, mem) for brevity
                REG dst = INS_OperandReg(ins,0);
                INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRMem),
                                   IARG_PTR, rtnName,
                                   IARG_INST_PTR,
                                   IARG_PTR,  Intern("mul"),
                                   IARG_REG_VALUE, dst,
                                   IARG_MEMORYREAD_EA,
                                   IARG_MEMORYREAD_SIZE,
                                   IARG_UINT32, wbits,
                                   IARG_END);
            }
            return;
        }
        // Case 5: MUL r/m (implicit GAX * op)
        if (opc == XED_ICLASS_MUL) {
            if (INS_OperandIsReg(ins,0)) {
                REG rm = INS_OperandReg(ins,0);
                INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOp2R),
                                   IARG_PTR, rtnName,
                                   IARG_INST_PTR,
                                   IARG_PTR,  Intern("mul"),
                                   IARG_REG_VALUE, LEVEL_BASE::REG_GAX,
                                   IARG_REG_VALUE, rm,
                                   IARG_UINT32, wbits,
                                   IARG_END);
            } else if (INS_OperandIsMemory(ins,0)) {
                INS_InsertIfCall (ins, IPOINT_BEFORE, AFUNPTR(ShouldTrace), IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(LogOpRMem),
                                   IARG_PTR, rtnName,
                                   IARG_INST_PTR,
                                   IARG_PTR,  Intern("mul"),
                                   IARG_REG_VALUE, LEVEL_BASE::REG_GAX,
                                   IARG_MEMORYREAD_EA,
                                   IARG_MEMORYREAD_SIZE,
                                   IARG_UINT32, wbits,
                                   IARG_END);
            }
            return;
        }
    }

    // else: not a form we handle (and we didn't emit If without Then).
}


static VOID Instruction(INS ins, VOID*)
{
    if (INS_IsCall(ins))     INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnAnyCall), IARG_END);
    else if (INS_IsRet(ins)) INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnAnyRet),  IARG_END);

    InstrumentALUINS(ins, KnobInstrumentMul64.Value(), KnobInstrumentCS64other.Value(), KnobInstrumentCS32other.Value());
}

static VOID ImageLoad(IMG img, VOID*)
{
    if (!IMG_Valid(img)) return;
    RTN r = RTN_FindByName(img, KnobStart.Value().c_str());
    if (!RTN_Valid(r)) return;
    if (RTN_Name(r).find("@plt") != std::string::npos) return; 

    RTN_Open(r);
    RTN_InsertCall(r, IPOINT_BEFORE, AFUNPTR(StartExtent), IARG_END);
    RTN_Close(r);
}

static VOID ThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    PIN_SetThreadData(g_tls_key, new TState, tid);
}
static VOID ThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*) {
    delete TS();
}

static VOID Fini(INT32, VOID*)
{
    //g_out << "TOTAL_MULTIPLIES " << g_mul_count << "\n";
    g_out.close();
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();                      
    if (PIN_Init(argc, argv)) return 1;

    g_tls_key = PIN_CreateThreadDataKey(nullptr);
    g_out.open(KnobOut.Value().c_str(), std::ios::out | std::ios::trunc);

    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram(); 
    return 0;
}

