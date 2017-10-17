#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
//#include <string>
//#include <sstream>
//#include <unordered_map>
//#include <vector>

#include <Windows.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drsyms.h"


static int tls_index = -1;
static int thread_index = 0;
static size_t pageSize = 0;
static size_t cleanCallAllocSize = 0;
static app_pc ccTraceIOPC = NULL;
static app_pc ccQueryPerformanceCounterPC = NULL;

typedef struct _threadData_t {
    FILE *file;
    void *bufferBase;
    void *bufferPtr;
    void *bufferEnd;
} threadData_t;

typedef struct _traceData_t {
    void *iAddr;
    void *dAddr;
    int32_t iType;
    int32_t timerState;
    uint64_t startT;
    uint64_t endT;
} traceData_t;

//typedef struct _traceDataWS_t {
//    /*void *iAddr;
//    int32_t iType;
//    int32_t timerState;
//    uint64_t startT;
//    uint64_t endT;*/
//
//    traceData_t baseData;
//
//    uint32_t symbolIDX;
//
//    _traceDataWS_t &operator=(const traceData_t &rhs) {
//        /*this->iAddr = rhs.iAddr;
//        this->iType = rhs.iType;
//        this->timerState = rhs.timerState;
//        this->startT = rhs.startT;
//        this->endT = rhs.endT;*/
//        this->baseData = rhs;
//
//        return *this;
//    }
//} traceDataWS_t;

//typedef std::unordered_map<std::string, uint32_t> symbolIndexMap_t;

#define MAX_NUM_MEM_REFS 1000

#define MEM_BUF_SIZE (sizeof(traceData_t)*MAX_NUM_MEM_REFS)

//#define REGINA_BINARY


static void instrument(void *drcontext, instrlist_t *ilist, instr_t *where,
    int pos, bool write);

static void traceIO(void *drcontext);

//static void symbolLookUp(app_pc addr, std::string &symbol);


/**
 * DR clean call that writes current trace buffer onto disk.
 * Should only be called when trace buffer is about to overflow.
 */
static void ccTraceIO(void) {
    void *drcontext = dr_get_current_drcontext();

    traceIO(drcontext);
}


/**
 * DR clean call to insert performance counter to get real-time stamp.
 * This call is very expensive, but should be free of system_calls.
 */
static void ccQueryPerformanceCounter(void) {
    void *drcontext = dr_get_current_drcontext();
    threadData_t *data = (threadData_t*)(
        drmgr_get_tls_field(drcontext, tls_index));
    traceData_t *tPtr = (traceData_t*)(data->bufferPtr);

    LARGE_INTEGER timer;
    bool success = QueryPerformanceCounter(&timer); //< the expensive part

    if (success) {
        tPtr->timerState = 1;
        tPtr->startT = timer.QuadPart;
    } else {
        tPtr->timerState = -1;
        tPtr->startT = 0;
    }

    /*if (success) {
        if (tPtr->timerState == 0) {
            tPtr->timerState = 1;
            tPtr->startT = timer.QuadPart;
        } else if (tPtr->timerState == 1) {
            tPtr->timerState = 0;
            tPtr->endT = timer.QuadPart;
        }
    } else {
        tPtr->timerState = 3;
    }*/

    /*if (((char*)(data->bufferPtr) + sizeof(traceData_t)) > ((char*)data->bufferEnd)) {
        traceIO(drcontext);
    } else {
        data->bufferPtr = (void*)((size_t)data->bufferPtr + sizeof(traceData_t));
    }*/
}


static void code_cache_init(void) {
    void         *drcontext;
    instrlist_t  *ilist;
    instr_t      *where;
    byte         *end;

    drcontext = dr_get_current_drcontext();


    ccTraceIOPC = (app_pc)(dr_nonheap_alloc(cleanCallAllocSize,
        DR_MEMPROT_READ |
        DR_MEMPROT_WRITE |
        DR_MEMPROT_EXEC));
    ilist = instrlist_create(drcontext);

    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);
    /*where = INSTR_CREATE_ret(drcontext);
    instrlist_meta_append(ilist, where);*/
    dr_insert_clean_call(drcontext, ilist, where, (void *)ccTraceIO,
        false, 0);

    end = instrlist_encode(drcontext, ilist, ccTraceIOPC, false);
    if (!((size_t)(end - ccTraceIOPC) < cleanCallAllocSize)) {
        dr_fprintf(STDERR, "Page size not enough to encode clean call TraceIO\n");
    }
    instrlist_clear_and_destroy(drcontext, ilist);

    dr_memory_protect(ccTraceIOPC, cleanCallAllocSize, DR_MEMPROT_READ | DR_MEMPROT_EXEC);

    ccQueryPerformanceCounterPC = (app_pc)(dr_nonheap_alloc(cleanCallAllocSize,
        DR_MEMPROT_READ |
        DR_MEMPROT_WRITE |
        DR_MEMPROT_EXEC));
    ilist = instrlist_create(drcontext);

    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);
    /*where = INSTR_CREATE_ret(drcontext);
    instrlist_meta_append(ilist, where);*/
    dr_insert_clean_call(drcontext, ilist, where, (void*)ccQueryPerformanceCounter,
        false, 0);

    end = instrlist_encode(drcontext, ilist, ccQueryPerformanceCounterPC, false);
    if (!((size_t)(end - ccQueryPerformanceCounterPC) < cleanCallAllocSize)) {
        dr_fprintf(STDERR, "Page size not enough to encode clean call QueryPerformanceCounter\n");
    }
    instrlist_clear_and_destroy(drcontext, ilist);

    dr_memory_protect(ccQueryPerformanceCounterPC, cleanCallAllocSize, DR_MEMPROT_READ | DR_MEMPROT_EXEC);
}


static void code_cache_exit(void) {
    dr_nonheap_free(ccTraceIOPC, cleanCallAllocSize);
    dr_nonheap_free(ccQueryPerformanceCounterPC, cleanCallAllocSize);
}


static void onThreadInit(void *drcontext) {
    dr_fprintf(STDOUT, "Init thread %d\n", thread_index);

    threadData_t *data = NULL;

    data = (threadData_t*)(
        dr_thread_alloc(drcontext, sizeof(threadData_t)));
    if (data == NULL) {
        dr_fprintf(STDERR, "Could not allocate thread data\n");
        return;
    }
    if (!drmgr_set_tls_field(drcontext, tls_index, data)) {
        dr_fprintf(STDERR, "Could not set thread local storage\n");
        return;
    }

    data->bufferBase = dr_thread_alloc(drcontext, MEM_BUF_SIZE);
    data->bufferPtr = data->bufferBase;
    data->bufferEnd = (char*)(data->bufferBase) + MEM_BUF_SIZE;

#ifdef REGINA_BINARY
    data->file = fopen((std::string("memtrace_rv2_") 
        + std::to_string(thread_index) + std::string(".mmtrd")).c_str(), "wb");
#else
    char filenameBuf[1024];
    sprintf(filenameBuf, "memtrace_rv2_%d.mmtrd", thread_index);
    /*data->file = fopen((std::string("memtrace_rv2_")
        + std::to_string(thread_index) + std::string(".mmtrd")).c_str(), "w");*/
    data->file = fopen(filenameBuf, "w");
    fprintf(data->file, "Addr, dAddr, Type, TimerState, StartTime, EndTime\n");
#endif

    thread_index++;
}


static void onThreadExit(void *drcontext) {
    dr_fprintf(STDOUT, "Exit thread\n");

    // write remaining buffer entries
    traceIO(drcontext);

    threadData_t *data = (threadData_t*)(
        drmgr_get_tls_field(drcontext, tls_index));

    fclose(data->file);

    dr_thread_free(drcontext, data->bufferBase, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(threadData_t));
}


static dr_emit_flags_t onBBApp2App(void *drcontext, void *tag, instrlist_t *bb,
    bool for_trace, bool translating) {
    if (!drutil_expand_rep_string(drcontext, bb)) {
        dr_fprintf(STDERR, "Could not expand string loops\n");
    }

    return DR_EMIT_DEFAULT;
}


static dr_emit_flags_t onBBInsert(void *drcontext, void *tag, instrlist_t *bb,
    instr_t *instr, bool for_trace, bool translating, void *user_data) {
    if (instr_get_app_pc(instr) == NULL) {
        return DR_EMIT_DEFAULT;
    }

    //dr_fprintf(STDOUT, "Instrumenting BB\n");

    if (instr_reads_memory(instr)) {
        for (int i = 0; i < instr_num_srcs(instr); i++) {
            if (opnd_is_memory_reference(instr_get_src(instr, i))) {
                instrument(drcontext, bb, instr, i, false);
            }
        }
    }

    if (instr_writes_memory(instr)) {
        for (int i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
                instrument(drcontext, bb, instr, i, true);
            }
        }
    }

    return DR_EMIT_DEFAULT;
}


static void onExit(void) {
#ifdef REGINA_BINARY
    // read trace file and perform symbol queries
    dr_fprintf(STDOUT, "Performing symbol queries\n");

    symbolIndexMap_t sim;
    int symbolCounter = 0;

    // read for each thread the corresponding file
    for (int i = 0; i < thread_index; i++) {
        FILE *f = fopen((std::string("memtrace_rv2_")
            + std::to_string(i) + std::string(".mmtrd")).c_str(), "rwb");

        int fileSz = fseek(f, 0, SEEK_END);
        rewind(f);

        int numTraces = fileSz / sizeof(traceData_t);

        traceData_t *traces = new traceData_t[numTraces];

        fread(traces, 1, fileSz, f);

        std::vector<traceDataWS_t> traceBuffer(numTraces);

        for (int traceIdx = 0; traceIdx < numTraces; traceIdx++) {
            traceDataWS_t tmp;
            tmp = traces[traceIdx];

            // perform symbol queries
            std::string symbol;
            symbolLookUp(static_cast<app_pc>(traces[traceIdx].iAddr), symbol);

            auto fit = sim.find(symbol);
            if (fit != sim.end()) {
                // symbol already exists -> use its index
                tmp.symbolIDX = fit->second;
            } else {
                sim.insert(std::make_pair(symbol, symbolCounter));
                tmp.symbolIDX = symbolCounter;
                symbolCounter++;
            }

            traceBuffer[traceIdx] = tmp;
        }

        delete[] traces;

        dr_write_file(f, traceBuffer.data(), traceBuffer.size() * sizeof(traceDataWS_t));

        fclose(f);
    }

    // write derived partial symbol table on disk
    FILE *symf = fopen((std::string("memtrace_rv2")
        + std::string(".mmsym")).c_str(), "wb");

    for (auto &e : sim) {
        fprintf(symf, "%d|%s\n", e.second, e.first);
    }

    fclose(symf);
#endif

    dr_fprintf(STDOUT, "Client cleanup\n");

    code_cache_exit();

    if (!drmgr_unregister_tls_field(tls_index)) {
        dr_fprintf(STDERR, "Could not unregister tls field\n");
    }

    if (!drmgr_unregister_thread_init_event(onThreadInit) ||
        !drmgr_unregister_thread_exit_event(onThreadExit) ||
        !drmgr_unregister_bb_insertion_event(onBBInsert)) {
        dr_fprintf(STDERR, "Could not unregister event\n");
    }

    if (drreg_exit() != DRREG_SUCCESS) {
        dr_fprintf(STDERR, "Could not release clobbered register slots\n");
    }

    drutil_exit();
    drmgr_exit();
    drsym_exit();
}


DR_EXPORT
void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    drreg_options_t ops = {sizeof(ops), 3, false};

    drmgr_priority_t priority = {
        sizeof(drmgr_priority_t),
        "reginaV2",
        NULL,
        NULL,
        0
    };
    dr_set_client_name("DynamoRIO client regina v2", "-");

    pageSize = dr_page_size();
    cleanCallAllocSize = pageSize;

    dr_enable_console_printing();

    drmgr_init();
    drutil_init();

    dr_register_exit_event(onExit);
    if (!drmgr_register_thread_init_event(onThreadInit) ||
        !drmgr_register_thread_exit_event(onThreadExit) ||
        !drmgr_register_bb_app2app_event(onBBApp2App, &priority) ||
        !drmgr_register_bb_instrumentation_event(NULL, onBBInsert, &priority)) {
        dr_fprintf(STDERR, "Could not register event\n");
        return;
    }

    if (drreg_init(&ops) != DRREG_SUCCESS) {
        dr_fprintf(STDERR, "Could not clobber register slots\n");
        return;
    }

    if (drsym_init(NULL) != DRSYM_SUCCESS) {
        dr_fprintf(STDERR, "Could not initialize symbol access tool\n");
        return;
    }

    tls_index = drmgr_register_tls_field();
    if (tls_index == -1) {
        dr_fprintf(STDERR, "Could not register tls field\n");
        return;
    }

    code_cache_init();
}

/*
typedef struct _threadData_t {
    FILE *file;
    void *bufferBase;
    void *bufferPtr;
    void *bufferEnd;
} threadData_t;

typedef struct _traceData_t {
    void *iAddr;
    int32_t iType;
    uint64_t startT;
    uint64_t endT;
} traceData_t;
*/

static void instrument(void *drcontext, instrlist_t *ilist, instr_t *where,
    int pos, bool write) {
    reg_id_t reg1;
    reg_id_t regCX;

    // set vector to reserve some registers, default none
    drvector_t allowed;
    drreg_init_and_fill_vector(&allowed, false);
    // we want to reserve CX register
    drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
    // reserve two registers
    if (drreg_reserve_register(drcontext, ilist, where, &allowed, &regCX) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg1) != DRREG_SUCCESS) {
        drvector_delete(&allowed);
        return;
    }
    drvector_delete(&allowed);

    // specify instructions inserted before where
    // this would be the capturing of meta information on the mem reference
    // and a perf query to get the start timer

    opnd_t opnd1, opnd2;
    instr_t *instr;

    opnd_t ref;
    if (write)
        ref = instr_get_dst(where, pos);
    else
        ref = instr_get_src(where, pos);

    //drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg1, regCX);

    // get trace buffer current ptr
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, regCX);
    // now load it
    opnd1 = opnd_create_reg(regCX);
    opnd2 = OPND_CREATE_MEMPTR(regCX, offsetof(threadData_t, bufferPtr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // store data addr
    /*opnd1 = OPND_CREATE_MEMPTR(regCX, offsetof(traceData_t, dAddr));
    opnd2 = opnd_create_reg(reg1);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);*/

    // get instr pc
    /*app_pc pc = instr_get_app_pc(where);
    opnd1 = OPND_CREATE_MEMPTR(regCX, offsetof(traceData_t, iAddr));
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd1, ilist, where, nullptr, nullptr);*/

#pragma region TRACEIOJUMP
    // increment bufferPtr
    opnd1 = opnd_create_reg(regCX);
    opnd2 = opnd_create_base_disp(regCX, DR_REG_NULL, 0, sizeof(traceData_t), OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // store new pointer value
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg1);
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(threadData_t, bufferPtr));
    opnd2 = opnd_create_reg(regCX);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // check jump condition
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg1, offsetof(threadData_t, bufferEnd));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    opnd1 = opnd_create_reg(regCX);
    opnd2 = opnd_create_base_disp(reg1, regCX, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // jump if condition met
    instr_t *ccTraceIOCallTarget = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(ccTraceIOCallTarget);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // if we get here we must jump to skip clean call
    instr_t *ccTraceIORestoreTarget = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(ccTraceIORestoreTarget);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // set call jump target
    instrlist_meta_preinsert(ilist, where, ccTraceIOCallTarget);

    // make the jump to clean call
    opnd1 = opnd_create_reg(regCX);
    opnd1 = opnd_create_instr(ccTraceIORestoreTarget);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    opnd1 = opnd_create_pc(ccTraceIOPC);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    //instr = INSTR_CREATE_call(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // set restore target
    instrlist_meta_preinsert(ilist, where, ccTraceIORestoreTarget);
#pragma endregion


    // restore registers
    if (drreg_unreserve_register(drcontext, ilist, where, reg1) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, regCX) != DRREG_SUCCESS)
        DR_ASSERT(false);
}


static void traceIO(void *drcontext) {
    threadData_t *data = (threadData_t*)
        (drmgr_get_tls_field(drcontext, tls_index));

#ifdef REGINA_BINARY
    dr_write_file(data->file, data->bufferBase,
        (size_t)data->bufferPtr - (size_t)data->bufferBase);
#else
    traceData_t *cur = (traceData_t*)(data->bufferBase);

    traceData_t *ptr = (traceData_t*)(data->bufferPtr);

    traceData_t *end = (traceData_t*)(data->bufferEnd);

    //for (size_t i = 0; i < numTraces; i++) {
    //    fprintf(data->file, "%llx, %llx, %d, %d, %lld, %lld\n", ptr[i].iAddr,
    //        ptr[i].dAddr, ptr[i].iType, ptr[i].timerState, ptr[i].startT,
    //        ptr[i].endT); //< access violation
    //}

    while (cur <= ptr && cur < end) {
        fprintf(data->file, "%llx, %llx, %d, %d, %lld, %lld\n", cur->iAddr,
            cur->dAddr, cur->iType, cur->timerState, cur->startT,
            cur->endT);
        cur += sizeof(traceData_t);
    }
#endif

    data->bufferPtr = data->bufferBase;
}


//static void symbolLookUp(app_pc addr, std::string &symbol) {
//    // lookup module containing address, might be null
//    module_data_t *data = dr_lookup_module(addr);
//
//    if (data == nullptr) {
//        // module not found
//        return;
//    }
//
//    const int MAX_SYMBOL_NAME = 256;
//
//    char symName[MAX_SYMBOL_NAME];
//    char symFile[MAXIMUM_PATH];
//
//    // initialize symbol info struct
//    drsym_info_t sym;
//    sym.struct_size = sizeof(sym);
//    sym.name = symName;
//    sym.name_size = MAX_SYMBOL_NAME;
//    sym.file = symFile;
//    sym.file_size = MAXIMUM_PATH;
//
//    drsym_error_t symres = drsym_lookup_address(data->full_path,
//        addr - data->start, &sym, DRSYM_DEMANGLE_FULL);
//
//    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
//        std::stringstream stream;
//
//        // get name of module
//        const char *modname = dr_module_preferred_name(data);
//        if (modname == nullptr) {
//            modname = "<noname>";
//        }
//
//        stream << modname << '#' << sym.name;
//        if (symres != DRSYM_ERROR_LINE_NOT_AVAILABLE) {
//            // source information is available
//            stream << '#' << sym.file << '#' << sym.line;
//        }
//
//        symbol = stream.str();
//    }
//
//    dr_free_module_data(data);
//}