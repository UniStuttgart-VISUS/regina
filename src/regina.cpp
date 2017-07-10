#include <stdio.h>
#include <stdint.h>
#include <string>
#include <sstream>

#include <Windows.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drsyms.h"


static int tls_index = -1;
static int thread_index = 0;
static size_t pageSize = 0;
static app_pc ccTraceIOPC = nullptr;
static app_pc ccQueryPerformanceCounterPC = nullptr;

typedef struct _threadData_t {
    FILE *file;
    void *bufferBase;
    void *bufferPtr;
    void *bufferEnd;
} threadData_t;

typedef struct _traceData_t {
    void *iAddr;
    int32_t iType;
    int32_t timerState;
    uint64_t startT;
    uint64_t endT;
} traceData_t;

typedef struct _traceDataWS_t {
    void *iAddr;
    int32_t iType;
    int32_t timerState;
    uint64_t startT;
    uint64_t endT;
    uint32_t symbolIDX;
} traceDataWS_t;

#define MAX_NUM_MEM_REFS 1000000

#define MEM_BUF_SIZE (sizeof(traceData_t)*MAX_NUM_MEM_REFS)


static void instrument(void *drcontext, instrlist_t *ilist, instr_t *where,
    bool write);

static void traceIO(void *drcontext);

static void symbolLookUp(app_pc addr, std::string &symbol);


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
    threadData_t *data = static_cast<threadData_t*>(
        drmgr_get_tls_field(drcontext, tls_index));
    traceData_t *tPtr = static_cast<traceData_t*>(data->bufferPtr);

    LARGE_INTEGER timer;
    bool success = QueryPerformanceCounter(&timer); //< the expensive part

    if (success) {
        if (tPtr->timerState == 0) {
            tPtr->timerState = 1;
            tPtr->startT = timer.QuadPart;
        } else if (tPtr->timerState == 1) {
            tPtr->timerState = 0;
            tPtr->endT = timer.QuadPart;
        }
    } else {
        tPtr->timerState = 3;
    }
}


static void code_cache_init(void) {
    void         *drcontext;
    instrlist_t  *ilist;
    instr_t      *where;
    byte         *end;

    drcontext = dr_get_current_drcontext();
    ccTraceIOPC = static_cast<app_pc>(dr_nonheap_alloc(pageSize,
        DR_MEMPROT_READ |
        DR_MEMPROT_WRITE |
        DR_MEMPROT_EXEC));
    ilist = instrlist_create(drcontext);

    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);
    dr_insert_clean_call(drcontext, ilist, where, (void *)ccTraceIO,
        false, 0);

    end = instrlist_encode(drcontext, ilist, ccTraceIOPC, false);
    if (!(size_t)(end - ccTraceIOPC) < pageSize) {
        dr_fprintf(STDERR, "Page size not enough to encode clean call\n");
    }
    instrlist_clear_and_destroy(drcontext, ilist);

    dr_memory_protect(ccTraceIOPC, pageSize, DR_MEMPROT_READ | DR_MEMPROT_EXEC);
}


static void code_cache_exit(void) {
    dr_nonheap_free(ccTraceIOPC, pageSize);
}


static void onThreadInit(void *drcontext) {
    dr_fprintf(STDOUT, "Init thread %d\n", thread_index);

    threadData_t *data = nullptr;

    data = static_cast<threadData_t*>(
        dr_thread_alloc(drcontext, sizeof(threadData_t)));
    if (data == nullptr) {
        dr_fprintf(STDERR, "Could not allocate thread data\n");
        return;
    }
    if (!drmgr_set_tls_field(drcontext, tls_index, data)) {
        dr_fprintf(STDERR, "Could not set thread local storage\n");
        return;
    }

    data->bufferBase = dr_thread_alloc(drcontext, MEM_BUF_SIZE);
    data->bufferPtr = data->bufferBase;
    data->bufferEnd = static_cast<char*>(data->bufferBase) + MEM_BUF_SIZE;

    data->file = fopen((std::string("memtrace_rv2_") 
        + std::to_string(thread_index) + std::string(".mmtrd")).c_str(), "wb");

    thread_index++;
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
    if (instr_get_app_pc(instr) == nullptr) {
        return DR_EMIT_DEFAULT;
    }

    if (instr_reads_memory(instr)) {
        instrument(drcontext, bb, instr, false);
        /*for (int i = 0; i < instr_num_srcs(instr); i++) {
            if (opnd_is_memory_reference(instr_get_src(instr, i))) {
            }
        }*/
    }

    if (instr_writes_memory(instr)) {
        instrument(drcontext, bb, instr, true);
        /*for (int i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            }
        }*/
    }

    return DR_EMIT_DEFAULT;
}


static void onExit(void) {
    // read trace file and perform symbol queries
    dr_fprintf(STDOUT, "Performing symbol queries\n");

    // read for each thread the corresponding file
    for (int i = 0; i < thread_index; i++) {
        FILE *f = fopen((std::string("memtrace_rv2_")
            + std::to_string(i) + std::string(".mmtrd")).c_str(), "rwb");

        int fileSz = fseek(f, 0, SEEK_END);
        rewind(f);

        traceData_t *traces = new traceData_t[fileSz / sizeof(traceData_t)];

        fread(traces, 1, fileSz, f);

        // perform symbol queries
        

        fclose(f);
    }


    dr_fprintf(STDOUT, "Client cleanup\n");

    code_cache_exit();

    if (!drmgr_unregister_tls_field(tls_index)) {
        dr_fprintf(STDERR, "Could not unregister tls field\n");
    }

    if (!drmgr_unregister_thread_init_event(onThreadInit) ||
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
    drreg_options_t ops = {sizeof(drreg_options_t), 3, false};

    drmgr_priority_t priority = {
        sizeof(drmgr_priority_t),
        "reginaV2",
        nullptr,
        nullptr,
        0
    };
    dr_set_client_name("DynamoRIO client regina v2", "-");

    pageSize = dr_page_size();

    dr_enable_console_printing();

    drmgr_init();
    drutil_init();

    dr_register_exit_event(onExit);
    if (!drmgr_register_thread_init_event(onThreadInit) ||
        !drmgr_register_bb_app2app_event(onBBApp2App, &priority) ||
        !drmgr_register_bb_instrumentation_event(nullptr, onBBInsert, &priority)) {
        dr_fprintf(STDERR, "Could not register event\n");
        return;
    }

    if (drreg_init(&ops) != DRREG_SUCCESS) {
        dr_fprintf(STDERR, "Could not clobber register slots\n");
        return;
    }

    if (drsym_init(nullptr) != DRSYM_SUCCESS) {
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
    bool write) {
    reg_id_t reg1;
    reg_id_t regCX;

    // set vector to reserve some registers, default none
    drvector_t allowed;
    drreg_init_and_fill_vector(&allowed, false);
    // we want to reserve CX register
    drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
    // reserve two registers
    if (drreg_reserve_register(drcontext, ilist, where, &allowed, &regCX) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, nullptr, &reg1) != DRREG_SUCCESS) {
        drvector_delete(&allowed);
        return;
    }
    drvector_delete(&allowed);

    // specify instructions inserted before where
    // this would the capturing of meta information on the mem reference
    // and a perf query to get the start timer

    opnd_t opnd1, opnd2;
    instr_t *instr;

    // get trace buffer current ptr
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, regCX);
    // now load it
    opnd1 = opnd_create_reg(regCX);
    opnd2 = OPND_CREATE_MEMPTR(regCX, offsetof(threadData_t, bufferPtr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // store read/write flag
    opnd1 = OPND_CREATE_MEM32(regCX, offsetof(traceData_t, iType));
    if (write) {
        opnd2 = OPND_CREATE_INT32(1);
    } else {
        opnd2 = OPND_CREATE_INT32(0);
    }
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // set timerState to 0 -> timer started
    opnd1 = OPND_CREATE_MEM32(regCX, offsetof(traceData_t, timerState));
    opnd2 = OPND_CREATE_INT32(0);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);


    // set jump restore label
    instr_t *startTimerRestoreLabel = INSTR_CREATE_label(drcontext);

    // load jump restore label to CX reg
    opnd1 = opnd_create_reg(regCX);
    opnd2 = opnd_create_instr(startTimerRestoreLabel);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // jump to code cache
    opnd1 = opnd_create_pc(ccQueryPerformanceCounterPC);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    // set restore jump target
    instrlist_meta_preinsert(ilist, where, startTimerRestoreLabel);

    // specify instructions inserted after where
    // this would be a perf query for the end timer
    // and the overflow check for the trace buffer

    // set jump restore label
    instr_t *endTimerRestoreLabel = INSTR_CREATE_label(drcontext);

    // load jump restore label to CX reg
    opnd1 = opnd_create_reg(regCX);
    opnd2 = opnd_create_instr(endTimerRestoreLabel);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_postinsert(ilist, where, instr);

    // jump to code cache
    opnd1 = opnd_create_pc(ccQueryPerformanceCounterPC);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_postinsert(ilist, where, instr);

    // set restore jump target
    instrlist_meta_postinsert(ilist, where, endTimerRestoreLabel);

    // increment bufferPtr
    opnd1 = opnd_create_reg(regCX);
    opnd2 = opnd_create_base_disp(regCX, DR_REG_NULL, 0, sizeof(traceData_t),
        OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_postinsert(ilist, where, instr);

    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg1);
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(threadData_t, bufferPtr));
    opnd2 = opnd_create_reg(regCX);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_postinsert(ilist, where, instr);

    // jump to IO clean call, if buffer is full
    // set CX reg to jump condition
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg1, offsetof(threadData_t, bufferEnd));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_postinsert(ilist, where, instr);
    opnd1 = opnd_create_reg(regCX);
    opnd2 = opnd_create_base_disp(reg1, regCX, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_postinsert(ilist, where, instr);

    // set jump call label
    instr_t *traceIOCallLabel = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(traceIOCallLabel);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_postinsert(ilist, where, instr);

    // set jump restore label and jump there, if clean call cond not met
    instr_t *traceIORestoreLabel = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(traceIORestoreLabel);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_postinsert(ilist, where, instr);

    // do the call
    instrlist_meta_postinsert(ilist, where, traceIOCallLabel);
    // set restore target
    opnd1 = opnd_create_reg(regCX);
    opnd2 = opnd_create_instr(traceIORestoreLabel);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_postinsert(ilist, where, instr);
    // jump to traceIO clean call
    opnd1 = opnd_create_pc(ccTraceIOPC);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_postinsert(ilist, where, instr);

    // restore target
    instrlist_meta_postinsert(ilist, where, traceIORestoreLabel);

    // restore registers
    if (drreg_unreserve_register(drcontext, ilist, where, reg1) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, regCX) != DRREG_SUCCESS)
        DR_ASSERT(false);
}


static void traceIO(void *drcontext) {
    threadData_t *data = static_cast<threadData_t*>(
        drmgr_get_tls_field(drcontext, tls_index));

#ifdef REGINA_BINARY
    dr_write_file(data->file, data->bufferBase,
        static_cast<size_t>(data->bufferPtr - data->bufferBase));
#else
    traceData_t *ptr = static_cast<traceData_t*>(data->bufferBase);

    int numTraces = static_cast<int>(static_cast<traceData_t*>(data->bufferPtr)
        - static_cast<traceData_t*>(data->bufferBase));

    for (int i = 0; i < numTraces; i++) {
        dr_fprintf(data->file, "%llx, %d, %d, %lld, %lld\n", ptr[i].iAddr,
            ptr[i].iType, ptr[i].timerState, ptr[i].startT, ptr[i].endT);
    }
#endif

    data->bufferPtr = data->bufferBase;
}


static void symbolLookUp(app_pc addr, std::string &symbol) {
    // lookup module containing address, might be null
    module_data_t *data = dr_lookup_module(addr);

    if (data == nullptr) {
        // module not found
        return;
    }

    const int MAX_SYMBOL_NAME = 256;

    char symName[MAX_SYMBOL_NAME];
    char symFile[MAXIMUM_PATH];

    // initialize symbol info struct
    drsym_info_t sym;
    sym.struct_size = sizeof(sym);
    sym.name = symName;
    sym.name_size = MAX_SYMBOL_NAME;
    sym.file = symFile;
    sym.file_size = MAXIMUM_PATH;

    drsym_error_t symres = drsym_lookup_address(data->full_path,
        addr - data->start, &sym, DRSYM_DEMANGLE_FULL);

    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        std::stringstream stream;

        // get name of module
        const char *modname = dr_module_preferred_name(data);
        if (modname == nullptr) {
            modname = "<noname>";
        }

        stream << modname << '#' << sym.name;
        if (symres != DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            // source information is available
            stream << '#' << sym.file << '#' << sym.line;
        }

        symbol = stream.str();
    }

    dr_free_module_data(data);
}