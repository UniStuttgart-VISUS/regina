#include <stdio.h>
#include <stdint.h>
#include <string>

#include <Windows.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"


static int tls_index = -1;
static int thread_index = 0;
static size_t pageSize = 0;
static app_pc codeCache = nullptr;

typedef struct _threadData_t {
    FILE *file;
    void *bufferBase;
    void *bufferPtr;
} threadData_t;

typedef struct _traceData_t {
    void *iAddr;
    void *dAddr;
    int32_t dSize;
    int32_t iType;
    uint64_t startT;
    uint64_t endT;
} traceData_t;

#define MAX_NUM_MEM_REFS 1000000

#define MEM_BUF_SIZE (sizeof(traceData_t)*MAX_NUM_MEM_REFS)


static void instrument(void *drcontext, instrlist_t *ilist, instr_t *where,
    int pos, bool write);


/**
 * DR clean call that writes current trace buffer onto disk.
 * Should only be called when trace buffer is about to overflow.
 */
static void ccTraceIO(void) {
    void *drcontext = dr_get_current_drcontext();

    //memtrace(drcontext);
}


/**
 * DR clean call to insert performance counter to get real-time stamp.
 * This call is very expensive, but should be free of system_calls.
 */
static void ccQueryPerformanceCounter(void) {
    LARGE_INTEGER timer;
    QueryPerformanceCounter(&timer);
}


static void code_cache_init(void) {
    void         *drcontext;
    instrlist_t  *ilist;
    instr_t      *where;
    byte         *end;

    drcontext = dr_get_current_drcontext();
    codeCache = static_cast<app_pc>(dr_nonheap_alloc(pageSize,
        DR_MEMPROT_READ |
        DR_MEMPROT_WRITE |
        DR_MEMPROT_EXEC));
    ilist = instrlist_create(drcontext);

    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);
    dr_insert_clean_call(drcontext, ilist, where, (void *)ccTraceIO,
        false, 0);

    end = instrlist_encode(drcontext, ilist, codeCache, false);
    if (!(size_t)(end - codeCache) < pageSize) {
        dr_fprintf(STDERR, "Page size not enough to encode clean call\n");
    }
    instrlist_clear_and_destroy(drcontext, ilist);

    dr_memory_protect(codeCache, pageSize, DR_MEMPROT_READ | DR_MEMPROT_EXEC);
}


static void code_cache_exit(void) {
    dr_nonheap_free(codeCache, pageSize);
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
    // read trace file and perform symbol queries
    dr_fprintf(STDOUT, "Performing symbol queries\n");



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
} threadData_t;

typedef struct _traceData_t {
    void *iAddr;
    void *dAddr;
    int32_t dSize;
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

    // specify instructions inserted after where
    // this would be a perf query for the end timer
    // and the overflow check for the trace buffer
}