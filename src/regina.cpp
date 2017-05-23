#include <vector>
#include <iostream>
#include <string.h>
#include <sstream>
#include <cstdio>
#include <cstddef>
#include <unordered_map>

#include "dr_api.h"
#include "dr_config.h"

#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drsyms.h"

#include "log.h"
#include "per_thread_t.h"
#include "trace_ref_t.h"
#include "fileio.h"


#define MAX_TRACE_STORAGE_SIZE 10000


// Forward declarations
static void event_exit(void);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag,
    instrlist_t *bb, instr_t *instr, bool for_trace, bool translating,
    void *user_data);
static dr_emit_flags_t event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
    bool for_trace, bool translating);
static void cb_mem_ref();
static void translate_addr(app_pc addr, std::string &sym_string);
#ifdef WIN32
static bool event_exception(void *drcontext, dr_exception_t *excpt);
#else
static dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *siginfo);
#endif
//---------------------


// Global variables
static int tls_index;
static glb_trc_str trace_storage;
static int thread_idx;
static app_pc code_cache;
static drsym_type_t *types;
static std::unordered_map<std::string, size_t> symbol_lookup;
static size_t symbol_idx;
//-----------------
typedef FileIO<true, true> _FileIO;

static _FileIO filer;


static void clean_call(void);

static bool signalIO = false;

static void
code_cache_init(void) {
    void         *drcontext;
    instrlist_t  *ilist;
    instr_t      *where;
    byte         *end;

    drcontext = dr_get_current_drcontext();
    code_cache = static_cast<app_pc>(dr_nonheap_alloc(dr_page_size(),
        DR_MEMPROT_READ |
        DR_MEMPROT_WRITE |
        DR_MEMPROT_EXEC));
    ilist = instrlist_create(drcontext);
    /* The lean procecure simply performs a clean call, and then jump back */
    /* jump back to the DR's code cache */
    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);
    /* clean call */
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call, false, 0);
    /* Encodes the instructions into memory and then cleans up. */
    end = instrlist_encode(drcontext, ilist, code_cache, false);
    //DR_ASSERT((size_t)(end - code_cache) < page_size);
    instrlist_clear_and_destroy(drcontext, ilist);
    /* set the memory as just +rx now */
    dr_memory_protect(code_cache, dr_page_size(), DR_MEMPROT_READ | DR_MEMPROT_EXEC);
}


static void code_cache_exit(void) {
    dr_nonheap_free(code_cache, dr_page_size());
}




static void clean_call(void) {
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *data = static_cast<per_thread_t *>(drmgr_get_tls_field(drcontext, tls_index));

    //int thread_idx = data->thread_idx;

    trace_storage[data->thread_idx].push_back(trace_ref_t(*(data->buf)));
    memset(data->buf, 0, sizeof(trace_ref_t));
}





static bool event_exception(void *drcontext, dr_exception_t *excpt) {
    return true;
}


/*
 * dr_client_main
 */
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_log(NULL, LOG_ALL, 1, "Client 'regina' initializing\n");
    //REGINA_LOG("Client 'regina' initializing\n");

    // Client setup
    dr_set_client_name("regina -- mem- and call-trace", "-");
    dr_set_client_version_string("0.1.0");

    drreg_options_t ops = {sizeof(ops), 3, false};

    /* Specify priority relative to other instrumentation operations: */
    drmgr_priority_t priority = {
        sizeof(priority), /* size of struct */
        "memtrace",       /* name of our operation */
        NULL,             /* optional name of operation we should precede */
        NULL,             /* optional name of operation we should follow */
        0};               /* numeric priority */

    // Init extension
    if (!drmgr_init()) {
        //REGINA_LOG_ERROR("Failed to initialize drmgr\n");
        return;
    }

    // Register events
    dr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
#ifdef WIN32
        !drmgr_register_exception_event(event_exception) ||
#else
        !drmgr_register_signal_event(event_signal) ||
#endif
        !drmgr_register_bb_app2app_event(event_bb_app2app, &priority) ||
        !drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, &priority) ||
        drreg_init(&ops) != DRREG_SUCCESS ||
        drsym_init(NULL) != DRSYM_SUCCESS) {
        //REGINA_LOG_ERROR("Unable to register drmgr events\n");
        DR_ASSERT(false);
        return;
    }

    tls_index = drmgr_register_tls_field();
    if (tls_index == -1) {
        //REGINA_LOG_ERROR("No TLS fields available\n");
        return;
    }

    thread_idx = 0;

    symbol_idx = 0;

    types = new drsym_type_t[3];

    code_cache_init();

    // Notify dr log of this client
    dr_log(NULL, LOG_ALL, 1, "Client 'regina' is running\n");
    //REGINA_LOG("Client 'regina' is running\n");
}


/*
 * event_exit
 */
static void event_exit(void) {
    code_cache_exit();

    // Unregister events
    if (!drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
#ifdef WIN32
        !drmgr_unregister_exception_event(event_exception) ||
#else
        !drmgr_unregister_signal_event(event_signal) ||
#endif
        !drmgr_unregister_bb_insertion_event(event_app_instruction)) {
        //REGINA_LOG_ERROR("Unable to unregister drmgr events\n");
    }

    // Exit extensions
    drreg_exit();
    drsym_exit();
    drmgr_exit();

    FILE *lookupIO = std::fopen("regina.0.mmtrd.txt", "w");
    for (auto &e : symbol_lookup) {
        std::string tmp = std::to_string(e.second)+"|"+ e.first + "\n";
        std::fwrite(tmp.c_str(), strlen(tmp.c_str()), 1, lookupIO);
    }
    std::fclose(lookupIO);
}


/*
 * event_thread_init
 */
static void event_thread_init(void *drcontext) {
    // Push a storage for this thread
    trace_storage.push_back(thr_trc_str());

    // Create thread local storage
    per_thread_t *data;

    data = static_cast<per_thread_t *>(dr_thread_alloc(drcontext, sizeof(per_thread_t)));
    drmgr_set_tls_field(drcontext, tls_index, data);

    data->thread_idx = thread_idx;
    data->buf = static_cast<trace_ref_t *>(dr_thread_alloc(drcontext, sizeof(trace_ref_t)));
    char filename[1024];
    sprintf(filename, "regina.%d.log", thread_idx);
    data->f = fopen(filename, "w");

    sprintf(filename, "regina.%d.mmtrd", thread_idx);
    data->fileIO = fopen(filename, "wb");
    /*data->fileIO = static_cast<FileIO<true, true> *>(dr_thread_alloc(drcontext, sizeof(FileIO<true, true>)));
    *(data->fileIO) = std::move(FileIO<true, true>(filename));*/

    thread_idx++;
}


/*
 * event_thread_exit
 */
static void event_thread_exit(void *drcontext) {
    // Free thread local storage
    per_thread_t *data;

    data = static_cast<per_thread_t *>(drmgr_get_tls_field(drcontext, tls_index));

#if 1
    if (!trace_storage[data->thread_idx].empty()) {
        // print out
        for (int i = 0; i < trace_storage[data->thread_idx].size(); i++) {
            trace_ref_t &tmp = trace_storage[data->thread_idx][i];
            if (tmp.is_mem_ref) {
                //fprintf(data->f, "mem %p\n", tmp.instr_addr);
                if (tmp.is_write) {
                    std::string str;
                    _FileIO::MemRef_t mrt;
                    mrt.is_write = true;
                    mrt.instr = tmp.instr_addr;
                    mrt.size = tmp.size;
                    mrt.data = tmp.data_addr;
                    translate_addr(tmp.instr_addr, str);
                    auto it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        mrt.symIdx = it->second;
                    } else {
                        mrt.symIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    mrt.instrSym = str;
                    filer.Print(data->fileIO, _FileIO::RefType::MemRef, &mrt);

                    /*print_address(data->f, tmp.instr_addr, "\t\t mem write @ ");
                    print_data(drcontext, data->f, tmp.instr_addr, tmp.data_addr, tmp.size, "\t\t\t type ");*/
                    //fprintf(data->f, "\t\t\t %u %p\n", tmp.size, tmp.data_addr);
                } else {
                    std::string str;
                    _FileIO::MemRef_t mrt;
                    mrt.is_write = false;
                    mrt.instr = tmp.instr_addr;
                    mrt.size = tmp.size;
                    mrt.data = tmp.data_addr;
                    translate_addr(tmp.instr_addr, str);
                    auto it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        mrt.symIdx = it->second;
                    } else {
                        mrt.symIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    mrt.instrSym = str;
                    filer.Print(data->fileIO, _FileIO::RefType::MemRef, &mrt);

                    /*print_address(data->f, tmp.instr_addr, "\t\t mem read @ ");
                    print_data(drcontext, data->f, tmp.instr_addr, tmp.data_addr, tmp.size, "\t\t\t type ");*/
                    //fprintf(data->f, "\t\t\t %u %p\n", tmp.size, tmp.data_addr);
                }
            } else {
                if (tmp.is_call) {
                    std::string str;

                    _FileIO::CallRetRef_t crt;
                    crt.instr = tmp.instr_addr;
                    crt.target = tmp.target_addr;
                    translate_addr(tmp.instr_addr, str);
                    auto it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        crt.instrSymIdx = it->second;
                    } else {
                        crt.instrSymIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    crt.instrSym = str;
                    translate_addr(tmp.target_addr, str);
                    it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        crt.targetSymIdx = it->second;
                    } else {
                        crt.targetSymIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    crt.targetSym = str;

                    if (tmp.is_ind) {
                        filer.Print(data->fileIO, _FileIO::RefType::CallIndRef, &crt);
                    } else {
                        filer.Print(data->fileIO, _FileIO::RefType::CallRef, &crt);
                    }

                    //fprintf(data->f, "call %p to %p\n", tmp.instr_addr, tmp.target_addr);
                    /*print_address(data->f, tmp.instr_addr, "call @ ");
                    print_address(data->f, tmp.target_addr, "\t to ");*/
                } else {
                    std::string str;

                    _FileIO::CallRetRef_t crt;
                    crt.instr = tmp.instr_addr;
                    crt.target = tmp.target_addr;
                    translate_addr(tmp.instr_addr, str);
                    auto it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        crt.instrSymIdx = it->second;
                    } else {
                        crt.instrSymIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    crt.instrSym = str;
                    translate_addr(tmp.target_addr, str);
                    it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        crt.targetSymIdx = it->second;
                    } else {
                        crt.targetSymIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    crt.targetSym = str;

                    filer.Print(data->fileIO, _FileIO::RefType::RetRef, &crt);

                    //fprintf(data->f, "return %p to %p\n", tmp.instr_addr, tmp.target_addr);
                    /*print_address(data->f, tmp.instr_addr, "return @ ");
                    print_address(data->f, tmp.target_addr, "\t to ");*/
                }
            }
        }
        trace_storage[data->thread_idx].clear();
    }
#endif

    fclose(data->f);
    fclose(data->fileIO);

    //dr_thread_free(drcontext, data->fileIO, sizeof(FileIO<true, true>));
    dr_thread_free(drcontext, data->buf, sizeof(trace_ref_t));
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}


// global callbacks forward decl
//static void cb_mem_ref(void *drcontext, instr_t *where, int pos, bool is_write);
//------------------------------

#define MAX_SYM_RESULT 256
//static void
//print_address(FILE *f, app_pc addr, const char *prefix) {
//    drsym_error_t symres;
//    drsym_info_t sym;
//    char name[MAX_SYM_RESULT];
//    char file[MAXIMUM_PATH];
//    module_data_t *data;
//    data = dr_lookup_module(addr);
//    if (data == NULL) {
//        fprintf(f, "%s %p ? ??:0\n", prefix, addr);
//        return;
//    }
//    sym.struct_size = sizeof(sym);
//    sym.name = name;
//    sym.name_size = MAX_SYM_RESULT;
//    sym.file = file;
//    sym.file_size = MAXIMUM_PATH;
//    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
//        DRSYM_DEFAULT_FLAGS);
//    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
//        const char *modname = dr_module_preferred_name(data);
//        if (modname == NULL)
//            modname = "<noname>";
//        fprintf(f, "%s %p %s!%s+%p", prefix, addr,
//            modname, sym.name, addr - data->start - sym.start_offs);
//        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
//            fprintf(f, " ??:0\n");
//        } else {
//            fprintf(f, " %s:%d + %d\n",
//                sym.file, sym.line, sym.line_offs);
//        }
//    } else
//        dr_fprintf(f, "%s %p ? ??:0\n", prefix, addr);
//    dr_free_module_data(data);
//}


static void translate_addr(app_pc addr, std::string &sym_string) {
    std::ostringstream stringStream;
    stringStream << std::hex;
    drsym_error_t symres;
    drsym_info_t sym;
    char name[MAX_SYM_RESULT];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        stringStream << "###";
        sym_string = stringStream.str();
        return;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = MAX_SYM_RESULT;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
        DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        const char *modname = dr_module_preferred_name(data);
        if (modname == NULL)
            modname = "<noname>";
        stringStream << modname << "#" << sym.name;// << "+" << addr - data->start - sym.start_offs;
        /*if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            stringStream << "##";
        } else {
            stringStream << "#" << sym.file << "#" << std::dec << sym.line << "+" << sym.line_offs;
        }*/
    } else
        stringStream << "###";
    sym_string = stringStream.str();
    dr_free_module_data(data);
}


static void
print_data(void *drcontext, FILE *f, app_pc addr, void *data_addr, uint size, const char *prefix) {
    drsym_error_t symres;
    drsym_info_t sym;
    char name[MAX_SYM_RESULT];
    char buf[MAX_SYM_RESULT];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        fprintf(f, "%s ? %u %p\n", prefix, size, data_addr);
        return;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = MAX_SYM_RESULT;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
        DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS) {
        //drsym_type_t *types = static_cast<drsym_type_t*>(dr_thread_alloc(drcontext, 3*sizeof(drsym_type_t)));
        symres = drsym_expand_type(data->full_path, sym.type_id, 2, buf, MAX_SYM_RESULT, &types);
        int i = 0;
        int j = -1;
        while (types[i].kind != DRSYM_TYPE_OTHER && i < 3) {
            i++;
            j++;
        }
        if (j >= 0) {
            if (types[i].kind == DRSYM_TYPE_INT) {
                fprintf(f, "%s INT %u %p\n", prefix, size, data_addr);
            } else if (types[i].kind == DRSYM_TYPE_PTR) {
                fprintf(f, "%s PTR %u %p\n", prefix, size, data_addr);
            } else if (types[i].kind == DRSYM_TYPE_FUNC) {
                fprintf(f, "%s FUNC %u %p\n", prefix, size, data_addr);
            } else if (types[i].kind == DRSYM_TYPE_VOID) {
                fprintf(f, "%s VOID %u %p\n", prefix, size, data_addr);
            } else if (types[i].kind == DRSYM_TYPE_COMPOUND) {
                fprintf(f, "%s COMPOUND %u %p\n", prefix, size, data_addr);
            }
        }
        //dr_thread_free(drcontext, types, 3 * sizeof(drsym_type_t));
    } else
        fprintf(f, "%s ? %u %p\n", prefix, size, data_addr);
    dr_free_module_data(data);
}


static dr_mcontext_t mc;
/*
* cb_mem_ref
*/
static void cb_mem_ref(/*instr_t *where, int pos, bool is_write*/) {
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *data = static_cast<per_thread_t *>(drmgr_get_tls_field(drcontext, tls_index));

    int thread_idx = data->thread_idx;
#if 1
    if (trace_storage[data->thread_idx].size() > MAX_TRACE_STORAGE_SIZE) {
        // print out
        for (int i = 0; i < trace_storage[data->thread_idx].size(); i++) {
            trace_ref_t &tmp = trace_storage[data->thread_idx][i];
            if (tmp.is_mem_ref) {
                //fprintf(data->f, "mem %p\n", tmp.instr_addr);
                if (tmp.is_write) {
                    std::string str;
                    _FileIO::MemRef_t mrt;
                    mrt.is_write = true;
                    mrt.instr = tmp.instr_addr;
                    mrt.size = tmp.size;
                    mrt.data = tmp.data_addr;
                    translate_addr(tmp.instr_addr, str);
                    auto it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        mrt.symIdx = it->second;
                    } else {
                        mrt.symIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    mrt.instrSym = str;
                    filer.Print(data->fileIO, _FileIO::RefType::MemRef, &mrt);

                    /*print_address(data->f, tmp.instr_addr, "\t\t mem write @ ");
                    print_data(drcontext, data->f, tmp.instr_addr, tmp.data_addr, tmp.size, "\t\t\t type ");*/
                    //fprintf(data->f, "\t\t\t %u %p\n", tmp.size, tmp.data_addr);
                } else {
                    std::string str;
                    _FileIO::MemRef_t mrt;
                    mrt.is_write = false;
                    mrt.instr = tmp.instr_addr;
                    mrt.size = tmp.size;
                    mrt.data = tmp.data_addr;
                    translate_addr(tmp.instr_addr, str);
                    auto it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        mrt.symIdx = it->second;
                    } else {
                        mrt.symIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    mrt.instrSym = str;
                    filer.Print(data->fileIO, _FileIO::RefType::MemRef, &mrt);

                    /*print_address(data->f, tmp.instr_addr, "\t\t mem read @ ");
                    print_data(drcontext, data->f, tmp.instr_addr, tmp.data_addr, tmp.size, "\t\t\t type ");*/
                    //fprintf(data->f, "\t\t\t %u %p\n", tmp.size, tmp.data_addr);
                }
            } else {
                if (tmp.is_call) {
                    std::string str;

                    _FileIO::CallRetRef_t crt;
                    crt.instr = tmp.instr_addr;
                    crt.target = tmp.target_addr;
                    translate_addr(tmp.instr_addr, str);
                    auto it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        crt.instrSymIdx = it->second;
                    } else {
                        crt.instrSymIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    crt.instrSym = str;
                    translate_addr(tmp.target_addr, str);
                    it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        crt.targetSymIdx = it->second;
                    } else {
                        crt.targetSymIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    crt.targetSym = str;

                    if (tmp.is_ind) {
                        filer.Print(data->fileIO, _FileIO::RefType::CallIndRef, &crt);
                    } else {
                        filer.Print(data->fileIO, _FileIO::RefType::CallRef, &crt);
                    }

                    //fprintf(data->f, "call %p to %p\n", tmp.instr_addr, tmp.target_addr);
                    /*print_address(data->f, tmp.instr_addr, "call @ ");
                    print_address(data->f, tmp.target_addr, "\t to ");*/
                } else {
                    std::string str;

                    _FileIO::CallRetRef_t crt;
                    crt.instr = tmp.instr_addr;
                    crt.target = tmp.target_addr;
                    translate_addr(tmp.instr_addr, str);
                    auto it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        crt.instrSymIdx = it->second;
                    } else {
                        crt.instrSymIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    crt.instrSym = str;
                    translate_addr(tmp.target_addr, str);
                    it = symbol_lookup.find(str);
                    if (it != symbol_lookup.end()) {
                        crt.targetSymIdx = it->second;
                    } else {
                        crt.targetSymIdx = symbol_idx;
                        symbol_lookup.insert(std::make_pair(str, symbol_idx++));
                    }
                    crt.targetSym = str;

                    filer.Print(data->fileIO, _FileIO::RefType::RetRef, &crt);

                    //fprintf(data->f, "return %p to %p\n", tmp.instr_addr, tmp.target_addr);
                    /*print_address(data->f, tmp.instr_addr, "return @ ");
                    print_address(data->f, tmp.target_addr, "\t to ");*/
                }
            }
        }
        trace_storage[data->thread_idx].clear();
    }
#endif

    //trace_ref_t trace(*(data->buf));
    /*trace.instr_addr = data->buf->instr_addr;
    trace.data_addr = data->buf->data_addr;
    trace.is_call = data->buf->is_call;
    trace.is_mem_ref = data->buf->is_mem_ref;
    trace.is_write = data->buf->is_write;
    trace.size = data->buf->size;
    trace.target_addr = data->buf->target_addr;*/
    trace_storage[data->thread_idx].push_back(trace_ref_t(*(data->buf)));
    memset(data->buf, 0, sizeof(trace_ref_t));
}


static void instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, int pos, bool iswrite) {
    drvector_t allowed;

    drreg_init_and_fill_vector(&allowed, false);
    drreg_set_vector_entry(&allowed, DR_REG_XCX, true);

    reg_id_t reg_ptr, reg_tmp;
    if (drreg_reserve_register(drcontext, ilist, where, &allowed, &reg_ptr) !=
        DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
        DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }
    drvector_delete(&allowed);

    instr_t *instr, *restore;
    opnd_t opnd1, opnd2, ref;

    if (iswrite) {
        ref = instr_get_dst(where, pos);
    } else {
        ref = instr_get_src(where, pos);
    }

    drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_tmp, reg_ptr);

    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg_ptr);
    // read tls field
    opnd1 = opnd_create_reg(reg_ptr);
    opnd2 = OPND_CREATE_MEMPTR(reg_ptr, offsetof(per_thread_t, buf));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // store is_write
    opnd1 = OPND_CREATE_MEM32(reg_ptr, offsetof(trace_ref_t, is_write));
    opnd2 = OPND_CREATE_INT32(iswrite);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // store is_mem_ref
    opnd1 = OPND_CREATE_MEM32(reg_ptr, offsetof(trace_ref_t, is_mem_ref));
    opnd2 = OPND_CREATE_INT32(true);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // store data addr
    opnd1 = OPND_CREATE_MEMPTR(reg_ptr, offsetof(trace_ref_t, data_addr));
    opnd2 = opnd_create_reg(reg_tmp);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // store data size
    opnd1 = OPND_CREATE_MEMPTR(reg_ptr, offsetof(trace_ref_t, size));
    opnd2 = OPND_CREATE_INT32(drutil_opnd_mem_size_in_bytes(ref, where));
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // store pc
    opnd1 = OPND_CREATE_MEMPTR(reg_ptr, offsetof(trace_ref_t, instr_addr));
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)instr_get_app_pc(where), opnd1, ilist, where, NULL, NULL);

    // store return address
    restore = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_reg(reg_ptr);
    opnd2 = opnd_create_instr(restore);
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    // jump to clean call
    opnd1 = opnd_create_pc(code_cache);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    instrlist_meta_preinsert(ilist, where, restore);

    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
}


static void at_call(app_pc instr_addr, app_pc target_addr) {
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *data = static_cast<per_thread_t *>(drmgr_get_tls_field(drcontext, tls_index));

    trace_ref_t trace;
    trace.is_mem_ref = false;
    trace.is_call = true;
    trace.is_ind = false;
    trace.instr_addr = instr_addr;
    trace.target_addr = target_addr;

    trace_storage[data->thread_idx].push_back(trace);
}


static void at_call_ind(app_pc instr_addr, app_pc target_addr) {
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *data = static_cast<per_thread_t *>(drmgr_get_tls_field(drcontext, tls_index));

    trace_ref_t trace;
    trace.is_mem_ref = false;
    trace.is_call = true;
    trace.is_ind = true;
    trace.instr_addr = instr_addr;
    trace.target_addr = target_addr;

    trace_storage[data->thread_idx].push_back(trace);
}


static void at_return(app_pc instr_addr, app_pc target_addr) {
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *data = static_cast<per_thread_t *>(drmgr_get_tls_field(drcontext, tls_index));

    trace_ref_t trace;
    trace.is_mem_ref = false;
    trace.is_call = false;
    trace.is_ind = false;
    trace.instr_addr = instr_addr;
    trace.target_addr = target_addr;

    trace_storage[data->thread_idx].push_back(trace);
}


/*
 * event_app_instruction
 */
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag,
    instrlist_t *bb, instr_t *instr, bool for_trace, bool translating,
    void *user_data) {
    // instrument calls, returns, and MOVs
    if (instr_get_app_pc(instr) == NULL)
        return DR_EMIT_DEFAULT;

    if (instr_is_call_direct(instr)) {
        dr_insert_call_instrumentation(drcontext, bb, instr, (app_pc)at_call);
    } else if (instr_is_call_indirect(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_call_ind,
            SPILL_SLOT_1);
    } else if (instr_is_return(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_return,
            SPILL_SLOT_1);
    } else if (instr_reads_memory(instr)) {
        int opcode = instr_get_opcode(instr);
        /*if (strncmp(decode_opcode_name(opcode), "mov", 3ul) == 0)*/
        if (!(strncmp(decode_opcode_name(opcode), "push", 4ul) == 0) &&
            !(strncmp(decode_opcode_name(opcode), "pop", 3ul) == 0))
        {
            for (int i = 0; i < instr_num_srcs(instr); i++) {
                if (opnd_is_memory_reference(instr_get_src(instr, i))) {
                    instrument_mem(drcontext, bb, instr, i, false);
                    //cb_mem_ref(drcontext, instr, i, false);
                    //dr_insert_clean_call(drcontext, bb, instr, cb_mem_ref, false, 2, OPND_CREATE_ABSMEM(instr, OPSZ_8), OPND_CREATE_INT32(i)/*, OPND_CREATE_INT8(false)*/);
                }
            }
        }
    } else if (instr_writes_memory(instr)) {
        int opcode = instr_get_opcode(instr);
        /*if (strncmp(decode_opcode_name(opcode), "mov", 3ul) == 0)*/
        if (!(strncmp(decode_opcode_name(opcode), "push", 4ul) == 0) &&
            !(strncmp(decode_opcode_name(opcode), "pop", 3ul) == 0))
        {
            for (int i = 0; i < instr_num_dsts(instr); i++) {
                if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
                    instrument_mem(drcontext, bb, instr, i, true);
                    //cb_mem_ref(drcontext, instr, i, true);
                    //dr_insert_clean_call(drcontext, bb, instr, cb_mem_ref, false, 2, OPND_CREATE_ABSMEM(instr, OPSZ_8), OPND_CREATE_INT32(i)/*, OPND_CREATE_INT8(true)*/);
                }
            }
        }
    }

    // do IO if trace_storage is about to overflow

    return DR_EMIT_DEFAULT;
}


static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
    bool for_trace, bool translating) {
    if (!drutil_expand_rep_string(drcontext, bb)) {
        DR_ASSERT(false);
        /* in release build, carry on: we'll just miss per-iter refs */
    }
    return DR_EMIT_DEFAULT;
}
