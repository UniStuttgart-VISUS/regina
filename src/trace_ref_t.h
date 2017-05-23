#ifndef REGINA_TRACE_REF_T_H_INCLUDED
#define REGINA_TRACE_REF_T_H_INCLUDED

#include <vector>
#include <stdint.h>

#include "dr_api.h"

#pragma pack(1) //< TODO Christoph ist sich net sicher
typedef struct _trace_ref_t {
    int32_t is_mem_ref;
    int32_t is_write;
    int32_t is_call;
    int32_t is_ind;
    void *data_addr;
    uint size;
    app_pc instr_addr;
    app_pc target_addr;

    _trace_ref_t() { };

    _trace_ref_t &operator=(const _trace_ref_t &rhs) {
        this->is_mem_ref = rhs.is_mem_ref;
        this->is_write = rhs.is_write;
        this->is_call = rhs.is_call;
        this->is_ind = rhs.is_ind;
        this->data_addr = rhs.data_addr;
        this->size = rhs.size;
        this->instr_addr = rhs.instr_addr;
        this->target_addr = rhs.target_addr;

        return *this;
    }

    _trace_ref_t(const _trace_ref_t &rhs) {
        /*this->is_mem_ref = rhs.is_mem_ref;
        this->is_write = rhs.is_write;
        this->is_call = rhs.is_call;
        this->is_ind = rhs.is_ind;
        this->data_addr = rhs.data_addr;
        this->size = rhs.size;
        this->instr_addr = rhs.instr_addr;
        this->target_addr = rhs.target_addr;*/
        *this = rhs;
    }
} trace_ref_t;

typedef std::vector<trace_ref_t> thr_trc_str;

typedef std::vector<thr_trc_str> glb_trc_str;

#endif