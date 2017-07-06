#ifndef REGINA_PER_THREAD_T_H_INCLUDED
#define REGINA_PER_THREAD_T_H_INCLUDED

#include <stdio.h>

#include "trace_ref_t.h"
#include "fileio.h"

typedef struct _per_thread_t {
    int thread_idx;
    trace_ref_t *basePtr;
    trace_ref_t *currPtr;
    FILE *fileIO;
} per_thread_t;

#endif