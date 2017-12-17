#ifndef __TASK_H__
#define __TASK_H__

#include "types.h"

typedef void (*task_func_t)(void *arg1, void *arg2);

typedef enum {
    TASK_TYPE_PRIORITY,
    TASK_TYPE_TIME,
} task_type_t;

typedef enum {
    TASK_PRIORITY_LOW,
    TASK_PRIORITY_COMMON,
    TASK_PRIORITY_HIGH
} task_priority_t;

typedef struct task_t{
    union {
        task_priority_t priority;
        struct timeval time;
    } u;
    void *arg;
    task_func_t task;
    struct task_t *prev;
    struct task_t *next;
} task_t;

typedef struct {
    int size;
    task_t *first;
    task_t *last;

    pthread_mutex_t     mutex;
} task_queue_t;

int timeval_cmp(struct timeval *t1, struct timeval *t2);
task_queue_t *task_queue_create(pool_t *pool);
int task_is_empty(task_queue_t *q);
void task_push(task_queue_t *q, task_t *task);
void task_push_before(task_queue_t *q, task_t *pos, task_t *task);
void task_pop(task_queue_t *q, task_t *task);
void task_queue_free(pool_t *pool, task_queue_t *q);
task_t *task_register(cwmp_t *cwmp, void *task, void *arg, int seq, task_type_t type);
void task_unregister(cwmp_t *cwmp, task_t *task, task_type_t type);


#endif //__TASK_H__
