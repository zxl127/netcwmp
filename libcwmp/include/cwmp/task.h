#ifndef __TASK_H__
#define __TASK_H__


typedef enum {
    TASK_TYPE_TIME,
    TASK_TYPE_PRIORITY,
    TASK_TYPE_RANDOM
} task_type_t;

typedef enum {
    TASK_PRIORITY_LOW,
    TASK_PRIORITY_COMMON,
    TASK_PRIORITY_HIGH
} task_priority_t;


int timeval_cmp(struct timeval *t1, struct timeval *t2);
int register_task(cwmp_t *cwmp, void *task, void *arg, task_priority_t priority);
int register_time_task(cwmp_t *cwmp, void *task, void *arg, time_t time);

#endif //__TASK_H__
