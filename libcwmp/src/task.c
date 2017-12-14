#include <cwmp/cwmp.h>
#include "cwmp/queue.h"
#include "task.h"


static int timeval_cmp(struct timeval *t1, struct timeval *t2)
{
    if(!t1 || !t2)
        return 0;
    return (t1->tv_sec == t2->tv_sec? (t1->tv_usec - t2->tv_usec) : (t1->tv_sec - t2->tv_sec));
}


int callback_register_task(cwmp_t * cwmp, callback_func_t callback, void *data1, void *data2)
{
    queue_add(cwmp->queue, callback, TASK_CALLBACK_TAG, QUEUE_PRIORITY_HIGH, data1, data2);
    return CWMP_OK;
}

int register_task(cwmp_t *cwmp, void *task, void *arg, task_type_t type)
{

}
