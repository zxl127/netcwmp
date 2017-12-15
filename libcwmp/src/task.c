#include <cwmp/cwmp.h>
#include "cwmp/log.h"


int timeval_cmp(struct timeval *t1, struct timeval *t2)
{
    if(!t1 || !t2)
        return 0;
    return (t1->tv_sec == t2->tv_sec? (t1->tv_usec - t2->tv_usec) : (t1->tv_sec - t2->tv_sec));
}

int register_task(cwmp_t *cwmp, void *task, void *arg, task_priority_t priority)
{
    qnode_t *node, *pos = NULL;
    queue_t *q = cwmp->queue;

    if(!q)
        return -1;

    for(pos = q->first; pos; pos = pos->next) {
        if(priority > pos->u.priority)
            break;
    }

    node = (qnode_t *)pool_pcalloc(cwmp->pool, sizeof(qnode_t));
    if(!node)
    {
        cwmp_log_debug("Malloc fail");
        return -1;
    }
    node->arg = arg;
    node->data = task;
    node->u.priority = priority;
    if(pos)
        queue_push_before(q, pos, node);
    else
        queue_push(q, node);

    return 0;
}

int register_time_task(cwmp_t *cwmp, void *task, void *arg, time_t time)
{
    struct timeval now;
    qnode_t *node, *pos = NULL;
    queue_t *q = cwmp->queue;

    if(!q)
        return -1;

    gettimeofday(&now, NULL);
    now.tv_sec += time;
    for(pos = q->first; pos; pos = pos->next) {
        if(timeval_cmp(&now, &pos->u.time) < 0)
            break;
    }

    node = (qnode_t *)pool_pcalloc(cwmp->pool, sizeof(qnode_t));
    if(!node)
    {
        cwmp_log_debug("Malloc fail");
        return -1;
    }
    node->arg = arg;
    node->data = task;
    node->u.time = now;
    if(pos)
        queue_push_before(q, pos, node);
    else
        queue_push(q, node);

    return 0;
}
