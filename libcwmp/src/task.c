#include "cwmp/log.h"
#include "cwmp/task.h"
#include "cwmp/cwmp.h"


int timeval_cmp(struct timeval *t1, struct timeval *t2)
{
    if(!t1 || !t2)
        return 0;
    return (t1->tv_sec == t2->tv_sec? (t1->tv_usec - t2->tv_usec) : (t1->tv_sec - t2->tv_sec));
}

task_queue_t *task_queue_create(pool_t *pool)
{
    if(!pool)
        return;

    task_queue_t *queue = (task_queue_t *)pool_pcalloc(pool, sizeof(task_queue_t));
    if(queue == NULL) return NULL;
    queue->first = NULL;
    queue->last = NULL;
    queue->size = 0;

    pthread_mutex_init(& queue->mutex ,NULL);

    return queue;
}

int task_is_empty(task_queue_t *q)
{
    if(q)
        return (q->first == NULL);
    else
        return 1;
}

void task_push(task_queue_t *q, task_t *task)
{
    if(!q || !task)
        return;
    pthread_mutex_lock(& q->mutex);
    task->next = NULL;
    task->prev = q->last;

    if (q->last)
        q->last->next = task;
    else
        q->first = task;
    q->last = task;
    q->size++;
    pthread_mutex_unlock(& q->mutex);
}

void task_push_before(task_queue_t *q, task_t *pos, task_t *task)
{
    if(!q || !pos || !task)
        return;
    pthread_mutex_lock(& q->mutex);
    task->next = pos;
    task->prev = pos->prev;

    if (pos->prev)
        pos->prev->next = task;
    else
        q->first = task;
    pos->prev = task;
    q->size++;
    pthread_mutex_unlock(& q->mutex);
}

void task_pop(task_queue_t *q, task_t *task)
{
    if(!q || !task)
        return;
    pthread_mutex_lock(& q->mutex);
    if (task->next)
        task->next->prev = task->prev;
    else
        q->last = task->prev;
    if (task->prev)
        task->prev->next = task->next;
    else
        q->first = task->next;
    task->next = task->prev = NULL;
    q->size--;
    pthread_mutex_unlock(& q->mutex);
}

void task_queue_free(pool_t *pool, task_queue_t *q)
{
    struct task_t *task;

    if(!pool || !q)
        return;
    pthread_mutex_lock(& q->mutex);
    for (task = q->first; task ; task = q->first) {
        task_pop(q, task);
        pool_pfree(pool, task);
    }
    pthread_mutex_unlock(& q->mutex);
    pool_pfree(pool, q);
}

task_t *task_register(cwmp_t *cwmp, void *task, void *arg, int seq, task_type_t type)
{
    task_t *ptask, *pos = NULL;
    task_queue_t *q = NULL;
    struct timeval now;

    ptask = (task_t *)pool_pcalloc(cwmp->pool, sizeof(task_t));
    if(!ptask)
    {
        cwmp_log_debug("Malloc fail");
        return NULL;
    }
    ptask->arg = arg;
    ptask->task = task;

    switch (type) {
    case TASK_TYPE_PRIORITY:
        ptask->u.priority = (task_priority_t)seq;
        q = cwmp->task_priority;
        if(!q)
            return NULL;
        for(pos = q->first; pos; pos = pos->next) {
            if((task_priority_t)seq > pos->u.priority)
                break;
        }
        break;
    case TASK_TYPE_TIME:
        ptask->u.time = now;
        q = cwmp->task_time;
        if(!q)
            return NULL;
        gettimeofday(&now, NULL);
        now.tv_sec += (time_t)seq;
        for(pos = q->first; pos; pos = pos->next) {
            if(timeval_cmp(&now, &pos->u.time) < 0)
                break;
        }
        break;
    default:
        cwmp_log_debug("unkown task type");
        break;
    }

    if(!q)
        return NULL;
    if(pos)
        task_push_before(q, pos, ptask);
    else
        task_push(q, ptask);

    return ptask;
}

void task_unregister(cwmp_t *cwmp, task_t *task, task_type_t type)
{
    task_t *ptask = NULL;
    task_queue_t *q = NULL;

    switch (type) {
    case TASK_TYPE_PRIORITY:
        q = cwmp->task_priority;
        break;
    case TASK_TYPE_TIME:
        q = cwmp->task_time;
        break;
    default:
        cwmp_log_debug("unkown task type");
        break;
    }

    if(!q || !task)
        return;

    for(ptask = q->first; ptask; ptask = ptask->next)
    {
        if(ptask == task)
        {
            task_pop(q, task);
            pool_pfree(cwmp->pool, task);
        }
    }
}

