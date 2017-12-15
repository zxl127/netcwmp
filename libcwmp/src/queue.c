#include "cwmp/log.h"
#include "cwmp/queue.h"
#include <cwmp/cwmp.h>

queue_t *queue_create(pool_t * pool)
{
    if(!pool)
        return;

    queue_t *queue = (queue_t *)pool_pcalloc(pool, sizeof(queue_t));
    if(queue == NULL) return NULL;
    queue->first = NULL;
    queue->last = NULL;
    queue->size = 0;

    pthread_mutex_init(& queue->mutex ,NULL);

    return queue;
}

int queue_is_empty(queue_t *q)
{
    if(q)
        return (q->first == NULL);
    else
        return 1;
}

void queue_push(queue_t *q, qnode_t *node)
{
    if(!q || !node)
        return;
    pthread_mutex_lock(& q->mutex);
    node->next = NULL;
    node->prev = q->last;

    if (q->tail)
        q->tail->next = node;
    else
        q->first = node;
    q->last = node;
    q->size++;
    pthread_mutex_unlock(& q->mutex);
}

void queue_push_before(queue_t *q, qnode_t *pos, qnode_t *node)
{
    if(!q || !pos || !node)
        return;
    pthread_mutex_lock(& q->mutex);
    node->next = pos;
    node->prev = pos->prev;

    if (pos->prev)
        pos->prev->next = node;
    else
        q->first = node;
    pos->prev = node;
    q->size++;
    pthread_mutex_unlock(& q->mutex);
}

void queue_pop(queue_t *q, qnode_t *node)
{
    if(!q || !node)
        return;
    pthread_mutex_lock(& q->mutex);
    if (node->next)
        node->next->prev = node->prev;
    else
        q->last = node->prev;
    if (node->prev)
        node->prev->next = node->next;
    else
        q->first = node->next;
    node->next = node->prev = NULL;
    q->size--;
    pthread_mutex_unlock(& q->mutex);
}

void queue_free(pool_t *pool, queue_t *q)
{
    struct qnode_t *node;

    if(!q)
        return;
    pthread_mutex_lock(& q->mutex);
    for (node = q->first; node ; node = q->first) {
        queue_pop(q, node);
        pool_pfree(pool, node);
    }
    pthread_mutex_unlock(& q->mutex);
    pool_pfree(pool, q);
}

void queue_view(queue_t *q) {
	qnode_t *p;

    if(!q)
        return;
	p=q->first;
	if(p==NULL) {
		cwmp_log_debug("queue is empty.");
		return; 
	} else {
		cwmp_log_debug("queue size = %d. ", q->size);
		while(p->next!=NULL) {
			cwmp_log_debug(" %s ",p->data);
			p=p->next;
		}
		cwmp_log_debug(" %s ",p->data);
	}
}
