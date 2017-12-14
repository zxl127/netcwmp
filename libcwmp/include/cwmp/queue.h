/************************************************************************
 *                                                                      *
 * Netcwmp Project                                                      *
 *                                                                      *
 * A software client for enabling TR-069 in embedded devices (CPE).     *
 *                                                                      *
 * Copyright (C) 2013-2014  netcwmp.netcwmp group                         *
 *                                                                      *
 * Copyright 2013-2014           Mr.x() <netcwmp@gmail.com>          *
 *                                                                      *
 ***********************************************************************/


#ifndef __CWMPQUEUE_H__
#define __CWMPQUEUE_H__
#include <cwmp/types.h>

typedef struct qnode_t qnode_t;
typedef struct queue_t queue_t;

struct qnode_t {
	void *data;
    void *arg;
    union {
        int priority;
        struct timeval time;
    } u;
    struct qnode_t *prev;
    struct qnode_t *next;
} ;

struct queue_t {
	int size;
    struct qnode_t *first;
	struct qnode_t *last;
	
	pthread_mutex_t     mutex;
} ;


queue_t *queue_create(pool_t * pool);
int queue_is_empty(queue_t *q);
void queue_push(struct queue_t *q, struct qnode_t *node);
void queue_push_before(struct queue_t *q, struct qnode_t *pos,struct qnode_t *node);
void queue_pop(struct queue_t *q, struct qnode_t *node);
void queue_free(struct queue_t *q);
void queue_view(queue_t *q);


#endif //__CWMPQUEUE_H__
