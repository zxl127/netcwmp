#ifndef __TASK_H__
#define __TASK_H__

#include "types.h"
#include "cwmp/list.h"

typedef enum {
    TASK_TYPE_PRIORITY,
    TASK_TYPE_TIME,
} task_type_t;

typedef enum {
    TASK_PRIORITY_LOW,
    TASK_PRIORITY_COMMON,
    TASK_PRIORITY_HIGH
} task_priority_t;

typedef struct u_fd
{
    int fd;
    bool eof;
    bool error;
    bool registered;
    uint8_t flags;

    void (*handler)(struct u_fd *f, unsigned int events);
} ufd_t;

typedef struct u_timer
{
    struct list_head list;

    bool waiting;
    struct timeval time;

    void (*handler)(struct u_timer *timer);
} utimer_t;

struct task_handler {
    void (*run)(task_queue_t *q, task_t *t);
    void (*kill)(task_queue_t *q, task_t *t);
    void (*complete)(task_queue_t *q, task_t *t);
};

typedef struct {
    struct list_head list;

    pid_t pid;
    int timeout;
    bool running;
    utimer_t *timer;
    struct task_handler handler;
} task_t;

typedef struct {
    task_t *head;

    bool stopped;
    int max_tasks;
    int running_tasks;
    int max_running_tasks;

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
