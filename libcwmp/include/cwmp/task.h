#ifndef __TASK_H__
#define __TASK_H__

#include "types.h"
#include "cwmp/list.h"


#define EVENT_READ              0x01
#define EVENT_WRITE             0x02
#define EVENT_EDGE_TRIGGER      0x04

typedef struct u_timer utimer_t;
typedef struct u_task task_t;
typedef struct u_task_queue task_queue_t;

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
    unsigned int events;

    void (*handler)(struct u_fd *f);
} ufd_t;

struct u_timer
{
    struct list_head list;

    bool waiting;
    struct timeval time;

    void (*handler)(struct u_timer *timer);
};

struct task_handler {
    void (*run)(task_queue_t *q, task_t *t);
    void (*kill)(task_queue_t *q, task_t *t);
    void (*complete)(task_queue_t *q, task_t *t);
};

struct u_task{
    struct list_head list;

    pid_t pid;
    int timeout;
    bool running;
    utimer_t *timer;
    struct task_handler handler;
};

struct u_task_queue{
    struct list_head head;

    bool stopped;
    int max_tasks;
    int running_tasks;
    int max_running_tasks;

    pthread_mutex_t     mutex;
};

int timer_add(utimer_t *timer);
void timer_cancel(utimer_t *timer);
int timer_set(utimer_t *timer, int msecs);
int timer_remaining(utimer_t *timer);
void task_add(task_queue_t *q, task_t *task);
void task_delete(task_queue_t *q, task_t *task);
int ufd_add(ufd_t *sock, unsigned int events);
int ufd_delete(ufd_t *fd);
void task_queue_init(task_queue_t *q);
int task_queue_loop(task_queue_t *q);
void tasks_done(task_queue_t *q);

#endif //__TASK_H__
