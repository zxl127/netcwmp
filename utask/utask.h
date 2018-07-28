#ifndef __UTASK_H__
#define __UTASK_H__

#include "list.h"
#include <pthread.h>
#include <sys/time.h>

#define EVENT_READ              0x01
#define EVENT_WRITE             0x02
#define EVENT_EDGE_TRIGGER      0x04
#define EVENT_NONBLOCK          0x08

typedef struct u_fd ufd_t;
typedef struct u_timer utimer_t;
typedef struct u_task utask_t;
typedef struct u_task_queue utask_queue_t;

struct u_fd
{
    int fd;
    bool eof;
    bool error;
    bool registered;
    unsigned int events;

    void (*handler)(struct u_fd *f);
};

struct u_timer
{
    struct list_head list;

    bool waiting;
    struct timeval time;

    void (*handler)(struct u_timer *timer);
};

struct task_handler {
    void (*run)(utask_queue_t *q, utask_t *t);
    void (*kill)(utask_queue_t *q, utask_t *t);
    void (*complete)(utask_queue_t *q, utask_t *t);
};

struct u_task{
    struct list_head list;

    void *arg;
    pid_t pid;
    int timeout;
    bool running;
    utimer_t timer;
    utask_queue_t *queue;
    struct task_handler handler;
};

struct u_task_queue{
    struct list_head head;

    bool stopped;
    int running_tasks;
    int max_running_tasks;

    pthread_mutex_t     mutex;
};

int ufd_add(ufd_t *fd, unsigned int events);
int ufd_delete(ufd_t *fd);
int utimer_add(utimer_t *timer);
void utimer_cancel(utimer_t *timer);
void utimer_set(utimer_t *timer, int msecs);
int utask_time_remaining(utask_t *t);
void utask_kill(utask_queue_t *q, utask_t *t);
void utask_set_timer(utask_t *task, int time, int timeout);
void utask_set_handler(utask_t *task, void *run, void *kill, void *complete);
void utask_register(utask_queue_t *q, utask_t *task, void *arg);
void utask_unregister(utask_t *task);
void utasks_init(utask_queue_t *q);
void utasks_loop(utask_queue_t *q);
void utasks_done(utask_queue_t *q);

#endif //__UTASK_H__
