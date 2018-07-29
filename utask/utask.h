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

    void **args;
    void (*handler)(struct u_fd *f);
};

struct u_timer
{
    struct list_head list;

    bool waiting;
    struct timeval time;

    void **args;
    void (*handler)(struct u_timer *timer);
};

struct u_task{
    struct list_head list;

    pid_t pid;
    int timeout;
    bool running;
    utimer_t timer;

    void **args;
    void (*run)(utask_queue_t *q, utask_t *t);
    void (*kill)(utask_queue_t *q, utask_t *t);
    void (*complete)(utask_queue_t *q, utask_t *t);
};

struct u_task_queue{
    struct list_head head;

    int running_tasks;
    int max_running_tasks;

    pthread_mutex_t     mutex;
};

void **mk_args(int n, ...);
int ufd_add(ufd_t *fd, unsigned int events);
int ufd_delete(ufd_t *fd);
int utimer_add(utimer_t *timer);
void utimer_cancel(utimer_t *timer);
void utimer_set(utimer_t *timer, int msecs);
int utask_time_remaining(utask_t *t);
void utask_kill(utask_t *t);
void utask_set_timer(utask_t *task, int time, int timeout);
void utask_set_handler(utask_t *task, void *run, void *kill, void *complete);
void utask_register(utask_t *task, void **args);
void utask_unregister(utask_t *task);
void utasks_init();
void utasks_loop();
void utasks_done();

#endif //__UTASK_H__
