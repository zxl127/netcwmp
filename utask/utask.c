#include "utask.h"
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/wait.h>

#define USE_EPOLL_PROTO
//#define USE_SELECT_PROTO

#define MAX_EVENTS          10
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))

#define UTASK_DEBUG
#ifdef UTASK_DEBUG
#define UTASK_DEBUG(fmt, args...)    printf("[utask %s]"fmt"\n", __func__, ##args)
#else
#define UTASK_DEBUG(fmt, args...)
#endif

static struct list_head timer_list = LIST_HEAD_INIT(timer_list);

static int task_cancelled = false;
static int task_exit = false;

static ufd_t *cur_fds[MAX_EVENTS];
static int cur_fd, cur_nfds;

#ifdef USE_EPOLL_PROTO
static int poll_fd = -1;
static struct epoll_event events[MAX_EVENTS];
#endif

#ifdef USE_SELECT_PROTO
static int max_fd;
static ufd_t *sel_fds[MAX_EVENTS];
fd_set read_set, write_set, except_set;
#endif

static int tv_diff(struct timeval *t1, struct timeval *t2)
{
    return (t1->tv_sec - t2->tv_sec) * 1000 + (t1->tv_usec - t2->tv_usec) / 1000;
}

static void get_time(struct timeval *tv)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000;
}

int utimer_add(utimer_t *timer)
{
    utimer_t *tmp;
    struct list_head *h = &timer_list;

    if (!timer || timer->waiting)
        return -1;

    list_for_each_entry(tmp, &timer_list, list) {
        if (tv_diff(&tmp->time, &timer->time) > 0) {
            h = &tmp->list;
            break;
        }
    }

    list_add_tail(&timer->list, h);
    timer->waiting = true;

    return 0;
}

void utimer_cancel(utimer_t *timer)
{
    if (!timer || !timer->waiting)
        return;

    list_del(&timer->list);
    timer->waiting = false;
}

void utimer_set(utimer_t *timer, int msecs)
{
    struct timeval *time = &timer->time;

    if(!timer)
        return;

    get_time(time);

    time->tv_sec += msecs / 1000;
    time->tv_usec += (msecs % 1000) * 1000;

    if (time->tv_usec > 1000000) {
        time->tv_sec++;
        time->tv_usec -= 1000000;
    }
}

int utask_time_remaining(utask_t *t)
{
    struct timeval now;

    if (!t || !t->timer.waiting)
        return -1;

    get_time(&now);

    return tv_diff(&t->timer.time, &now);
}

static int get_rest_time_from_timer()
{
    utimer_t *timer;
    struct timeval tv;
    int diff;

    if (list_empty(&timer_list))
        return 1;

    get_time(&tv);
    timer = list_first_entry(&timer_list, utimer_t, list);
    diff = tv_diff(&timer->time, &tv);
    if (diff < 0)
        return 1;

    return diff;
}

static void clear_all_timer(void)
{
    utimer_t *t, *tmp;

    list_for_each_entry_safe(t, tmp, &timer_list, list)
        utimer_cancel(t);
}

static void process_timer()
{
    utimer_t *t;
    struct timeval tv;

    get_time(&tv);
    while (!list_empty(&timer_list)) {
        t = list_first_entry(&timer_list, utimer_t, list);

        if (tv_diff(&t->time, &tv) > 0)
            break;

        utimer_cancel(t);
        if (t->handler)
            t->handler(t);
    }
}

static void utask_add(utask_queue_t *q, utask_t *task)
{
    if(!q || !task)
        return;

    utask_t *tmp;
    struct list_head *h = &q->head;

    pthread_mutex_lock(&q->mutex);
    list_for_each_entry(tmp, &q->head, list) {
        if (tmp->pid > task->pid) {
            h = &tmp->list;
            break;
        }
    }
    list_add_tail(&task->list, h);
    task->running = true;
    q->running_tasks++;
    pthread_mutex_unlock(&q->mutex);
}

static void utask_delete(utask_queue_t *q, utask_t *task)
{
    if(!q || !task)
        return;

    pthread_mutex_lock(&q->mutex);
    list_del(&task->list);
    task->pid = 0;
    task->running = false;
    q->running_tasks--;
    pthread_mutex_unlock(&q->mutex);
}

void utask_kill(utask_queue_t *q, utask_t *t)
{
    if(!q || !t)
        return;
    if(!t->running)
        return;
    if(t->pid > 0)
    {
        printf("kill task, pid = %d\n", t->pid);
        kill(t->pid, SIGKILL);
        utask_delete(q, t);
    }
}


static void clear_all_tasks(utask_queue_t *q)
{
    utask_t *p, *tmp;

    list_for_each_entry_safe(p, tmp, &q->head, list)
        utask_delete(q, p);
}

static void _task_run_timeout(utimer_t *timer)
{
    utask_t *task = container_of(timer, utask_t, timer);
    if(task->handler.kill)
        task->handler.kill(task->queue, task);
    if(task->running)
        utask_delete(task->queue, task);
    if(task->handler.complete)
        task->handler.complete(task->queue, task);
}

static void _task_timer_start(utimer_t *timer)
{
    utask_t *task = container_of(timer, utask_t, timer);

    if(task->queue->running_tasks < task->queue->max_running_tasks)
    {
        if(task->handler.run)
            task->handler.run(task->queue, task);
        if(task->pid > 0)
        {
            utask_add(task->queue, task);
            if(task->timeout > 0)
            {
                timer->handler = _task_run_timeout;
                utimer_set(timer, task->timeout);
                utimer_add(timer);
            }
        }
        else
        {
            if(task->handler.complete)
                task->handler.complete(task->queue, task);
        }
    }
    else
        utimer_add(&task->timer);
}

void utask_set_timer(utask_t *task, int time, int timeout)
{
    task->timer.waiting = false;
    task->timer.handler = _task_timer_start;
    task->timeout = timeout;
    utimer_set(&task->timer, time);
}

void utask_set_handler(utask_t *task, void *run, void *kill, void *complete)
{
    task->handler.run = run;
    task->handler.kill = kill;
    task->handler.complete = complete;
}

void utask_register(utask_queue_t *q, utask_t *task, void *arg)
{
    if(!q || !task)
        return;
    if(task->timer.waiting)
        return;
    task->pid = 0;
    task->queue = q;
    task->arg = arg;
    task->running = false;
    utimer_add(&task->timer);
}

void utask_unregister(utask_t *task)
{
    utimer_cancel(&task->timer);
}

static void add_signal_handler(int signum, void (*handler)(int), struct sigaction *old)
{
    struct sigaction s;

    sigaction(signum, NULL, &s);
    if(old)
        memcpy(old, &s, sizeof(struct sigaction));
    s.sa_handler = handler;
    s.sa_flags = 0;
    sigaction(signum, &s, NULL);
}

static void signo_handler(int signo)
{
    switch (signo) {
    case SIGINT:
        task_cancelled = true;
        break;
    case SIGTERM:
        task_cancelled = true;
        break;
    case SIGCHLD:
        task_exit = true;
        break;
    default:
        break;
    }
}

static void init_signals()
{
    add_signal_handler(SIGINT, signo_handler, NULL);
    add_signal_handler(SIGTERM, signo_handler, NULL);
    add_signal_handler(SIGCHLD, signo_handler, NULL);
    add_signal_handler(SIGPIPE, SIG_IGN, NULL);
}

static void process_task_exit(utask_queue_t *q)
{
    utask_t *p, *tmp;
    pid_t pid;
    int ret;

    task_exit = false;
    while (1) {
        pid = waitpid(-1, &ret, WNOHANG);
        if (pid < 0 && errno == EINTR)
            continue;

        if (pid <= 0)
            return;

        list_for_each_entry_safe(p, tmp, &q->head, list) {
            if (p->pid < pid)
                continue;

            if (p->pid > pid)
                break;

            utask_delete(q, p);
            utimer_cancel(&p->timer);
            if(p->handler.complete)
                p->handler.complete(q, p);
        }
    }

}

#ifdef USE_EPOLL_PROTO
static int init_poll()
{
    poll_fd = epoll_create(MAX_EVENTS);
    if(poll_fd < 0)
        return -1;
    fcntl(poll_fd, fcntl(poll_fd, F_GETFD) | FD_CLOEXEC);
}

static int register_poll(ufd_t *fd, unsigned int events)
{
    struct epoll_event ev;
    int op = fd->registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

    if(poll_fd < 0)
        return -1;

    memset(&ev, 0, sizeof(struct epoll_event));

    if (events & EVENT_READ)
        ev.events |= EPOLLIN | EPOLLRDHUP;

    if (events & EVENT_WRITE)
        ev.events |= EPOLLOUT;

    if (events & EVENT_EDGE_TRIGGER)
        ev.events |= EPOLLET;

    ev.data.fd = fd->fd;
    ev.data.ptr = fd;
    fd->events = events;

    return epoll_ctl(poll_fd, op, fd->fd, &ev);
}


int ufd_add(ufd_t *fd, unsigned int events)
{
    unsigned int fl;
    int ret;

    if(!fd)
        return -1;
    if (!fd->registered) {
        fl = fcntl(fd->fd, F_GETFL, 0);
        fl |= O_NONBLOCK;
        fcntl(fd->fd, F_SETFL, fl);
    }

    ret = register_poll(fd, events);
    if (ret < 0)
        return -1;

    fd->registered = true;
    fd->eof = false;
    fd->error = false;

    return 0;
}

int ufd_delete(ufd_t *fd)
{
    int i;

    if(!fd)
        return -1;
    if(!fd->registered)
        return -1;
    if(poll_fd < 0)
        return -1;

    for (i = 0; i < cur_nfds; i++) {
        if (cur_fds[i] == fd)
            cur_fds[i] = NULL;
    }

    fd->registered = false;
    fd->events = 0;
    fd->eof = false;
    fd->error = false;

    return epoll_ctl(poll_fd, EPOLL_CTL_DEL, fd->fd, 0);
}

static int fetch_events()
{
    int n, nfds;
    ufd_t *cur;

    if(poll_fd < 0)
        return -1;

    nfds = epoll_wait(poll_fd, events, ARRAY_SIZE(events), get_rest_time_from_timer());
    for (n = 0; n < nfds; ++n) {
        cur = events[n].data.ptr;
        cur_fds[n] = cur;

        if (!cur)
            continue;

        cur->events = 0;
        if(!(events[n].events & (EPOLLRDHUP|EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)))
            continue;

        if(events[n].events & (EPOLLERR|EPOLLHUP))
            cur->error = true;

        if(events[n].events & EPOLLRDHUP)
            cur->eof = true;

        if(events[n].events & EPOLLIN)
            cur->events |= EVENT_READ;

        if(events[n].events & EPOLLOUT)
            cur->events |= EVENT_WRITE;
    }

    return nfds;
}
#endif

#ifdef USE_SELECT_PROTO
static int init_poll()
{
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&except_set);

    return 0;
}

static int register_poll(ufd_t *fd, unsigned int events)
{
    int i = 0;

    for(i = 0; i < MAX_EVENTS; i++)
    {
        if(sel_fds[i] == NULL)
        {
            sel_fds[i] = fd;
            break;
        }
    }
    if(i == MAX_EVENTS)
        return -1;
    if(fd->fd > max_fd)
        max_fd = fd->fd;

    if (events & EVENT_READ)
        FD_SET(fd->fd, &read_set);
    if (events & EVENT_WRITE)
        FD_SET(fd->fd, &write_set);
    FD_SET(fd->fd, &except_set);

    fd->events = events;

    return 0;
}

int ufd_add(ufd_t *fd, unsigned int events)
{
    unsigned int fl;
    int ret;

    if(!fd || fd->registered)
        return -1;

    fl = fcntl(fd->fd, F_GETFL, 0);
    fl |= O_NONBLOCK;
    fcntl(fd->fd, F_SETFL, fl);

    ret = register_poll(fd, events);
    if (ret < 0)
        return -1;

    fd->registered = true;
    fd->eof = false;
    fd->error = false;

    return 0;
}

int ufd_delete(ufd_t *fd)
{
    bool bfind = false;
    int i, max = 0;

    if(!fd || !fd->registered)
        return -1;

    for (i = 0; i < MAX_EVENTS; i++) {
        if(sel_fds[i] == NULL)
            break;
        if (sel_fds[i] == fd)
            bfind = true;
        if(bfind) {
            if(i == MAX_EVENTS - 1)
                sel_fds[i] = NULL;
            else
                sel_fds[i] = sel_fds[i + 1];
        }
        if(max < sel_fds[i]->fd)
            max = sel_fds[i]->fd;
    }
    max_fd = max;

    fd->registered = false;
    fd->events = 0;
    fd->eof = false;
    fd->error = false;
    FD_CLR(fd->fd, &read_set);
    FD_CLR(fd->fd, &write_set);
    FD_CLR(fd->fd, &except_set);

    return 0;
}

static int fetch_events()
{
    int n, m;
    int nfds, msec;
    fd_set read, write, except;
    struct timeval tv;
    ufd_t *u;

    read = read_set;
    write = write_set;
    except = except_set;

    msec = get_rest_time_from_timer();
    tv.tv_sec = msec / 1000;
    tv.tv_usec = msec % 1000 * 1000;

    nfds = select(max_fd + 1, &read, &write, &except, &tv);
    for (n = 0, m = 0; n < MAX_EVENTS; ++n) {
        u = sel_fds[n];

        if (!u)
            break;;

        u->events = 0;
        if(FD_ISSET(u->fd, &read))
            u->events |= EVENT_READ;
        if(FD_ISSET(u->fd, &write))
            u->events |= EVENT_READ;
        if(FD_ISSET(u->fd, &except))
            u->error = true;
        if(u->events || u->error) {
            cur_fds[m] = u;
            m++;
        }
    }
    if(m < nfds)
        nfds = m;

    return nfds;
}

#endif

static void process_events()
{
    ufd_t *fd;

    if (!cur_nfds) {
        cur_fd = 0;
        cur_nfds = fetch_events();
        if (cur_nfds < 0)
            cur_nfds = 0;
    }

    while (cur_nfds > 0) {
        fd = cur_fds[cur_fd++];
        cur_nfds--;

        if (!fd)
            continue;

        if (!fd->handler)
            continue;

        fd->handler(fd);
        return;
    }
}

static void task_queue_init(utask_queue_t *q)
{
    if(!q)
        return;

    INIT_LIST_HEAD(&q->head);
    q->running_tasks = 0;
    q->max_running_tasks = 3;
    q->stopped = false;
    pthread_mutex_init(&q->mutex ,NULL);
}

void utasks_init(utask_queue_t *q)
{
    init_poll();
    init_signals();
    task_queue_init(q);
}

void utasks_loop(utask_queue_t *q)
{
    if(!q)
        return;
    task_cancelled = false;
    while (!task_cancelled)
    {
        process_timer();

        if (task_exit)
            process_task_exit(q);

        if (task_cancelled)
            break;

        process_events();
    }
}

void utasks_done(utask_queue_t *q)
{
#ifdef USE_EPOLL_PROTO
	if (poll_fd >= 0) {
		close(poll_fd);
		poll_fd = -1;
	}
#endif

    clear_all_timer();
    clear_all_tasks(q);
}
