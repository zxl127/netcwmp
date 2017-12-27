#include "cwmp/log.h"
#include "cwmp/task.h"
#include "cwmp/cwmp.h"
#include <signal.h>
#include <sys/epoll.h>

#define MAX_EVENTS      10
#define ARRAY_SIZE(arr)      (sizeof(arr) / sizeof((arr)[0]))

static struct list_head timer_list = LIST_HEAD_INIT(timer_list);

static int task_cancelled = false;
static int task_exit = false;

static struct epoll_event events[MAX_EVENTS];
static ufd_t cur_fds[MAX_EVENTS];
static int cur_fd, cur_nfds;
static int poll_fd = -1;

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

static int timer_add(utimer_t *timer)
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

static void timer_cancel(utimer_t *timer)
{
    if (!timer || !timer->waiting)
        return;

    list_del(&timer->list);
    timer->waiting = false;
}

static void timer_set(utimer_t *timer, int msecs)
{
    struct timeval *time = &timer->time;

    if(!timer)
        return -1;

    get_time(time);

    time->tv_sec += msecs / 1000;
    time->tv_usec += (msecs % 1000) * 1000;

    if (time->tv_usec > 1000000) {
        time->tv_sec++;
        time->tv_usec -= 1000000;
    }
}

int task_timer_remaining(utimer_t *timer)
{
    struct timeval now;

    if (!timer || !timer->waiting)
        return -1;

    get_time(&now);

    return tv_diff(&timer->time, &now);
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
        timer_cancel(t);
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

        timer_cancel(t);
        if (t->handler)
            t->handler(t);
    }
}

static void task_add(task_queue_t *q, task_t *task)
{
    if(!q || !task)
        return;

    task_t *tmp;
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

static void task_delete(task_queue_t *q, task_t *task)
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

void task_kill(task_queue_t *q, task_t *t)
{
    if(!q || !t)
        return;
    if(!t->running)
        return;
    if(t->pid > 0)
    {
        printf("kill task, pid = %d\n", t->pid);
        kill(t->pid, SIGKILL);
        task_delete(q, t);
    }
}


static void clear_all_tasks(task_queue_t *q)
{
    task_t *p, *tmp;

    list_for_each_entry_safe(p, tmp, &q->head, list)
        task_delete(q, p);
}

static void _task_run_timeout(utimer_t *timer)
{
    task_t *task = container_of(timer, task_t, timer);
    if(task->handler.kill)
        task->handler.kill(task->queue, task);
    if(task->running)
        task_delete(task->queue, task);
    if(task->handler.complete)
        task->handler.complete(task->queue, task);
}

static void _task_timer_start(utimer_t *timer)
{
    task_t *task = container_of(timer, task_t, timer);

    if(task->queue->running_tasks < task->queue->max_running_tasks)
    {
        if(task->handler.run)
            task->handler.run(task->queue, task);
        if(task->pid > 0)
        {
            task_add(task->queue, task);
            if(task->timeout > 0)
            {
                timer->handler = _task_run_timeout;
                timer_set(timer, task->timeout);
                timer_add(timer);
            }
        }
    }
    else
        timer_add(&task->timer);
}

void task_set_timer(task_t *task, int time, int timeout)
{
    task->timer.waiting = false;
    task->timer.handler = _task_timer_start;
    task->timeout = timeout;
    timer_set(&task->timer, time);
}

void task_set_handler(task_t *task, void *run, void *kill, void *complete)
{
    task->handler.run = run;
    task->handler.kill = kill;
    task->handler.complete = complete;
}

void task_register(task_queue_t *q, task_t *task)
{
    if(!q || !task)
        return;
    if(task->timer.waiting)
        return;
    task->pid = 0;
    task->queue = q;
    task->running = false;
    timer_add(&task->timer);
}

void task_unregister(task_t *task)
{
    timer_cancel(&task->timer);
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

static void process_task_exit(task_queue_t *q)
{
    task_t *p, *tmp;
    pid_t pid;
    int ret;

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

            task_delete(q, p);
            timer_cancel(&p->timer);
            if(p->handler.complete)
                p->handler.complete(q, p);
        }
    }

}

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


int ufd_add(ufd_t *sock, unsigned int events)
{
    unsigned int fl;
    int ret;

    if(!sock)
        return -1;
    if (!sock->registered) {
        fl = fcntl(sock->fd, F_GETFL, 0);
        fl |= O_NONBLOCK;
        fcntl(sock->fd, F_SETFL, fl);
    }

    ret = register_poll(sock, events);
    if (ret < 0)
        goto out;

    sock->registered = true;
    sock->eof = false;

out:
    return ret;
}

int ufd_delete(ufd_t *fd)
{
    int i;

    if(!fd)
        return -1;
    for (i = 0; i < cur_nfds; i++) {
        if (cur_fds[cur_fd + i].fd != fd)
            continue;

        cur_fds[cur_fd + i].fd = NULL;
    }

    if (!fd->registered)
        return 0;

    fd->registered = false;
    fd->events = 0;
    return epoll_ctl(poll_fd, EPOLL_CTL_DEL, fd->fd, 0);
}

static int fetch_events()
{
    int n, nfds;

    nfds = epoll_wait(poll_fd, events, ARRAY_SIZE(events), get_rest_time_from_timer());
    for (n = 0; n < nfds; ++n) {
        ufd_t *cur = &cur_fds[n];
        ufd_t *u = events[n].data.ptr;
        unsigned int ev = 0;

        if (!u)
            continue;

        if (events[n].events & (EPOLLERR|EPOLLHUP)) {
            u->error = true;
            (u);
        }

        if(!(events[n].events & (EPOLLRDHUP|EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP))) {
            cur->fd = NULL;
            continue;
        }

        if(events[n].events & EPOLLRDHUP)
            u->eof = true;

        if(events[n].events & EPOLLIN)
            ev |= EVENT_READ;

        if(events[n].events & EPOLLOUT)
            ev |= EVENT_WRITE;

        cur->events = ev;
    }

    return nfds;
}

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
        unsigned int events;

        fd = &cur_fds[cur_fd++];
        cur_nfds--;

        events = fd->events;
        if (!fd)
            continue;

        if (!fd->handler)
            continue;

        fd->handler(fd);
        return;
    }
}

static void task_queue_init(task_queue_t *q)
{
    if(!q)
        return;

    q->head.next = &q->head;
    q->head.prev = &q->head;
    q->running_tasks = 0;
    q->max_running_tasks = 3;
    q->stopped = false;
    pthread_mutex_init(&q->mutex ,NULL);
}

void tasks_init(task_queue_t *q)
{
    init_poll();
    init_signals();
    task_queue_init(q);
}

void tasks_loop(task_queue_t *q)
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

void tasks_done(task_queue_t *q)
{
	if (poll_fd >= 0) {
		close(poll_fd);
		poll_fd = -1;
	}

    clear_all_timer();
    clear_all_tasks(q);
}
