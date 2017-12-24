#include "cwmp/log.h"
#include "cwmp/task.h"
#include "cwmp/cwmp.h"
#include <signal.h>

static struct list_head timer_list = LIST_HEAD_INIT(timer_list);
static struct list_head proc_list = LIST_HEAD_INIT(proc_list);

static int tv_diff(struct timeval *t1, struct timeval *t2)
{
    if(!t1 || !t2)
        return 0;
    return (t1->tv_sec == t2->tv_sec? (t1->tv_usec - t2->tv_usec) : (t1->tv_sec - t2->tv_sec));
}

static void get_time(struct timeval *tv)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000;
}

int timer_add(utimer_t *timer)
{
    utimer_t *tmp;
    struct list_head *h = &timer_list;

    if (timer->waiting)
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

void timer_cancel(utimer_t *timer)
{
    if (!timer->waiting)
        return;

    list_del(&timer->list);
    timer->waiting = false;
}


int timer_set(struct utimer_t *timer, int msecs)
{
    struct timeval *time = &timer->time;

    if (timer->waiting)
        timer_cancel(timer);

    get_time(time);

    time->tv_sec += msecs / 1000;
    time->tv_usec += (msecs % 1000) * 1000;

    if (time->tv_usec > 1000000) {
        time->tv_sec++;
        time->tv_usec -= 1000000;
    }

    return timer_add(timer);
}

int timer_remaining(struct utimer_t *timer)
{
    struct timeval now;

    if (!timer->waiting)
        return -1;

    get_time(&now);

    return tv_diff(&timer->time, &now);
}

static void process_timer()
{
    struct utimer_t *t;
    struct timeval tv;

    get_time(&tv);
    while (!list_empty(&timer_list)) {
        t = list_first_entry(&timer_list, struct utimer_t, list);

        if (tv_diff(&t->time, &tv) > 0)
            break;

        timer_cancel(t);
        if (t->handler)
            t->handler(t);
    }
}

static int get_rest_time_from_timer()
{
    struct utimer_t *timer;
    struct timeval tv;
    int diff;

    if (list_empty(&timer_list))
        return -1;

    get_time(&tv);
    timer = list_first_entry(&timer_list, struct utimer_t, list);
    diff = tv_diff(&timer->time, &tv);
    if (diff < 0)
        return 0;

    return diff;
}

static void clear_all_timer(void)
{
    struct utimer_t *t, *tmp;

    list_for_each_entry_safe(t, tmp, &timer_list, list)
        timer_cancel(t);
}

void task_queue_init(task_queue_t *q)
{
    q->head = proc_list;
    q->running_tasks = 0;
    q->stopped = false;
    pthread_mutex_init(& queue->mutex ,NULL);
}

void task_add(task_queue_t *q, task_t *task)
{
    if(!q || !task)
        return;

    struct task_t *tmp;
    struct list_head *h = &proc_list;

    pthread_mutex_lock(&q->mutex);
    list_for_each_entry(tmp, &proc_list, list) {
        if (tmp->pid > p->pid) {
            h = &tmp->list;
            break;
        }
    }
    list_add_tail(&task->list, h);
    pthread_mutex_unlock(&q->mutex);
}

void task_delete(task_queue_t *q, task_t *task)
{
    pthread_mutex_lock(&q->mutex);
    if(task->running)
        return;
    list_del(&task->list);
    task->running = false;
    pthread_mutex_unlock(&q->mutex);
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

static void sigint_handler(int signo)
{

}

static void sigchld_handler(int signo)
{

}

static void init_signals()
{
    add_signal_handler(SIGINT, sigint_handler, NULL);
    add_signal_handler(SIGTERM, sigint_handler, NULL);
    add_signal_handler(SIGCHLD, sigchld_handler, NULL);
    add_signal_handler(SIGPIPE, SIG_IGN, NULL);
}

static void handle_tasks(task_queue_t *q)
{
    struct task_t *p, *tmp;
    pid_t pid;
    int ret;

    while (1) {
        pid = waitpid(-1, &ret, WNOHANG);
        if (pid < 0 && errno == EINTR)
            continue;

        if (pid <= 0)
            return;

        list_for_each_entry_safe(p, tmp, &proc_list, list) {
            if (p->pid < pid)
                continue;

            if (p->pid > pid)
                break;

            task_delete(q, p);
            p->handler.complete(q, p);
        }
    }

}

static void clear_all_tasks(void)
{
    task_t *p, *tmp;

    list_for_each_entry_safe(p, tmp, &proc_list, list)
        task_delete(p);
}

static void uloop_run_events(int timeout)
{
    struct uloop_fd_event *cur;
    struct uloop_fd *fd;

    if (!cur_nfds) {
        cur_fd = 0;
        cur_nfds = uloop_fetch_events(timeout);
        if (cur_nfds < 0)
            cur_nfds = 0;
    }

    while (cur_nfds > 0) {
        struct uloop_fd_stack stack_cur;
        unsigned int events;

        cur = &cur_fds[cur_fd++];
        cur_nfds--;

        fd = cur->fd;
        events = cur->events;
        if (!fd)
            continue;

        if (!fd->cb)
            continue;

        if (uloop_fd_stack_event(fd, cur->events))
            continue;

        stack_cur.next = fd_stack;
        stack_cur.fd = fd;
        fd_stack = &stack_cur;
        do {
            stack_cur.events = 0;
            fd->cb(fd, events);
            events = stack_cur.events & ULOOP_EVENT_MASK;
        } while (stack_cur.fd && events);
        fd_stack = stack_cur.next;

        return;
    }
}

int task_oi                      p amain_loop()
{
    int block_time = 0;
    struct timeval tv;

    uloop_run_depth++;

    uloop_status = 0;
    uloop_cancelled = false;
    while (!uloop_cancelled)
    {
        process_timer();

        if (do_sigchld)
            handle_tasks(q);

        if (uloop_cancelled)
            break;

        block_time = get_rest_time_from_timer();
        if (timeout >= 0 && timeout < next_time)
            next_time = timeout;
        uloop_run_events(block_time);
    }

    --uloop_run_depth;

    return uloop_status;
}

void tasks_done(void)
{
	uloop_setup_signals(false);

	if (poll_fd >= 0) {
		close(poll_fd);
		poll_fd = -1;
	}

	if (waker_pipe >= 0) {
		uloop_fd_delete(&waker_fd);
		close(waker_pipe);
		close(waker_fd.fd);
		waker_pipe = -1;
	}

	uloop_clear_timeouts();
	uloop_clear_processes();
}
