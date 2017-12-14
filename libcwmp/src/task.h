#ifndef __TASK_H__
#define __TASK_H__


typedef enum {
    TASK_TYPE_TIME,
    TASK_TYPE_PRIORITY,
    TASK_TYPE_RANDOM
} task_type_t;

#define QUEUE_PRIORITY_LOW	0
#define QUEUE_PRIORITY_COMMON	1
#define QUEUE_PRIORITY_HIGH	2


#endif //__TASK_H__
