#ifndef QUEUE_H
#define QUEUE_H

#include <stddef.h>

typedef struct queue queue_t;

queue_t *queue_init(size_t entry_size, int init_capacity);
void     queue_free(queue_t *queue);
int      queue_push(queue_t *queue, void *entry);
int      queue_pop(queue_t *queue, void *out);
size_t   queue_get_size(queue_t *queue);

#endif
