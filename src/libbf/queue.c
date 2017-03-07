#include "queue.h"

#include <string.h>
#include <stdlib.h>

#define QUEUE_BYTES(q) ((q)->entry_size * (q)->capacity)

struct queue {
    size_t entry_size;
    int capacity;
    size_t size;
    char *head;
    char *tail;
    char *mem;
};

static int queue_resize(queue_t *queue, int new_cap)
{
    void *ret;
    if(ret = realloc(queue->mem, queue->entry_size * new_cap))
        queue->mem = ret;
    else
        return -1;
    queue->capacity = new_cap;

    if(queue->head > queue->tail){
        /*                       */
        /* +-----+ <--mem    ^   */
        /* |     |          top  */
        /* |     |           |   */
        /* +-----+ <--tail   |   */
        /* +-----+           v   */
        /* |     |               */
        /* |     |               */
        /* +-----+ <--head   ^   */
        /* +-----+           |   */
        /* |     |          bot  */
        /* +-----+           v   */
        /* | new |               */
        /*                       */

        ptrdiff_t top = queue->tail + queue->entry_size - queue->mem;
        ptrdiff_t bot = queue->mem + QUEUE_BYTES(queue) - queue->head;

        memmove(queue->mem + bot, queue->mem, top);
        memmove(queue->mem, queue->head, bot);
    }

    return 0;
}

queue_t *queue_init(size_t entry_size, int init_capacity)
{
    queue_t *ret = malloc(sizeof(queue_t)); 
    if(ret){
        ret->mem = malloc(entry_size * init_capacity);
        if(!ret->mem){
            free(ret);
            return NULL;
        }
        ret->entry_size = entry_size;
        ret->capacity = init_capacity;
        ret->head = ret->mem;
        ret->tail = ret->mem;
        ret->size = 0;
    }
    return ret;
}

void queue_free(queue_t *queue)
{
    free(queue->mem);
    free(queue);
}

int queue_push(queue_t *queue, void *entry)
{
    if(queue->size == queue->capacity) {
        if(queue_resize(queue, queue->capacity * 2))
            return -1;
    }

    if(queue->size > 0)
        queue->tail += queue->entry_size;
    /* Wrap around back to top */
    if(queue->tail > queue->mem + QUEUE_BYTES(queue)) {
        queue->tail = queue->mem;    
    }

    memcpy(queue->tail, entry, queue->entry_size);
    queue->size++;
    return 0;
}

int queue_pop(queue_t *queue, void *out)
{
    if(queue->size == 0)
        return -1;

    memcpy(out, queue->head, queue->entry_size);
    queue->head += queue->entry_size;
    /*Wrap around back to top */
    if(queue->head > queue->mem + QUEUE_BYTES(queue)) {
        queue->head = queue->mem;
    }
    queue->size--;
    return 0;
}

