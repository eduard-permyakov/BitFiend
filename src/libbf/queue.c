#include "queue.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define QUEUE_BYTES(q) ((q)->entry_size * (q)->capacity)

struct queue {
    size_t entry_size;
    int capacity;
    size_t size;
    char *head;
    char *tail;
    char *mem;
};

static int queue_resize(queue_t *queue, unsigned new_cap)
{
    void *ret;
    ptrdiff_t offhead, offtail;
    offhead = queue->head - queue->mem;
    offtail = queue->tail - queue->mem;

    if(ret = realloc(queue->mem, queue->entry_size * new_cap)){
        queue->mem = ret;
        queue->head = queue->mem + offhead;
        queue->tail = queue->mem + offtail;
    }else{
        return -1;
    }
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

        assert(queue->tail >= queue->mem);
        assert(queue->head >= queue->mem);
        ptrdiff_t top = queue->tail + queue->entry_size - queue->mem;
        ptrdiff_t bot = queue->mem + QUEUE_BYTES(queue) - queue->head;

        char tmp[top];
        memcpy(tmp, queue->mem, top);
        memmove(queue->mem, queue->head, bot);
        memcpy(queue->mem + bot, tmp, top);

        queue->head = queue->mem;
        queue->tail = queue->mem + bot;
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
        ret->tail = ret->mem - entry_size;
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

    queue->tail += queue->entry_size;
    /* Wrap around back to top */
    if(queue->tail >= queue->mem + QUEUE_BYTES(queue)) {
        queue->tail = queue->mem;    
    }

    assert(queue->tail >= queue->mem && queue->tail < queue->mem + QUEUE_BYTES(queue));
    memcpy(queue->tail, entry, queue->entry_size);
    queue->size++;
    return 0;
}

int queue_pop(queue_t *queue, void *out)
{
    if(queue->size == 0)
        return -1;

    assert(queue->head>= queue->mem && queue->head < queue->mem + QUEUE_BYTES(queue));
    memcpy(out, queue->head, queue->entry_size);
    queue->head += queue->entry_size;
    /*Wrap around back to top */
    if(queue->head >= queue->mem + QUEUE_BYTES(queue)) {
        queue->head = queue->mem;
    }
    queue->size--;
    return 0;
}

size_t queue_get_size(queue_t *queue)
{
    return queue->size;
}

