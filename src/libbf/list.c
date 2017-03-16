#include "list.h" 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define FOREACH_NODE(_node, _list) \
    for(node_t *_node = _list->head; _node; _node = _node->next)

#define FOREACH_NODE_AND_PREV(_node, _prev, _list) \
    for(node_t *_node = _list->head, *_prev = NULL; _node; _prev = _node, _node = _node->next)

typedef struct node {
    struct node *next;
    size_t size;
    unsigned char data[];
}node_t;

struct list {
    node_t *head;    
    unsigned size;
};


static node_t *node_init(void *data, size_t size)
{
    node_t *node = malloc(sizeof(node_t) + size);
    if(node) {
        node->next = NULL;
        node->size = size;
        memcpy(node->data, data, size);
    }
    return node;
}

static void node_free(node_t *node)
{
    free(node);
}

list_t *list_init(void)
{
    list_t *ret = malloc(sizeof(list_t));
    if(ret) {
        ret->head = NULL;
        ret->size = 0;
    }
    return ret;
}

void list_free(list_t *list)
{
    node_t *curr = list->head;
    while(curr) {
        node_t *tmp = curr->next;
        node_free(curr);
        curr = tmp;
    }

    free(list);
}

int list_add(list_t *list, unsigned char *data, size_t size)
{
    node_t *new_node;

    new_node = node_init(data, size);
    if(!new_node)
        return -1;

    if(!list->head) {
        list->head = new_node;
        list->size = 1;
        return 0;
    }

    FOREACH_NODE(curr, list){
        if(curr->next)
            continue;
        
        curr->next = new_node;
        list->size++;
        return 0;
    }
}

int list_remove(list_t *list, unsigned char *data)
{
    if(!list->head)
        return -1;

    FOREACH_NODE_AND_PREV(curr, prev, list) {
        if(memcmp(curr->data, data, curr->size))
            continue;
        
        if(prev)        
            prev->next = curr->next;
        else
            list->head = curr->next;
        node_free(curr);
        list->size--;
        return 0;
    }
}

unsigned list_get_size(list_t *list)
{
    return list->size;
}

bool list_contains(list_t *list, unsigned char *data)
{
    FOREACH_NODE(curr, list) {
        if(!memcmp(curr->data, data, curr->size))
            return true;
    }
    return false;
}

const list_iter_t *list_iter_first(const list_t *list)
{
    if(list->head)
        return list->head;
    else 
        return NULL;
}

const list_iter_t *list_iter_next(const list_iter_t *iter)
{
    return ((node_t*)iter)->next;
}

const unsigned char *list_iter_get_value(const list_iter_t *iter)
{
    return ((node_t*)iter)->data;
}
