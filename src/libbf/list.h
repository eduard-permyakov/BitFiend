#ifndef LIST_H
#define LIST_H

#include <stdbool.h>
#include <stddef.h>

typedef struct list list_t;

list_t              *list_init(void);
void                list_free(list_t *list);
int                 list_add(list_t *list, unsigned char *data, size_t size);
int                 list_remove(list_t *list, unsigned char *data);
bool                list_contains(list_t *list, unsigned char *data);
unsigned            list_get_size(list_t *list);

typedef struct list_iter list_iter_t;

const list_iter_t   *list_iter_first(const list_t *list);
const list_iter_t   *list_iter_next(const list_iter_t *iter);
const unsigned char *list_iter_get_value(const list_iter_t *iter);

#define FOREACH_ENTRY(_entry, _list_ptr) \
    for(const list_iter_t *_iter = list_iter_first(_list_ptr); \
        _iter && (_entry = list_iter_get_value(_iter)); _iter = list_iter_next(_iter))

#endif 
