#ifndef RUDY_SENTINEL_QUEUE_H
#define RUDY_SENTINEL_QUEUE_H
#include "protocol.h"
/* Caller owns storage and synchronization. Also compiled by portable C tests. */
typedef struct RS_QUEUE {
    RS_EVENT* Events;
    uint32_t Head, Count, Capacity;
    uint64_t Produced, Dropped;
} RS_QUEUE;
void RsQueueInit(RS_QUEUE* queue, RS_EVENT* storage, uint32_t capacity);
int RsQueuePush(RS_QUEUE* queue, const RS_EVENT* event);
int RsQueuePop(RS_QUEUE* queue, RS_EVENT* event);
#endif
