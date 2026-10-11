#ifndef RUDY_SENTINEL_QUEUE_H
#define RUDY_SENTINEL_QUEUE_H
#include "protocol.h"
/* Caller owns storage and synchronization. Also compiled by portable C tests. */
typedef struct RS_QUEUE {
    RS_EVENT* Events;
    RS_U32 Head, Count, Capacity;
    RS_U64 Produced, Dropped;
} RS_QUEUE;
void RsQueueInit(RS_QUEUE* queue, RS_EVENT* storage, RS_U32 capacity);
int RsQueuePush(RS_QUEUE* queue, const RS_EVENT* event);
int RsQueuePop(RS_QUEUE* queue, RS_EVENT* event);
#endif
