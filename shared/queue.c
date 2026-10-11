#include "queue.h"
void RsQueueInit(RS_QUEUE* q, RS_EVENT* storage, RS_U32 capacity) {
    q->Events = storage; q->Head = q->Count = 0;
    q->Capacity = capacity; q->Produced = q->Dropped = 0;
}
int RsQueuePush(RS_QUEUE* q, const RS_EVENT* event) {
    RS_U32 index;
    ++q->Produced;
    if (q->Count == q->Capacity) { ++q->Dropped; return 0; }
    index = (q->Head + q->Count) % q->Capacity;
    q->Events[index] = *event;
    q->Events[index].Sequence = q->Produced;
    ++q->Count;
    return 1;
}
int RsQueuePop(RS_QUEUE* q, RS_EVENT* event) {
    if (!q->Count) return 0;
    *event = q->Events[q->Head];
    q->Head = (q->Head + 1) % q->Capacity;
    --q->Count;
    return 1;
}
