#include "../shared/queue.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"queue check failed at line %d\n",__LINE__); return 1; } } while(0)
int main(void) {
    RS_EVENT storage[7], event={0}, output;
    RS_QUEUE q; unsigned i; RS_U64 expected[7], head=0, count=0, produced=0, dropped=0;
    CHECK(sizeof(RS_EVENT)==1592 && sizeof(RS_BATCH)==48 && sizeof(RS_REQUEST)==16);
    RsQueueInit(&q,storage,7); CHECK(!RsQueuePop(&q,&output));
    srand(41);
    for(i=0;i<100000;++i) {
        if(rand()%3) {
            event.ProcessId=i; ++produced;
            if(count==7) { ++dropped; CHECK(!RsQueuePush(&q,&event)); }
            else { CHECK(RsQueuePush(&q,&event)); expected[(head+count)%7]=produced; ++count; }
        } else {
            if(!count) CHECK(!RsQueuePop(&q,&output));
            else { CHECK(RsQueuePop(&q,&output)); CHECK(output.Sequence==expected[head]); head=(head+1)%7; --count; }
        }
        CHECK(q.Count==count && q.Produced==produced && q.Dropped==dropped);
    }
    puts("C queue: 100,000 model-checked operations and ABI checks passed"); return 0;
}
