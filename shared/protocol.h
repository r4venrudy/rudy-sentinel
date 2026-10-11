#ifndef RUDY_SENTINEL_PROTOCOL_H
#define RUDY_SENTINEL_PROTOCOL_H
#include <stdint.h>

#define RS_VERSION 1u
#define RS_CAPACITY 1024u
#define RS_BATCH_MAX 64u
#define RS_PATH_CHARS 260u
#define RS_COMMAND_CHARS 512u
#define RS_DEVICE_TYPE 0x8000u
/* METHOD_BUFFERED, FILE_READ_ACCESS. No write/control/memory primitives. */
#define RS_IOCTL_DRAIN ((RS_DEVICE_TYPE << 16) | (1u << 14) | (0x801u << 2))
#define RS_IOCTL_STATS ((RS_DEVICE_TYPE << 16) | (1u << 14) | (0x802u << 2))
#define RS_PROCESS_START 1u
#define RS_PROCESS_EXIT 2u
#define RS_IMAGE_LOAD 3u
#define RS_HANDLE_REQUEST 4u
#define RS_PATH_TRUNCATED 1u
#define RS_COMMAND_TRUNCATED 2u

#pragma pack(push, 8)
typedef struct RS_EVENT {
    uint32_t Size, Version, Type, Flags;
    uint64_t Sequence, Time100ns;
    uint32_t ProcessId, ParentId, TargetId, AccessMask;
    uint16_t Image[RS_PATH_CHARS];
    uint16_t Command[RS_COMMAND_CHARS];
} RS_EVENT;

typedef struct RS_REQUEST { uint32_t Size, Version, MaxEvents, Reserved; } RS_REQUEST;
typedef struct RS_BATCH {
    uint32_t Size, Version, Count, Reserved;
    uint64_t Produced, Dropped, AllocationFailures;
    uint32_t Pending, Capacity;
} RS_BATCH;
#pragma pack(pop)
#endif
