#ifndef RUDY_SENTINEL_PROTOCOL_H
#define RUDY_SENTINEL_PROTOCOL_H
/* Windows x64 and the tested portable targets use these exact widths.
   Keep user-mode CRT headers out of the kernel translation units. */
typedef unsigned short RS_U16;
typedef unsigned int RS_U32;
typedef unsigned long long RS_U64;

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
    RS_U32 Size, Version, Type, Flags;
    RS_U64 Sequence, Time100ns;
    RS_U32 ProcessId, ParentId, TargetId, AccessMask;
    RS_U16 Image[RS_PATH_CHARS];
    RS_U16 Command[RS_COMMAND_CHARS];
} RS_EVENT;

typedef struct RS_REQUEST { RS_U32 Size, Version, MaxEvents, Reserved; } RS_REQUEST;
typedef struct RS_BATCH {
    RS_U32 Size, Version, Count, Reserved;
    RS_U64 Produced, Dropped, AllocationFailures;
    RS_U32 Pending, Capacity;
} RS_BATCH;
#pragma pack(pop)
#endif
