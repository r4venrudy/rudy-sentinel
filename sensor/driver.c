#include <ntddk.h>
#include <wdmsec.h>
#include "../shared/queue.h"

#define RS_TAG 'yduR'
#define RS_SENSITIVE_ACCESS 0x007Au /* create thread, VM operation/read/write, duplicate */
static const GUID RsClassGuid = {0x627fb1e7,0xe439,0x4ebc,{0xb8,0xb5,0xcf,0x0a,0x66,0xa2,0x34,0x0a}};
static UNICODE_STRING RsDeviceName = RTL_CONSTANT_STRING(L"\\Device\\RudySentinel");
static UNICODE_STRING RsLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\RudySentinel");
static RS_QUEUE RsQueue;
static KSPIN_LOCK RsLock;
static NPAGED_LOOKASIDE_LIST RsLookaside;
static uint64_t RsAllocationFailures;
static PVOID RsObRegistration;
static BOOLEAN RsProcessRegistered, RsImageRegistered, RsLinkCreated;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RsUnload;
DRIVER_DISPATCH RsDispatch;

static RS_EVENT* RsNewEvent(uint32_t type, HANDLE pid) {
    RS_EVENT* event = ExAllocateFromNPagedLookasideList(&RsLookaside);
    LARGE_INTEGER time;
    if (!event) {
        KIRQL irql;
        KeAcquireSpinLock(&RsLock, &irql);
        ++RsAllocationFailures;
        KeReleaseSpinLock(&RsLock, irql);
        return NULL;
    }
    RtlZeroMemory(event, sizeof(*event));
    event->Size = sizeof(*event); event->Version = RS_VERSION;
    event->Type = type; event->ProcessId = HandleToULong(pid);
    KeQuerySystemTimePrecise(&time); event->Time100ns = (uint64_t)time.QuadPart;
    return event;
}
static void RsCopyText(RS_EVENT* event, uint16_t* dest, uint32_t capacity,
                       PCUNICODE_STRING source, uint32_t flag) {
    SIZE_T chars;
    if (!source || !source->Buffer) return;
    chars = source->Length / sizeof(WCHAR);
    if (chars >= capacity) { chars = capacity - 1; event->Flags |= flag; }
    RtlCopyMemory(dest, source->Buffer, chars * sizeof(WCHAR));
    dest[chars] = 0;
}
static void RsEmit(RS_EVENT* event) {
    KIRQL irql;
    if (!event) return;
    KeAcquireSpinLock(&RsLock, &irql);
    (void)RsQueuePush(&RsQueue, event);
    KeReleaseSpinLock(&RsLock, irql);
    ExFreeToNPagedLookasideList(&RsLookaside, event);
}
static void RsProcessNotify(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info) {
    RS_EVENT* event;
    UNREFERENCED_PARAMETER(process);
    event = RsNewEvent(info ? RS_PROCESS_START : RS_PROCESS_EXIT, pid);
    if (!event) return;
    if (info) {
        event->ParentId = HandleToULong(info->ParentProcessId);
        RsCopyText(event, event->Image, RS_PATH_CHARS, info->ImageFileName, RS_PATH_TRUNCATED);
        RsCopyText(event, event->Command, RS_COMMAND_CHARS, info->CommandLine, RS_COMMAND_TRUNCATED);
    }
    RsEmit(event);
}
static void RsImageNotify(PUNICODE_STRING name, HANDLE pid, PIMAGE_INFO info) {
    RS_EVENT* event;
    /* Kernel image addresses are deliberately never exported. */
    if (info->SystemModeImage) return;
    event = RsNewEvent(RS_IMAGE_LOAD, pid);
    if (!event) return;
    RsCopyText(event, event->Image, RS_PATH_CHARS, name, RS_PATH_TRUNCATED);
    RsEmit(event);
}
static OB_PREOP_CALLBACK_STATUS RsHandleNotify(PVOID context, POB_PRE_OPERATION_INFORMATION info) {
    ACCESS_MASK access;
    HANDLE actor = PsGetCurrentProcessId();
    HANDLE target = PsGetProcessId((PEPROCESS)info->Object);
    RS_EVENT* event;
    UNREFERENCED_PARAMETER(context);
    if (info->KernelHandle || actor == target) return OB_PREOP_SUCCESS;
    access = info->Operation == OB_OPERATION_HANDLE_CREATE
        ? info->Parameters->CreateHandleInformation.OriginalDesiredAccess
        : info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    if (!(access & RS_SENSITIVE_ACCESS)) return OB_PREOP_SUCCESS;
    event = RsNewEvent(RS_HANDLE_REQUEST, actor);
    if (event) {
        event->TargetId = HandleToULong(target); event->AccessMask = access;
        RsEmit(event);
    }
    /* Audit requested rights only. Never change rights or claim a successful access. */
    return OB_PREOP_SUCCESS;
}
static void RsStopCallbacks(void) {
    if (RsObRegistration) { ObUnRegisterCallbacks(RsObRegistration); RsObRegistration = NULL; }
    if (RsImageRegistered) { (void)PsRemoveLoadImageNotifyRoutine(RsImageNotify); RsImageRegistered = FALSE; }
    if (RsProcessRegistered) { (void)PsSetCreateProcessNotifyRoutineEx(RsProcessNotify, TRUE); RsProcessRegistered = FALSE; }
}
void RsUnload(PDRIVER_OBJECT driver) {
    RsStopCallbacks();
    if (RsLinkCreated) IoDeleteSymbolicLink(&RsLinkName);
    IoDeleteDevice(driver->DeviceObject);
    ExDeleteNPagedLookasideList(&RsLookaside);
    ExFreePoolWithTag(RsQueue.Events, RS_TAG);
}
static void RsSnapshot(RS_BATCH* batch) {
    batch->Size = sizeof(*batch); batch->Version = RS_VERSION;
    batch->Produced = RsQueue.Produced; batch->Dropped = RsQueue.Dropped;
    batch->AllocationFailures = RsAllocationFailures;
    batch->Pending = RsQueue.Count; batch->Capacity = RsQueue.Capacity;
}
NTSTATUS RsDispatch(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytes = 0;
    UNREFERENCED_PARAMETER(device);
    if (stack->MajorFunction == IRP_MJ_CREATE) {
        /* Reject subpaths; the device ACL also covers its namespace. */
        status = stack->FileObject->FileName.Length ? STATUS_OBJECT_NAME_INVALID : STATUS_SUCCESS;
    } else if (stack->MajorFunction == IRP_MJ_CLOSE || stack->MajorFunction == IRP_MJ_CLEANUP) {
        status = STATUS_SUCCESS;
    } else if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
        ULONG input = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG output = stack->Parameters.DeviceIoControl.OutputBufferLength;
        RS_REQUEST request;
        RS_BATCH* batch = (RS_BATCH*)irp->AssociatedIrp.SystemBuffer;
        if (code != RS_IOCTL_DRAIN && code != RS_IOCTL_STATS) goto complete;
        if (input != sizeof(request) || output < sizeof(*batch) || !batch) {
            status = STATUS_BUFFER_TOO_SMALL; goto complete;
        }
        RtlCopyMemory(&request, batch, sizeof(request));
        if (request.Size != sizeof(request) || request.Version != RS_VERSION || request.Reserved ||
            !request.MaxEvents || request.MaxEvents > RS_BATCH_MAX) {
            status = STATUS_INVALID_PARAMETER; goto complete;
        }
        RtlZeroMemory(batch, sizeof(*batch));
        if (code == RS_IOCTL_DRAIN) {
            ULONG max = (output - sizeof(*batch)) / sizeof(RS_EVENT);
            RS_EVENT* events = (RS_EVENT*)(batch + 1);
            KIRQL irql;
            if (!max) { status = STATUS_BUFFER_TOO_SMALL; goto complete; }
            if (max > request.MaxEvents) max = request.MaxEvents;
            /* Bound each critical section to one event, not an entire batch. */
            while (batch->Count < max) {
                int popped;
                KeAcquireSpinLock(&RsLock, &irql);
                popped = RsQueuePop(&RsQueue, &events[batch->Count]);
                KeReleaseSpinLock(&RsLock, irql);
                if (!popped) break;
                ++batch->Count;
            }
        }
        {
            KIRQL irql;
            KeAcquireSpinLock(&RsLock, &irql);
            RsSnapshot(batch);
            KeReleaseSpinLock(&RsLock, irql);
        }
        bytes = sizeof(*batch) + batch->Count * sizeof(RS_EVENT);
        status = STATUS_SUCCESS;
    }
complete:
    irp->IoStatus.Status = status; irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path) {
    NTSTATUS status;
    PDEVICE_OBJECT device = NULL;
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    OB_OPERATION_REGISTRATION operation = {0};
    OB_CALLBACK_REGISTRATION callbacks = {0};
    ULONG i;
    UNREFERENCED_PARAMETER(path);
    C_ASSERT(sizeof(RS_EVENT) == 1592);
    C_ASSERT(sizeof(RS_BATCH) == 48);
    KeInitializeSpinLock(&RsLock);
    RsQueue.Events = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RS_EVENT) * RS_CAPACITY, RS_TAG);
    if (!RsQueue.Events) return STATUS_INSUFFICIENT_RESOURCES;
    RsQueueInit(&RsQueue, RsQueue.Events, RS_CAPACITY);
    ExInitializeNPagedLookasideList(&RsLookaside, NULL, NULL, 0, sizeof(RS_EVENT), RS_TAG, 0);
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) driver->MajorFunction[i] = RsDispatch;
    driver->DriverUnload = RsUnload;
    status = IoCreateDeviceSecure(driver, 0, &RsDeviceName, RS_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN, TRUE, &sddl, &RsClassGuid, &device);
    if (!NT_SUCCESS(status)) goto fail;
    status = IoCreateSymbolicLink(&RsLinkName, &RsDeviceName);
    if (!NT_SUCCESS(status)) goto fail;
    RsLinkCreated = TRUE;
    status = PsSetCreateProcessNotifyRoutineEx(RsProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) goto fail;
    RsProcessRegistered = TRUE;
    status = PsSetLoadImageNotifyRoutine(RsImageNotify);
    if (!NT_SUCCESS(status)) goto fail;
    RsImageRegistered = TRUE;
    operation.ObjectType = PsProcessType;
    operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operation.PreOperation = RsHandleNotify;
    callbacks.Version = OB_FLT_REGISTRATION_VERSION;
    callbacks.OperationRegistrationCount = 1;
    callbacks.OperationRegistration = &operation;
    /* Research altitude; production distribution needs an assigned altitude. */
    RtlInitUnicodeString(&callbacks.Altitude, L"385470.8642");
    status = ObRegisterCallbacks(&callbacks, &RsObRegistration);
    if (!NT_SUCCESS(status)) goto fail;
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
fail:
    RsStopCallbacks();
    if (RsLinkCreated) IoDeleteSymbolicLink(&RsLinkName);
    if (device) IoDeleteDevice(device);
    ExDeleteNPagedLookasideList(&RsLookaside);
    ExFreePoolWithTag(RsQueue.Events, RS_TAG);
    return status;
}
