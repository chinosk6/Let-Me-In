#pragma once

#include <Windows.h>
#include "build/_deps/libkdu-build/Source/Shared/ntos/ntos.h"

BOOLEAN ntsupQueryHVCIState(
        _Out_ PBOOLEAN pbHVCIEnabled,
        _Out_ PBOOLEAN pbHVCIStrictMode,
        _Out_ PBOOLEAN pbHVCIIUMEnabled
)
{
    BOOLEAN hvciEnabled;
    ULONG returnLength;
    NTSTATUS ntStatus;
    SYSTEM_CODEINTEGRITY_INFORMATION ci;

    if (pbHVCIEnabled) *pbHVCIEnabled = FALSE;
    if (pbHVCIStrictMode) *pbHVCIStrictMode = FALSE;
    if (pbHVCIIUMEnabled) *pbHVCIIUMEnabled = FALSE;

    ci.Length = sizeof(ci);

    ntStatus = NtQuerySystemInformation(
            SystemCodeIntegrityInformation,
            &ci,
            sizeof(ci),
            &returnLength);

    if (NT_SUCCESS(ntStatus)) {

        hvciEnabled = ((ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) &&
                       (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED));

        if (pbHVCIEnabled)
            *pbHVCIEnabled = hvciEnabled;

        if (pbHVCIStrictMode)
            *pbHVCIStrictMode = (hvciEnabled == TRUE) &&
                                (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED);

        if (pbHVCIIUMEnabled)
            *pbHVCIIUMEnabled = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) > 0;

        return TRUE;
    }
    else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }

    return FALSE;
}