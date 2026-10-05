"""Windows Job Object limits for extraction workers.

The worker is placed in a job with a per-process committed-memory limit and
KILL_ON_JOB_CLOSE, so a runaway parser cannot exhaust the machine and a
worker can never outlive the engine.
"""

from __future__ import annotations

import sys

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
    _JobObjectExtendedLimitInformation = 9
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001

    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)

    def limit_process(pid: int, memory_limit_mb: int) -> int | None:
        """Put ``pid`` in a new job. Returns the job handle (keep it open), or None."""
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        )
        info.ProcessMemoryLimit = memory_limit_mb * 1024 * 1024
        ok = _kernel32.SetInformationJobObject(
            job, _JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
        )
        process = _kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        if not ok or not process:
            _kernel32.CloseHandle(job)
            if process:
                _kernel32.CloseHandle(process)
            return None
        assigned = _kernel32.AssignProcessToJobObject(job, process)
        _kernel32.CloseHandle(process)
        if not assigned:
            _kernel32.CloseHandle(job)
            return None
        return int(job)

    def close(job: int) -> None:
        _kernel32.CloseHandle(wintypes.HANDLE(job))

else:

    def limit_process(pid: int, memory_limit_mb: int) -> int | None:
        return None

    def close(job: int) -> None:
        return None
