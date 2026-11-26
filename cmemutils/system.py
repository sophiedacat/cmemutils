"""Process, memory, and offset utilities with a lazy Windows backend."""

from __future__ import annotations

import csv
import ctypes
import json
import os
import struct
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union


# win32 constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
DEFAULT_PROCESS_ACCESS = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
OFFSET_FILE_FORMATS = (".json", ".csv")
POINTER_SIZE = ctypes.sizeof(ctypes.c_void_p)
MAX_ADDRESS = (1 << (POINTER_SIZE * 8)) - 1
MAX_DWORD = 0xFFFFFFFF
__all__ = [
    "mem_utils",
    "function_resolver",
    "resolver",
    "memory_transfer_error",
    "memory_basic_information",
    "bitmap_file_header",
    "bitmap_info_header",
    "load_offsets",
    "save_offsets",
    "resolve_offset",
    "get_foreground_title",
    "virtual_alloc",
    "virtual_free",
    "get_foreground_window",
    "get_window_text_w",
    "read_process_memory",
    "write_process_memory",
    "nt_read_virtual_memory",
    "nt_write_virtual_memory",
    "MEM_COMMIT",
    "MEM_RESERVE",
    "MEM_RELEASE",
    "PAGE_READWRITE",
    "PAGE_EXECUTE_READWRITE",
    "PROCESS_VM_OPERATION",
    "PROCESS_VM_READ",
    "PROCESS_VM_WRITE",
    "PROCESS_QUERY_INFORMATION",
    "DEFAULT_PROCESS_ACCESS",
    "OFFSET_FILE_FORMATS",
    "POINTER_SIZE",
]


# type aliases
byte = ctypes.c_uint8
word = ctypes.c_uint16
dword = ctypes.c_uint32
qword = ctypes.c_uint64
long_t = ctypes.c_int32
ulong_t = ctypes.c_uint32
lpvoid = ctypes.c_void_p
handle = ctypes.c_void_p
hwnd = ctypes.c_void_p
hdc = ctypes.c_void_p
hbitmap = ctypes.c_void_p
bool_t = ctypes.c_int32
size_t = ctypes.c_size_t
uint_ptr = ctypes.c_uint64 if POINTER_SIZE == 8 else ctypes.c_uint32
int_ptr = ctypes.c_int64 if POINTER_SIZE == 8 else ctypes.c_int32


# structures
class memory_basic_information(ctypes.Structure):
    """structure returned by ``VirtualQuery``"""

    _fields_ = [
        ("base_address", lpvoid),
        ("allocation_base", lpvoid),
        ("allocation_protect", dword),
        ("region_size", size_t),
        ("state", dword),
        ("protect", dword),
        ("type", dword),
    ]


class bitmap_file_header(ctypes.Structure):
    """packed Windows bitmap file header"""

    _pack_ = 2
    _fields_ = [
        ("bf_type", word),
        ("bf_size", dword),
        ("bf_reserved1", word),
        ("bf_reserved2", word),
        ("bf_off_bits", dword),
    ]


class bitmap_info_header(ctypes.Structure):
    """Windows bitmap information header"""

    _fields_ = [
        ("bi_size", dword),
        ("bi_width", long_t),
        ("bi_height", long_t),
        ("bi_planes", word),
        ("bi_bit_count", word),
        ("bi_compression", dword),
        ("bi_size_image", dword),
        ("bi_x_pels_per_meter", long_t),
        ("bi_y_pels_per_meter", long_t),
        ("bi_clr_used", dword),
        ("bi_clr_important", dword),
    ]


class memory_transfer_error(OSError):
    """raised when a memory operation transfers fewer bytes than requested"""

    def __init__(
        self,
        operation: str,
        requested_bytes: int,
        transferred_bytes: int,
        winerror: Optional[int] = None,
    ) -> None:
        self.operation = operation
        self.requested_bytes = requested_bytes
        self.transferred_bytes = transferred_bytes
        self.winerror = winerror
        message = (
            f"{operation} transferred {transferred_bytes} of "
            f"{requested_bytes} requested bytes"
        )
        if winerror is not None:
            message += f" (Windows error {winerror})"
        super().__init__(message)


def _require_windows() -> None:
    if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
        raise OSError("This operation requires Windows and the Win32 API")


def _windows_error_code() -> Optional[int]:
    if os.name == "nt" and hasattr(ctypes, "get_last_error"):
        return int(ctypes.get_last_error())
    return None


def _last_windows_error() -> OSError:
    """return the current Win32 error, with a portable fallback for test fakes"""
    error_code = _windows_error_code()
    if error_code is not None and hasattr(ctypes, "WinError"):
        return ctypes.WinError(error_code)
    return OSError("The Windows API call failed")


def _validate_size(size: int, *, allow_zero: bool = True) -> int:
    if isinstance(size, bool) or not isinstance(size, int):
        raise TypeError("size must be an integer")
    if size < 0 or (size == 0 and not allow_zero):
        qualifier = "positive" if not allow_zero else "non-negative"
        raise ValueError(f"size must be {qualifier}")
    if size > MAX_ADDRESS:
        raise ValueError("size is outside the current process SIZE_T range")
    return size


def _validate_dword(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value > MAX_DWORD:
        raise ValueError(f"{name} must fit in an unsigned 32-bit value")
    return value


def _validate_address(address: Any, *, allow_zero: bool = True) -> int:
    if isinstance(address, ctypes.c_void_p):
        address = address.value
    if address is None:
        if allow_zero:
            return 0
        raise ValueError("address must not be null")
    if isinstance(address, bool) or not isinstance(address, int):
        raise TypeError("address must be an integer or c_void_p")
    if address < 0 or address > MAX_ADDRESS:
        raise ValueError("address is outside the current process pointer range")
    if address == 0 and not allow_zero:
        raise ValueError("address must not be null")
    return address


def _validate_byteorder(byteorder: str) -> str:
    if byteorder not in ("little", "big"):
        raise ValueError("byteorder must be 'little' or 'big'")
    return byteorder


def _validate_signed(signed: bool) -> bool:
    if not isinstance(signed, bool):
        raise TypeError("signed must be a bool")
    return signed


def _unique_json_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate offset name {name!r}")
        result[name] = value
    return result


def _normalize_offsets(offsets: Mapping[str, Any]) -> Dict[str, int]:
    if not isinstance(offsets, Mapping):
        raise TypeError("offsets must be a mapping of names to integer offsets")

    normalized = {}
    for name, value in offsets.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("offset names must be non-empty strings")
        clean_name = name.strip()
        if clean_name in normalized:
            raise ValueError(f"duplicate offset name {clean_name!r}")
        if isinstance(value, bool):
            raise TypeError(f"offset {clean_name!r} must be an integer")
        if isinstance(value, int):
            normalized[clean_name] = value
        elif isinstance(value, str):
            text = value.strip()
            try:
                normalized[clean_name] = int(text, 0)
            except ValueError:
                try:
                    normalized[clean_name] = int(text, 10)
                except ValueError as exc:
                    raise ValueError(
                        f"offset {clean_name!r} is not a valid integer: {value!r}"
                    ) from exc
        else:
            raise TypeError(
                f"offset {clean_name!r} must be an integer or integer string"
            )
    return normalized


def _load_psutil() -> Any:
    try:
        import psutil
    except ImportError as exc:
        raise RuntimeError(
            "process listing requires psutil; install cmemutils with its dependencies"
        ) from exc
    return psutil


def _bind(dll: Any, export_name: str, restype: Any, argtypes: Sequence[Any]) -> Any:
    """bind an exact-case Win32 export with its argument and return types"""
    function = getattr(dll, export_name)
    function.restype = restype
    function.argtypes = list(argtypes)
    return function


class _windows_api_table:
    """typed Win32 functions, created only when a Windows call is made"""

    def __init__(self) -> None:
        _require_windows()

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

        # keep the library handles alive for the bound functions
        self.kernel32 = kernel32
        self.user32 = user32
        self.ntdll = ntdll

        self.open_process = _bind(kernel32, "OpenProcess", handle, [dword, bool_t, dword])
        self.close_handle = _bind(kernel32, "CloseHandle", bool_t, [handle])
        self.virtual_alloc = _bind(
            kernel32, "VirtualAlloc", lpvoid, [lpvoid, size_t, dword, dword]
        )
        self.virtual_free = _bind(
            kernel32, "VirtualFree", bool_t, [lpvoid, size_t, dword]
        )
        self.virtual_query = _bind(
            kernel32,
            "VirtualQuery",
            size_t,
            [lpvoid, ctypes.POINTER(memory_basic_information), size_t],
        )
        self.read_process_memory = _bind(
            kernel32,
            "ReadProcessMemory",
            bool_t,
            [handle, lpvoid, lpvoid, size_t, ctypes.POINTER(size_t)],
        )
        self.write_process_memory = _bind(
            kernel32,
            "WriteProcessMemory",
            bool_t,
            [handle, lpvoid, lpvoid, size_t, ctypes.POINTER(size_t)],
        )

        self.get_foreground_window = _bind(user32, "GetForegroundWindow", hwnd, [])
        self.get_window_text_length = _bind(
            user32, "GetWindowTextLengthW", ctypes.c_int32, [hwnd]
        )
        self.get_window_text = _bind(
            user32,
            "GetWindowTextW",
            ctypes.c_int32,
            [hwnd, ctypes.POINTER(ctypes.c_wchar), ctypes.c_int32],
        )
        self.get_window_thread_process_id = _bind(
            user32,
            "GetWindowThreadProcessId",
            dword,
            [hwnd, ctypes.POINTER(dword)],
        )
        self.enum_windows_callback_type = ctypes.WINFUNCTYPE(
            bool_t, hwnd, ctypes.c_ssize_t
        )
        self.enum_windows = _bind(
            user32,
            "EnumWindows",
            bool_t,
            [self.enum_windows_callback_type, ctypes.c_ssize_t],
        )

        self.nt_read_virtual_memory = _bind(
            ntdll,
            "NtReadVirtualMemory",
            long_t,
            [handle, lpvoid, lpvoid, size_t, ctypes.POINTER(size_t)],
        )
        self.nt_write_virtual_memory = _bind(
            ntdll,
            "NtWriteVirtualMemory",
            long_t,
            [handle, lpvoid, lpvoid, size_t, ctypes.POINTER(size_t)],
        )


_windows_api: Optional[_windows_api_table] = None
_windows_api_lock = threading.Lock()


def _get_windows_api() -> _windows_api_table:
    global _windows_api
    if _windows_api is None:
        _require_windows()
        with _windows_api_lock:
            if _windows_api is None:
                _windows_api = _windows_api_table()
    return _windows_api


class function_resolver:
    """resolve and cache correctly typed exports from Windows DLLs"""

    def __init__(self, library_loader: Optional[Callable[[str], Any]] = None) -> None:
        self.cache: Dict[Tuple[Any, ...], Any] = {}
        self._libraries: Dict[str, Any] = {}
        self._library_loader = library_loader
        self._lock = threading.RLock()

    def _load_library(self, dll: str) -> Any:
        if self._library_loader is not None:
            return self._library_loader(dll)
        _require_windows()
        return ctypes.WinDLL(dll, use_last_error=True)

    def resolve(
        self,
        dll: str,
        func: str,
        restype: Any = lpvoid,
        argtypes: Optional[Sequence[Any]] = None,
    ) -> Any:
        if not isinstance(dll, str) or not dll.strip():
            raise ValueError("dll must be a non-empty string")
        if not isinstance(func, str) or not func:
            raise ValueError("func must be a non-empty string")

        signature = tuple(argtypes or ())
        key = (dll.casefold(), func, restype, signature)
        library_key = dll.casefold()
        with self._lock:
            if key in self.cache:
                return self.cache[key]

            library = self._libraries.get(library_key)
            if library is None:
                library = self._load_library(dll)
                self._libraries[library_key] = library

            try:
                # __getitem__ creates a fresh function for each signature
                function = library[func]
            except (AttributeError, KeyError, OSError) as exc:
                raise AttributeError(
                    f"could not resolve {func!r} from {dll!r}"
                ) from exc

            function.restype = restype
            function.argtypes = list(signature)
            self.cache[key] = function
            return function


resolver = function_resolver()


class mem_utils:
    """process, memory, and offset helpers"""

    def __init__(self, api: Optional[Any] = None) -> None:
        self._api = api

    def _windows(self) -> Any:
        return self._api if self._api is not None else _get_windows_api()

    @property
    def kernel32(self) -> Any:
        """return the lazily loaded kernel32 library"""
        return self._windows().kernel32

    @property
    def ntdll(self) -> Any:
        """return the lazily loaded ntdll library"""
        return self._windows().ntdll

    def list_processes(
        self, name_contains: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """return process ids and names, optionally filtered by a name fragment"""
        if name_contains is not None and not isinstance(name_contains, str):
            raise TypeError("name_contains must be a string or None")
        psutil = _load_psutil()
        fragment = name_contains.casefold() if name_contains else ""
        processes = []
        for process in psutil.process_iter(["pid", "name"]):
            try:
                info = process.info
                process_pid = info.get("pid")
                process_name = info.get("name")
            except psutil.Error:
                continue
            if not process_pid:
                continue
            if fragment and (not process_name or fragment not in process_name.casefold()):
                continue
            processes.append({"pid": int(process_pid), "name": process_name})
        return processes

    def open_process(self, pid: int, access: int = DEFAULT_PROCESS_ACCESS) -> Any:
        """open a process with VM read/write/operation access by default"""
        pid = _validate_dword(pid, "pid")
        if pid == 0:
            raise ValueError("pid must be positive")
        access = _validate_dword(access, "access")

        process = self._windows().open_process(access, False, pid)
        if not process:
            raise _last_windows_error()
        return process

    def close_process(self, process_handle: Any) -> None:
        """close a handle returned by ``open_process``"""
        if not process_handle:
            return
        if not self._windows().close_handle(process_handle):
            raise _last_windows_error()

    @contextmanager
    def opened_process(
        self, pid: int, access: int = DEFAULT_PROCESS_ACCESS
    ) -> Iterator[Any]:
        """open a process for a ``with`` block and always close its handle"""
        process = self.open_process(pid, access=access)
        try:
            yield process
        finally:
            self.close_process(process)

    def find_process(
        self,
        name: Optional[str] = None,
        window_title: Optional[str] = None,
    ) -> Tuple[Optional[Any], int]:
        """find a process by executable name and/or a top-level window title"""
        if name is not None and not isinstance(name, str):
            raise TypeError("name must be a string or None")
        if window_title is not None and not isinstance(window_title, str):
            raise TypeError("window_title must be a string or None")

        has_name = bool(name and name.strip())
        has_window_title = bool(window_title and window_title.strip())
        if not has_name and not has_window_title:
            raise ValueError("provide a process name, a window title, or both")

        if has_window_title:
            try:
                match = self._find_window(window_title.strip())
            except OSError:
                if not has_name:
                    raise
            else:
                if match is not None:
                    return match

        if has_name:
            psutil = _load_psutil()
            requested_name = name.strip().casefold()
            for process in psutil.process_iter(["pid", "name"]):
                try:
                    info = process.info
                    process_name = info.get("name")
                    process_pid = info.get("pid")
                except psutil.Error:
                    continue
                if process_name and process_name.casefold() == requested_name and process_pid:
                    return None, int(process_pid)

        raise ValueError("process not found")

    def _find_window(self, title_fragment: str) -> Optional[Tuple[Any, int]]:
        api = self._windows()
        fragment = title_fragment.casefold()
        matches = []
        callback_errors = []
        callback_factory = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
        callback_type = callback_factory(bool_t, hwnd, ctypes.c_ssize_t)

        def inspect_window(window_handle: Any, lparam: int) -> int:
            try:
                title_length = api.get_window_text_length(window_handle)
                if title_length <= 0:
                    return 1
                buffer = ctypes.create_unicode_buffer(title_length + 1)
                copied = api.get_window_text(window_handle, buffer, title_length + 1)
                if copied > 0 and fragment in buffer.value[:copied].casefold():
                    pid = dword()
                    if api.get_window_thread_process_id(window_handle, ctypes.byref(pid)):
                        matches.append((window_handle, int(pid.value)))
            except Exception as exc:
                # exceptions cannot escape a ctypes callback safely
                callback_errors.append(exc)
            return 1

        callback = callback_type(inspect_window)
        succeeded = api.enum_windows(callback, 0)
        if callback_errors:
            raise callback_errors[0]
        if not succeeded:
            raise _last_windows_error()
        return matches[0] if matches else None

    def virtual_query(self, addr: int) -> memory_basic_information:
        """query a current-process address with ``VirtualQuery``"""
        address = _validate_address(addr)
        info = memory_basic_information()
        result = self._windows().virtual_query(
            lpvoid(address), ctypes.byref(info), ctypes.sizeof(info)
        )
        if not result:
            raise _last_windows_error()
        return info

    def alloc(
        self,
        size: int,
        prot: int = PAGE_READWRITE,
        type_: int = MEM_RESERVE | MEM_COMMIT,
    ) -> int:
        """allocate non-executable read/write memory in the current process"""
        _validate_size(size, allow_zero=False)
        prot = _validate_dword(prot, "prot")
        type_ = _validate_dword(type_, "type_")

        address = self._windows().virtual_alloc(None, size, type_, prot)
        if not address:
            raise _last_windows_error()
        return int(address)

    def free(self, addr: int) -> None:
        """release a current-process allocation with ``MEM_RELEASE``"""
        address = _validate_address(addr, allow_zero=False)
        if not self._windows().virtual_free(lpvoid(address), 0, MEM_RELEASE):
            raise _last_windows_error()

    def rpm(self, process_handle: Any, address: int, size: int) -> bytes:
        """read exactly ``size`` bytes or raise on a short read"""
        address = _validate_address(address)
        size = _validate_size(size)
        if size == 0:
            return b""

        buffer = ctypes.create_string_buffer(size)
        transferred = size_t(0)
        succeeded = self._windows().read_process_memory(
            process_handle,
            lpvoid(address),
            ctypes.cast(buffer, lpvoid),
            size,
            ctypes.byref(transferred),
        )
        count = int(transferred.value)
        if not succeeded:
            if count:
                raise memory_transfer_error(
                    "ReadProcessMemory", size, count, _windows_error_code()
                )
            raise _last_windows_error()
        if count != size:
            raise memory_transfer_error("ReadProcessMemory", size, count)
        return buffer.raw[:count]

    def wpm(self, process_handle: Any, address: int, data: bytes) -> int:
        """write all bytes and return the number written"""
        address = _validate_address(address)
        try:
            payload = memoryview(data).tobytes()
        except TypeError as exc:
            raise TypeError("data must be bytes-like") from exc
        if not payload:
            return 0

        buffer = ctypes.create_string_buffer(payload)
        transferred = size_t(0)
        succeeded = self._windows().write_process_memory(
            process_handle,
            lpvoid(address),
            ctypes.cast(buffer, lpvoid),
            len(payload),
            ctypes.byref(transferred),
        )
        count = int(transferred.value)
        if not succeeded:
            if count:
                raise memory_transfer_error(
                    "WriteProcessMemory",
                    len(payload),
                    count,
                    _windows_error_code(),
                )
            raise _last_windows_error()
        if count != len(payload):
            raise memory_transfer_error("WriteProcessMemory", len(payload), count)
        return count

    def read_int(
        self,
        process_handle: Any,
        address: int,
        size: int = 4,
        signed: bool = False,
        byteorder: str = "little",
    ) -> int:
        """read an integer of ``size`` bytes from process memory"""
        size = _validate_size(size, allow_zero=False)
        signed = _validate_signed(signed)
        byteorder = _validate_byteorder(byteorder)
        return int.from_bytes(
            self.rpm(process_handle, address, size), byteorder, signed=signed
        )

    def write_int(
        self,
        process_handle: Any,
        address: int,
        value: int,
        size: int = 4,
        signed: bool = False,
        byteorder: str = "little",
    ) -> int:
        """write an integer and return the number of bytes written"""
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("value must be an integer")
        size = _validate_size(size, allow_zero=False)
        signed = _validate_signed(signed)
        byteorder = _validate_byteorder(byteorder)
        payload = value.to_bytes(size, byteorder, signed=signed)
        return self.wpm(process_handle, address, payload)

    def read_float(
        self,
        process_handle: Any,
        address: int,
        size: int = 4,
        byteorder: str = "little",
    ) -> float:
        """read a 32-bit or 64-bit floating-point value"""
        format_string = _float_format(size, byteorder)
        value = struct.unpack(
            format_string, self.rpm(process_handle, address, size)
        )[0]
        return float(value)

    def write_float(
        self,
        process_handle: Any,
        address: int,
        value: Union[int, float],
        size: int = 4,
        byteorder: str = "little",
    ) -> int:
        """write a 32-bit or 64-bit floating-point value"""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("value must be an integer or float")
        format_string = _float_format(size, byteorder)
        payload = struct.pack(format_string, value)
        return self.wpm(process_handle, address, payload)

    def read_pointer_chain(
        self,
        process_handle: Any,
        base_address: int,
        offsets: Sequence[int],
        pointer_size: int = POINTER_SIZE,
        byteorder: str = "little",
    ) -> int:
        """resolve a pointer chain, dereferencing every offset except the last"""
        offsets = tuple(offsets)
        if not offsets:
            raise ValueError("offsets must contain at least one entry")
        if pointer_size not in (4, 8):
            raise ValueError("pointer_size must be 4 or 8 bytes")
        byteorder = _validate_byteorder(byteorder)

        address = _validate_address(base_address)
        for index, offset in enumerate(offsets):
            if isinstance(offset, bool) or not isinstance(offset, int):
                raise TypeError("offset entries must be integers")
            address = _validate_address(address + offset)
            if index < len(offsets) - 1:
                address = self.read_int(
                    process_handle,
                    address,
                    size=pointer_size,
                    signed=False,
                    byteorder=byteorder,
                )
                if address == 0:
                    raise ValueError("null pointer encountered while resolving chain")
        return address

    def nt_rpm(self, process_handle: Any, address: int, size: int) -> bytes:
        """read exactly ``size`` bytes with ``NtReadVirtualMemory``"""
        address = _validate_address(address)
        size = _validate_size(size)
        if size == 0:
            return b""

        buffer = ctypes.create_string_buffer(size)
        transferred = size_t(0)
        status = self._windows().nt_read_virtual_memory(
            process_handle,
            lpvoid(address),
            ctypes.cast(buffer, lpvoid),
            size,
            ctypes.byref(transferred),
        )
        count = int(transferred.value)
        if int(status) < 0:
            raise OSError(
                "NtReadVirtualMemory failed with NTSTATUS "
                f"0x{int(status) & MAX_DWORD:08X}"
            )
        if count != size:
            raise memory_transfer_error("NtReadVirtualMemory", size, count)
        return buffer.raw[:count]

    def nt_wpm(self, process_handle: Any, address: int, data: bytes) -> int:
        """write all bytes with ``NtWriteVirtualMemory``"""
        address = _validate_address(address)
        try:
            payload = memoryview(data).tobytes()
        except TypeError as exc:
            raise TypeError("data must be bytes-like") from exc
        if not payload:
            return 0

        buffer = ctypes.create_string_buffer(payload)
        transferred = size_t(0)
        status = self._windows().nt_write_virtual_memory(
            process_handle,
            lpvoid(address),
            ctypes.cast(buffer, lpvoid),
            len(payload),
            ctypes.byref(transferred),
        )
        count = int(transferred.value)
        if int(status) < 0:
            raise OSError(
                "NtWriteVirtualMemory failed with NTSTATUS "
                f"0x{int(status) & MAX_DWORD:08X}"
            )
        if count != len(payload):
            raise memory_transfer_error("NtWriteVirtualMemory", len(payload), count)
        return count


def _float_format(size: int, byteorder: str) -> str:
    if isinstance(size, bool) or not isinstance(size, int):
        raise TypeError("size must be an integer")
    if size not in (4, 8):
        raise ValueError("float size must be 4 or 8 bytes")
    byteorder = _validate_byteorder(byteorder)
    prefix = "<" if byteorder == "little" else ">"
    code = "f" if size == 4 else "d"
    return prefix + code


def resolve_offset(base_address: int, offset: int) -> int:
    """add a signed offset to a base address and validate the pointer range"""
    base_address = _validate_address(base_address)
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("offset must be an integer")
    return _validate_address(base_address + offset)


def load_offsets(file_path: Union[str, os.PathLike]) -> Dict[str, int]:
    """load a name-to-integer offset map from a JSON or CSV file"""
    path = Path(file_path)
    suffix = path.suffix.casefold()
    if suffix not in OFFSET_FILE_FORMATS:
        raise ValueError(f"offset files must use one of: {', '.join(OFFSET_FILE_FORMATS)}")

    if suffix == ".json":
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file, object_pairs_hook=_unique_json_object)
        return _normalize_offsets(data)

    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or not {"name", "offset"}.issubset(reader.fieldnames):
            raise ValueError("CSV offset files must have 'name' and 'offset' columns")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("CSV offset files cannot contain duplicate columns")
        offsets = {}
        for row_number, row in enumerate(reader, start=2):
            name = (row.get("name") or "").strip()
            if not name:
                raise ValueError(f"missing offset name on CSV row {row_number}")
            if name in offsets:
                raise ValueError(f"duplicate offset name {name!r} on CSV row {row_number}")
            offsets[name] = row.get("offset")
    return _normalize_offsets(offsets)


def save_offsets(
    file_path: Union[str, os.PathLike], offsets: Mapping[str, Any]
) -> None:
    """save a name-to-integer offset map as JSON or CSV"""
    path = Path(file_path)
    suffix = path.suffix.casefold()
    if suffix not in OFFSET_FILE_FORMATS:
        raise ValueError(f"offset files must use one of: {', '.join(OFFSET_FILE_FORMATS)}")
    normalized = _normalize_offsets(offsets)

    if suffix == ".json":
        with path.open("w", encoding="utf-8", newline="\n") as file:
            json.dump(normalized, file, indent=2, sort_keys=True)
            file.write("\n")
        return

    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(("name", "offset"))
        for name in sorted(normalized):
            writer.writerow((name, normalized[name]))


def get_foreground_title(max_len: int = 512) -> str:
    """return the title of the current foreground window"""
    _validate_size(max_len, allow_zero=False)
    api = _get_windows_api()
    window = api.get_foreground_window()
    if not window:
        return ""
    buffer = ctypes.create_unicode_buffer(max_len)
    length = api.get_window_text(window, buffer, max_len)
    return buffer.value[: max(0, int(length))]


def virtual_alloc(
    address: Optional[int], size: int, allocation_type: int, protect: int
) -> Any:
    """typed wrapper around ``VirtualAlloc``"""
    return _get_windows_api().virtual_alloc(address, size, allocation_type, protect)


def virtual_free(address: int, size: int, free_type: int) -> Any:
    """typed wrapper around ``VirtualFree``"""
    return _get_windows_api().virtual_free(address, size, free_type)


def get_foreground_window() -> Any:
    """typed wrapper around ``GetForegroundWindow``"""
    return _get_windows_api().get_foreground_window()


def get_window_text_w(window: Any, buffer: Any, max_count: int) -> int:
    """typed wrapper around ``GetWindowTextW``"""
    return int(_get_windows_api().get_window_text(window, buffer, max_count))


def read_process_memory(*args: Any) -> Any:
    """typed wrapper around ``ReadProcessMemory``"""
    return _get_windows_api().read_process_memory(*args)


def write_process_memory(*args: Any) -> Any:
    """typed wrapper around ``WriteProcessMemory``"""
    return _get_windows_api().write_process_memory(*args)


def nt_read_virtual_memory(*args: Any) -> Any:
    """typed wrapper around ``NtReadVirtualMemory``"""
    return _get_windows_api().nt_read_virtual_memory(*args)


def nt_write_virtual_memory(*args: Any) -> Any:
    """typed wrapper around ``NtWriteVirtualMemory``"""
    return _get_windows_api().nt_write_virtual_memory(*args)
