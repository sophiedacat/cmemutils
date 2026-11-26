import ctypes
import os
import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from cmemutils import (
    DEFAULT_PROCESS_ACCESS,
    MEM_COMMIT,
    MEM_RELEASE,
    MEM_RESERVE,
    PAGE_READWRITE,
    bitmap_file_header,
    bitmap_info_header,
    function_resolver,
    load_offsets,
    mem_utils,
    memory_basic_information,
    memory_transfer_error,
    resolve_offset,
    save_offsets,
)
from cmemutils.system import dword, size_t
from cmemutils import system as system_module


# fake win32 functions for portable tests
class fake_kernel32:
    def __init__(self):
        self.read_data = b"sample-data"
        self.read_limit = None
        self.write_limit = None
        self.written_data = None
        self.allocation = None
        self.closed_handles = []

    def open_process(self, access, inherit, pid):
        self.opened = (access, inherit, pid)
        return 0xCAFE

    def close_handle(self, process_handle):
        self.closed_handles.append(process_handle)
        return 1

    def virtual_alloc(self, address, size, allocation_type, protect):
        self.allocation = (address, size, allocation_type, protect)
        return 0x12340000

    def virtual_free(self, address, size, free_type):
        raw_address = address.value if isinstance(address, ctypes.c_void_p) else address
        self.freed = (raw_address, size, free_type)
        return 1

    def virtual_query(self, address, info, info_size):
        self.query = (address, info_size)
        ctypes.cast(info, ctypes.POINTER(memory_basic_information)).contents.region_size = 4096
        return info_size

    def read_process_memory(self, process_handle, address, buffer, size, transferred):
        amount = min(size, len(self.read_data))
        if self.read_limit is not None:
            amount = min(amount, self.read_limit)
        if amount:
            ctypes.memmove(buffer, self.read_data, amount)
        ctypes.cast(transferred, ctypes.POINTER(size_t)).contents.value = amount
        return 1

    def write_process_memory(self, process_handle, address, buffer, size, transferred):
        amount = size if self.write_limit is None else min(size, self.write_limit)
        self.written_data = ctypes.string_at(buffer, amount)
        ctypes.cast(transferred, ctypes.POINTER(size_t)).contents.value = amount
        return 1


class fake_ntdll:
    def nt_read_virtual_memory(self, process_handle, address, buffer, size, transferred):
        payload = b"native"
        amount = min(size, len(payload))
        if amount:
            ctypes.memmove(buffer, payload, amount)
        ctypes.cast(transferred, ctypes.POINTER(size_t)).contents.value = amount
        return 0

    def nt_write_virtual_memory(self, process_handle, address, buffer, size, transferred):
        ctypes.cast(transferred, ctypes.POINTER(size_t)).contents.value = size
        return 0


class fake_user32:
    def __init__(self):
        self.titles = {
            101: "Background - Notepad",
            202: "Terminal",
        }
        self.pids = {101: 42, 202: 84}

    def enum_windows(self, callback, lparam):
        for window in self.titles:
            callback(window, lparam)
        return 1

    def get_window_text_length(self, window):
        return len(self.titles.get(window, ""))

    def get_window_text(self, window, buffer, max_count):
        value = self.titles.get(window, "")[: max(0, max_count - 1)]
        buffer.value = value
        return len(value)

    def get_window_thread_process_id(self, window, pid_pointer):
        pid = self.pids.get(window, 0)
        ctypes.cast(pid_pointer, ctypes.POINTER(dword)).contents.value = pid
        return 1 if pid else 0

    def get_foreground_window(self):
        return 202


class fake_api:
    def __init__(self):
        self.kernel32 = fake_kernel32()
        self.user32 = fake_user32()
        self.ntdll = fake_ntdll()
        self.open_process = self.kernel32.open_process
        self.close_handle = self.kernel32.close_handle
        self.virtual_alloc = self.kernel32.virtual_alloc
        self.virtual_free = self.kernel32.virtual_free
        self.virtual_query = self.kernel32.virtual_query
        self.read_process_memory = self.kernel32.read_process_memory
        self.write_process_memory = self.kernel32.write_process_memory
        self.enum_windows = self.user32.enum_windows
        self.get_window_text_length = self.user32.get_window_text_length
        self.get_window_text = self.user32.get_window_text
        self.get_window_thread_process_id = self.user32.get_window_thread_process_id
        self.get_foreground_window = self.user32.get_foreground_window
        self.nt_read_virtual_memory = self.ntdll.nt_read_virtual_memory
        self.nt_write_virtual_memory = self.ntdll.nt_write_virtual_memory


class system_tests(unittest.TestCase):
    def setUp(self):
        self.api = fake_api()
        self.memory = mem_utils(api=self.api)

    def test_module_import_and_construction_do_not_load_windows_dlls(self):
        self.assertIsInstance(mem_utils(), mem_utils)

    @unittest.skipUnless(os.name == "nt", "requires Windows")
    def test_native_windows_bindings_have_pointer_safe_signatures(self):
        api = system_module._get_windows_api()
        self.assertIs(api.open_process.restype, ctypes.c_void_p)
        self.assertIs(api.virtual_alloc.restype, ctypes.c_void_p)
        self.assertIs(
            api.get_window_text.argtypes[1],
            ctypes.POINTER(ctypes.c_wchar),
        )
        self.assertIs(api.nt_read_virtual_memory.restype, ctypes.c_int32)

    @unittest.skipUnless(os.name == "nt", "requires Windows")
    def test_live_self_process_memory_round_trip(self):
        memory = mem_utils()
        buffer = ctypes.create_string_buffer(b"test")
        address = ctypes.addressof(buffer)
        with memory.opened_process(os.getpid()) as process:
            self.assertEqual(memory.rpm(process, address, 4), b"test")
            self.assertEqual(memory.wpm(process, address, b"LIVE"), 4)
        self.assertEqual(buffer.raw[:4], b"LIVE")

    def test_windows_operations_fail_clearly_on_non_windows(self):
        if os.name == "nt":
            self.skipTest("non-Windows import behavior is not applicable")
        with self.assertRaisesRegex(OSError, "requires Windows"):
            mem_utils().open_process(1234)
        with self.assertRaisesRegex(OSError, "requires Windows"):
            system_module.get_foreground_title()
        with self.assertRaisesRegex(OSError, "requires Windows"):
            function_resolver().resolve("kernel32.dll", "GetTickCount")

    def test_struct_layouts(self):
        self.assertEqual(ctypes.sizeof(bitmap_file_header), 14)
        self.assertEqual(ctypes.sizeof(bitmap_info_header), 40)
        expected_size = 48 if ctypes.sizeof(ctypes.c_void_p) == 8 else 28
        self.assertEqual(ctypes.sizeof(memory_basic_information), expected_size)

    def test_open_process_uses_limited_default_access(self):
        process_handle = self.memory.open_process(1234)
        self.assertEqual(process_handle, 0xCAFE)
        self.assertEqual(
            self.api.kernel32.opened,
            (DEFAULT_PROCESS_ACCESS, False, 1234),
        )
        self.assertEqual(DEFAULT_PROCESS_ACCESS, 0x38)

    def test_opened_process_closes_handle_even_when_body_raises(self):
        with self.assertRaisesRegex(RuntimeError, "body failed"):
            with self.memory.opened_process(1234) as process_handle:
                self.assertEqual(process_handle, 0xCAFE)
                raise RuntimeError("body failed")
        self.assertEqual(self.api.kernel32.closed_handles, [0xCAFE])

    def test_alloc_uses_reserved_committed_non_executable_memory(self):
        address = self.memory.alloc(32)
        self.assertEqual(address, 0x12340000)
        self.assertEqual(
            self.api.kernel32.allocation,
            (None, 32, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE),
        )

    def test_alloc_validates_size_before_calling_windows(self):
        with self.assertRaises(ValueError):
            self.memory.alloc(0)
        self.assertIsNone(self.api.kernel32.allocation)

    def test_free_uses_release_semantics(self):
        self.memory.free(0x12340000)
        self.assertEqual(self.api.kernel32.freed, (0x12340000, 0, MEM_RELEASE))

    def test_rpm_reads_exact_requested_bytes(self):
        self.assertEqual(self.memory.rpm(1, 0x1000, 6), b"sample")
        self.assertEqual(self.memory.rpm(1, 0x1000, 0), b"")

    def test_rpm_reports_short_reads(self):
        self.api.kernel32.read_limit = 3
        with self.assertRaises(memory_transfer_error) as raised:
            self.memory.rpm(1, 0x1000, 6)
        self.assertEqual(raised.exception.requested_bytes, 6)
        self.assertEqual(raised.exception.transferred_bytes, 3)

    def test_wpm_writes_bytes_and_rejects_short_writes(self):
        self.assertEqual(self.memory.wpm(1, 0x1000, b"write"), 5)
        self.assertEqual(self.api.kernel32.written_data, b"write")
        self.api.kernel32.write_limit = 2
        with self.assertRaises(memory_transfer_error):
            self.memory.wpm(1, 0x1000, b"write")

    def test_integer_and_float_helpers(self):
        self.api.kernel32.read_data = (0x12345678).to_bytes(4, "little")
        self.assertEqual(self.memory.read_int(1, 0x1000), 0x12345678)
        self.assertEqual(self.memory.write_int(1, 0x1000, 0x12345678), 4)
        self.assertEqual(self.api.kernel32.written_data, b"\x78\x56\x34\x12")

        self.api.kernel32.read_data = struct.pack("<f", 1.25)
        self.assertEqual(self.memory.read_float(1, 0x1000), 1.25)
        self.assertEqual(self.memory.write_float(1, 0x1000, 1.25), 4)
        self.assertAlmostEqual(struct.unpack("<f", self.api.kernel32.written_data)[0], 1.25)

        self.api.kernel32.read_data = b"\xff\xfe"
        self.assertEqual(
            self.memory.read_int(1, 0x1000, size=2, signed=True, byteorder="big"),
            -2,
        )
        self.memory.write_int(1, 0x1000, -2, size=2, signed=True, byteorder="big")
        self.assertEqual(self.api.kernel32.written_data, b"\xff\xfe")

    def test_pointer_chain_resolves_offsets(self):
        with patch.object(
            self.memory, "rpm", return_value=(0x2000).to_bytes(8, "little")
        ) as read_memory:
            result = self.memory.read_pointer_chain(
                1, 0x1000, [0x10, 0x20], pointer_size=8
            )
        self.assertEqual(result, 0x2020)
        read_memory.assert_called_once_with(1, 0x1010, 8)

    def test_native_memory_helpers_use_ntstatus_and_transfer_counts(self):
        self.assertEqual(self.memory.nt_rpm(1, 0x1000, 6), b"native")
        self.assertEqual(self.memory.nt_wpm(1, 0x1000, b"data"), 4)

    def test_virtual_query_returns_structure(self):
        info = self.memory.virtual_query(0x1000)
        self.assertEqual(info.region_size, 4096)

    def test_window_title_search_checks_non_foreground_windows(self):
        self.assertEqual(self.memory.find_process(window_title="notepad"), (101, 42))

    def test_process_name_lookup_handles_missing_names_and_races(self):
        class fake_process:
            def __init__(self, info=None, error=None):
                self._info = info or {}
                self.error = error

            @property
            def info(self):
                if self.error:
                    raise self.error
                return self._info

        class fake_process_error(Exception):
            pass

        fake_psutil = types.SimpleNamespace(
            process_iter=lambda _attrs: [
                fake_process({"pid": 1, "name": None}),
                fake_process(error=fake_process_error("process exited")),
                fake_process({"pid": 42, "name": "Notepad.EXE"}),
            ]
        )
        setattr(fake_psutil, "Error", fake_process_error)
        with patch.dict(sys.modules, {"psutil": fake_psutil}):
            self.assertEqual(self.memory.find_process(name="notepad.exe"), (None, 42))

    @unittest.skipIf(os.name == "nt", "fallback is for non-Windows hosts")
    def test_name_lookup_falls_back_when_window_search_is_unavailable(self):
        fake_psutil = types.SimpleNamespace(
            process_iter=lambda _attrs: [
                types.SimpleNamespace(info={"pid": 7, "name": "demo.exe"})
            ]
        )
        setattr(fake_psutil, "Error", Exception)
        with patch.dict(sys.modules, {"psutil": fake_psutil}):
            result = mem_utils().find_process(name="demo.exe", window_title="a title")
        self.assertEqual(result, (None, 7))

    def test_list_processes_filters_names(self):
        fake_psutil = types.SimpleNamespace(
            process_iter=lambda _attrs: [
                types.SimpleNamespace(info={"pid": 1, "name": "python.exe"}),
                types.SimpleNamespace(info={"pid": 2, "name": "editor.exe"}),
            ]
        )
        setattr(fake_psutil, "Error", Exception)
        with patch.dict(sys.modules, {"psutil": fake_psutil}):
            result = self.memory.list_processes(name_contains="EDIT")
        self.assertEqual(result, [{"pid": 2, "name": "editor.exe"}])

    def test_offset_json_and_csv_round_trip(self):
        offsets = {"health": 0x1234, "signed_delta": -8}
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "offsets.json"
            csv_path = Path(temp_dir) / "offsets.csv"
            save_offsets(json_path, offsets)
            save_offsets(csv_path, offsets)
            self.assertEqual(load_offsets(json_path), offsets)
            self.assertEqual(load_offsets(csv_path), offsets)

    def test_offset_loader_accepts_hex_strings_and_rejects_bad_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "offsets.json"
            json_path.write_text('{"base": "0x10", "count": "16"}', encoding="utf-8")
            self.assertEqual(load_offsets(json_path), {"base": 16, "count": 16})

            json_path.write_text('{"base": 1, "base": 2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_offsets(json_path)

            csv_path = Path(temp_dir) / "bad.csv"
            csv_path.write_text("name,offset\nbase,1\nbase,2\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_offsets(csv_path)

            invalid_path = Path(temp_dir) / "offsets.txt"
            with self.assertRaisesRegex(ValueError, "must use"):
                load_offsets(invalid_path)

    def test_resolve_offset_checks_address_range(self):
        self.assertEqual(resolve_offset(0x1000, 0x20), 0x1020)
        self.assertEqual(resolve_offset(0x1000, -0x20), 0xFE0)
        with self.assertRaises(ValueError):
            resolve_offset(0, -1)

    def test_function_resolver_caches_signatures_separately(self):
        class fake_function:
            restype = None
            argtypes = None

        class fake_library:
            def __getitem__(self, name):
                self.last_name = name
                return fake_function()

        library = fake_library()
        loads = []

        def loader(name):
            loads.append(name)
            return library

        resolver = function_resolver(library_loader=loader)
        first = resolver.resolve("sample.dll", "SampleCall", ctypes.c_int, [ctypes.c_int])
        cached = resolver.resolve("SAMPLE.DLL", "SampleCall", ctypes.c_int, [ctypes.c_int])
        second = resolver.resolve("sample.dll", "SampleCall", ctypes.c_long, [ctypes.c_long])

        self.assertIs(first, cached)
        self.assertIsNot(first, second)
        self.assertEqual(first.argtypes, [ctypes.c_int])
        self.assertEqual(second.argtypes, [ctypes.c_long])
        self.assertEqual(library.last_name, "SampleCall")
        self.assertEqual(loads, ["sample.dll"])


if __name__ == "__main__":
    unittest.main()
