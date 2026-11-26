# api reference

`cmemutils` is Windows-focused. The package can be imported on any platform,
but Win32-backed methods raise `OSError` when called off Windows. Process
listing and executable-name lookup use the `psutil` dependency installed with
the package.

```python
from cmemutils import mem_utils

memory = mem_utils()
```

## process helpers

### `list_processes(name_contains=None)`

Returns a list of dictionaries with `pid` and `name` fields. The optional
`name_contains` filter is a case-insensitive substring. Processes that exit or
become inaccessible during enumeration are skipped.

```python
for process in memory.list_processes(name_contains="python"):
    print(process["pid"], process["name"])
```

### `find_process(name=None, window_title=None)`

Returns `(hwnd, pid)`. A title search checks all top-level windows, including
background windows. If both arguments are provided, a matching title is tried
first and process-name lookup is the fallback. On non-Windows systems, a title
search is unavailable; when a name is also supplied, name lookup still works.
Raises `ValueError` if no process matches.

### `open_process(pid, access=DEFAULT_PROCESS_ACCESS)`

Returns a native process handle. The default requests only VM operation, read,
and write rights. Pass a narrower access mask for read-only work or an explicit
mask for other needs. The caller owns the returned handle.

- `close_process(handle)` closes the handle.
- `opened_process(pid, access=DEFAULT_PROCESS_ACCESS)` is a context manager
  that closes it even when an exception occurs:

  ```python
  with memory.opened_process(pid) as process:
      data = memory.rpm(process, address, 16)
  ```

## memory helpers

### byte reads and writes

- `rpm(process_handle, address, size) -> bytes` reads exactly `size` bytes.
- `wpm(process_handle, address, data) -> int` writes all bytes and returns the
  number written.
- `nt_rpm(...)` and `nt_wpm(...)` provide equivalent native NT calls. Prefer
  `rpm` and `wpm` unless the lower-level NT interfaces are specifically needed.

A short transfer raises `memory_transfer_error`, an `OSError` subclass with
`operation`, `requested_bytes`, `transferred_bytes`, and (when available)
`winerror` attributes. A short write may already have changed part of the
target memory.

### integers and floating-point values

- `read_int(process_handle, address, size=4, signed=False,
  byteorder="little") -> int`
- `write_int(process_handle, address, value, size=4, signed=False,
  byteorder="little") -> int`
- `read_float(process_handle, address, size=4, byteorder="little") -> float`
- `write_float(process_handle, address, value, size=4,
  byteorder="little") -> int`

Integer sizes are specified in bytes. Float size must be `4` (single precision)
or `8` (double precision). Byte order must be `"little"` or `"big"`.

```python
with memory.opened_process(pid) as process:
    health = memory.read_int(process, address, size=4)
    memory.write_int(process, address, health + 1, size=4)
```

### pointer chains and address offsets

`read_pointer_chain(process_handle, base_address, offsets, pointer_size=POINTER_SIZE,
byteorder="little")` adds each offset and dereferences a pointer at every step
except the last. `pointer_size` must be `4` or `8`; set it explicitly if the
target process has a different bitness from Python.

```python
health_address = memory.read_pointer_chain(
    process,
    base_address=module_base,
    offsets=[0x20, 0x18, 0x8],
    pointer_size=8,
)
health = memory.read_int(process, health_address, size=4)
```

`resolve_offset(base_address, offset)` adds one signed offset to a base address
and checks the result fits the current process pointer range. It does not read
or dereference memory.

### current-process virtual memory

These methods operate on the Python process, not the process handle passed to
`rpm` or `wpm`:

- `virtual_query(address) -> memory_basic_information`
- `alloc(size, prot=PAGE_READWRITE,
  type_=MEM_RESERVE | MEM_COMMIT) -> int`
- `free(address) -> None`

`alloc` defaults to non-executable read/write pages. Use
`PAGE_EXECUTE_READWRITE` only when executable memory is specifically required.
Pair each allocation with `free`.

## offset files

`load_offsets(file_path)` and `save_offsets(file_path, offsets)` support `.json`
and `.csv` files. Both return/use a mapping of non-empty names to integers.
Loading accepts decimal values and integer strings such as `"0x1234"`.
CSV files must include unique `name` and `offset` columns; additional columns
are ignored. Offset names may not repeat. Unknown extensions or malformed data
raise `ValueError`.

```python
from cmemutils import load_offsets, save_offsets

offsets = load_offsets("offsets.json")
save_offsets("offsets.csv", offsets)
```

## window and function helpers

- `get_foreground_title(max_len=512) -> str` returns the current foreground
  window title. `max_len` must be a positive integer.
- `function_resolver` resolves and caches an exact-case export from a Windows
  DLL. Pass its return type and argument types to avoid unsafe default
  signatures. DLL export names retain their exact Windows capitalization.

```python
from ctypes import c_uint32
from cmemutils import function_resolver

function_resolver_instance = function_resolver()
get_tick_count = function_resolver_instance.resolve(
    "kernel32.dll", "GetTickCount", restype=c_uint32, argtypes=[]
)
print(get_tick_count())
```

## structures and constants

Exported structures are `memory_basic_information`, `bitmap_file_header`, and
`bitmap_info_header`. The bitmap file header is packed to its 14-byte on-disk
layout.

Useful constants include `MEM_COMMIT`, `MEM_RESERVE`, `MEM_RELEASE`,
`PAGE_READWRITE`, `PAGE_EXECUTE_READWRITE`, `DEFAULT_PROCESS_ACCESS`, and
`POINTER_SIZE`. All Win32-backed operations validate sizes and addresses before
calling the native API.

## current scope

The library does not currently enumerate loaded modules or allocate memory in a
remote process. `alloc`, `free`, and `virtual_query` apply only to the current
Python process.
