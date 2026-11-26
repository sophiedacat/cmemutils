# cmemutils

`cmemutils` is a small Python library for process discovery, memory access, and
offset handling. It is intended for debugging software you own or are
authorized to inspect.

> **responsible use only.** Do not use this project to violate laws, service
> terms, or other people's privacy. Memory access can crash a process or damage
> its data. The authors are not responsible for misuse or resulting penalties.

## utilities

- List processes or find one by executable name or top-level window title.
- Open and automatically close process handles.
- Read and write bytes, integers, and floating-point values.
- Follow pointer chains using explicit offsets and target pointer size.
- Query, allocate, and free memory in the **current process**.
- Load and save offset maps in JSON or CSV format.
- Resolve a base address plus a signed offset.

This release does **not** provide module enumeration or remote-process
allocation. `alloc()` only allocates in the current process.

## platform and Python support

- Python 3.9 or newer.
- Process-memory and window-title APIs require Windows. Importing `cmemutils`
  is safe on other platforms; calling a Windows-only operation there raises a
  clear `OSError`.
- Process listing and name lookup use `psutil`, installed automatically with
  the package. Process access may still be denied by Windows permissions or
  security software.

## installation

From a checkout:

```console
python -m pip install .
```

For development and tests:

```console
python -m pip install -e ".[test]"
python -m pytest
```

## quick start

This example reads and then changes a buffer owned by the current Python
process. It avoids relying on another process or a hard-coded address:

```python
import ctypes
import os

from cmemutils import mem_utils

memory = mem_utils()
buffer = ctypes.create_string_buffer(b"hello")
address = ctypes.addressof(buffer)

with memory.opened_process(os.getpid()) as process:
    print(memory.rpm(process, address, 5))  # b"hello"
    memory.wpm(process, address, b"HELLO")

print(buffer.raw[:5])  # b"HELLO"
```

Only use process-memory operations on processes you own or are authorized to
debug. Allocations default to non-executable read/write pages. Requesting
`PAGE_EXECUTE_READWRITE` should be an explicit, carefully considered choice.

## offset files

JSON and CSV offset maps use names mapped to integer values. Hex strings are
accepted when loading either format:

```json
{
  "player_base": "0x1234",
  "health": 32
}
```

```python
from cmemutils import load_offsets, save_offsets

offsets = load_offsets("offsets.json")
save_offsets("offsets.csv", offsets)
```

## testing

The unit suite uses fake API objects for deterministic memory and process
behavior, so it can run without Windows. GitHub Actions also runs the suite on
Windows and Linux across several supported Python versions.

See [`docs.md`](docs.md) for the complete API and examples. See
[`LICENSE`](LICENSE) for the license terms.
