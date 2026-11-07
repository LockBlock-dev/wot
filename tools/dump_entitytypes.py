#!/usr/bin/env python3
"""Dump the client's EntityType table: the id -> name mapping the NRL uses.

`BW::EntityType::find` (sub_14039A7F0) is a plain index into one global vector
of type records, shared by entities and dynamic components alike:

    if ( index < (end - begin) >> 3 )
        return *(EntityType **)(begin + 8 * index);

That vector is filled at load time from the game's own defs, so the ordering
cannot be read from the packages or from the binary's strings — it only exists
in the running process. This reads it out of memory.

Layout, all verified against the live 2.4.1.1 client:

  * the vector's begin/end pointers are at 0x144B5E160 / 0x144B5E168;
  * each element is a pointer to a record whose first field is the
    `EntityType *` (`PyEntity::createDynamicComponent` reads `*a2` for the
    type and `a2[2]` for the Python object);
  * the type's name is a std::string at +8, with the SSO capacity at +32:
    above 15 the characters live behind the pointer at +8, below that they
    are inline.

The result is entities first (`GeneralSpaceData` 0, `Account` 1, ... `SPGZone`
52) and then the dynamic components in `scripts/components.xml` order
(`OwnVehicle` 53, `InAoEZone` 54, `AvatarVehiclesInfo` 126).

Usage:
    python3 tools/dump_entitytypes.py [pid]

With no pid it picks the first WorldOfTanks.exe it finds. The game runs under
Proton, so the addresses are the Windows VAs from IDA; Wine maps the image at
its preferred base, which is why they can be used directly. If the module is
relocated the script says so rather than printing nonsense.

Reading /proc/<pid>/mem needs ptrace permission, so this wants sudo — or run
the same walk from inside the client through `pyconsole`, which needs no
privileges at all (see docs/PRIVATE_SERVER.md).
"""

import os
import struct
import sys

# From IDA, image base 0x140000000.
VECTOR_VA = 0x144B5E160  # begin; end is the next pointer
IMAGE_BASE = 0x140000000


def find_pid():
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm") as f:
                comm = f.read().strip()
        except OSError:
            continue
        if "WorldOfTanks" in comm:
            return int(entry)
    return None


def module_base(pid, name="WorldOfTanks.exe"):
    """The load address of the main image, from /proc/<pid>/maps."""
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                # maxsplit: the path contains spaces ("World of Tanks"), so a
                # plain split would truncate it.
                parts = line.split(maxsplit=5)
                if len(parts) < 6:
                    continue
                path = parts[5].strip()
                if path.endswith(name) and parts[2] == "00000000":
                    return int(parts[0].split("-")[0], 16)
    except OSError:
        pass
    return None


def read(pid, addr, n):
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        mem.seek(addr)
        return mem.read(n)


def read_u64(pid, addr):
    return struct.unpack("<Q", read(pid, addr, 8))[0]


def read_name(pid, type_ptr):
    """The EntityType's name: a std::string at +8, capacity at +32."""
    raw = read(pid, type_ptr + 8, 32)
    capacity = struct.unpack("<Q", raw[24:32])[0]
    if capacity > 15:
        ptr = struct.unpack("<Q", raw[0:8])[0]
        if ptr <= 0 or ptr > 0x7FFFFFFFFFFF:
            return "<bad name ptr>"
        data = read(pid, ptr, min(capacity, 256))
    else:
        data = raw[:16]
    return data.split(b"\x00")[0].decode("utf-8", "replace")


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
    if pid is None:
        sys.exit("no WorldOfTanks.exe process found")

    base = module_base(pid)
    if base is None:
        sys.exit(f"pid {pid}: no WorldOfTanks.exe mapping")

    # Wine maps the image at its preferred base; anything else means the VAs
    # from IDA do not apply and the dump would be garbage.
    if base != IMAGE_BASE:
        print(f"warning: image at {base:#x}, IDA assumed {IMAGE_BASE:#x}", file=sys.stderr)
    delta = base - IMAGE_BASE

    begin, end = struct.unpack("<QQ", read(pid, VECTOR_VA + delta, 16))
    if not begin or not end or end <= begin:
        sys.exit("empty EntityType vector — is the client past the loading screen?")
    count = (end - begin) // 8
    print(f"pid {pid}, image {base:#x}, {count} entity types")

    ptrs = struct.unpack(f"<{count}Q", read(pid, begin, count * 8))
    for i, record in enumerate(ptrs):
        if not record:
            print(f"{i:4d} <null>")
            continue
        type_ptr = read_u64(pid, record)
        if not type_ptr:
            print(f"{i:4d} <no type>")
            continue
        print(f"{i:4d} {read_name(pid, type_ptr)}")


if __name__ == "__main__":
    main()
