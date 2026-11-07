# IDAPython: resolve the client's EntityType table for a new build.
#
#   idat -A -S"tools/ida_entitytype_layout.py" WorldOfTanks.exe.i64
#
# or paste into the IDA console. It prints the three things
# `tools/dump_entitytypes.py` hardcodes, so they can be re-derived after a game
# update instead of guessed:
#
#   * the address of the global vector of type records, read out of
#     `BW::EntityType::find` (the function that turns an NRL type id into a
#     type) rather than from a stale comment;
#   * the offset of the `EntityType *` inside each vector element, from
#     `PyEntity::createDynamicComponent`;
#   * the offset of the name `std::string` inside `EntityType`, and where its
#     SSO capacity sits.
#
# The vector is filled at load time from the game's own defs, so its *contents*
# only exist in the running process — this gives the addresses, and
# `dump_entitytypes.py` (or the same walk through pyconsole) reads the contents.

import ida_funcs
import ida_hexrays
import ida_lines
import idautils
import idc


def find_func_by_string(text):
    """The function that references a string, by its text."""
    for s in idautils.Strings():
        if text not in str(s):
            continue
        for x in idautils.XrefsTo(s.ea):
            f = ida_funcs.get_func(x.frm)
            if f is not None:
                return f.start_ea
    return None


def global_operands(func_ea, limit=40):
    """Every `cs:<global>` operand in a function, as (ea, name)."""
    out = []
    ea = func_ea
    end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
    while ea < end and len(out) < limit:
        for i in range(2):
            name = idc.get_operand_type(ea, i)
            if name in (idc.o_mem, idc.o_imm):
                v = idc.get_operand_value(ea, i)
                if v and v > 0x140000000:
                    out.append((ea, v, idc.get_name(v) or ''))
        ea = idc.next_head(ea, end)
    return out


def main():
    print('=== BW::EntityType::find')
    find_ea = find_func_by_string('EntityType::find: No such type index')
    if find_ea is None:
        print('not found — is this the client binary?')
        return
    print('function at %#x' % find_ea)
    for ea, v, name in global_operands(find_ea, 8):
        print('  %#x  %#x  %s' % (ea, v, name))
    print('  the two globals loaded into rax/r8 are the vector begin and end;')
    print('  begin is the lower address, end is begin + 8.')

    print('=== PyEntity::createDynamicComponent')
    cdc_ea = find_func_by_string('PyEntity::createDynamicComponent: %s failed to load')
    if cdc_ea is None:
        print('not found')
        return
    print('function at %#x' % cdc_ea)
    try:
        text = str(ida_hexrays.decompile(cdc_ea))
    except Exception as e:
        print('  decompile failed: %s' % e)
        return
    # The name is read as `*(_QWORD *)(*a2 + 8)` with the SSO capacity at
    # `*a2 + 32`; the property count comes from the type's own accessor.
    for line in text.splitlines():
        if '+ 8)' in line and 'a2' in line:
            print('  name: %s' % line.strip())
        if '+ 32)' in line and 'a2' in line:
            print('  capacity: %s' % line.strip())
        if 'sub_142C93250' in line:
            print('  property count: %s' % line.strip())


main()
