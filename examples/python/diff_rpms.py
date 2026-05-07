"""Compare the headers of two RPM packages and report differences."""

import argparse

from rpm_rs import PackageMetadata, SignatureTag, Tag


def tag_name(tag_id, enum_cls):
    try:
        return f"{enum_cls(tag_id).name} [{tag_id}]"
    except ValueError:
        return str(tag_id)


def format_value(val):
    if isinstance(val, str):
        return repr(val)
    if isinstance(val, bytes):
        if len(val) <= 16:
            return val.hex(" ")
        return f"[{len(val)} bytes]"
    if isinstance(val, list):
        if len(val) == 1:
            return repr(val[0])
        if len(val) <= 8:
            return repr(val)
        item_type = type(val[0]).__name__ if val else "?"
        return f"[{len(val)} {item_type}s]"
    return repr(val)


def diff_headers(label, a_entries, b_entries, enum_cls):
    all_tags = sorted(set(a_entries) | set(b_entries))

    lines = []
    count = 0
    for tag in all_tags:
        a_val = a_entries.get(tag)
        b_val = b_entries.get(tag)
        name = tag_name(tag, enum_cls)

        if a_val is not None and b_val is None:
            lines.append(f"  - {name} (only in first)")
            count += 1
        elif a_val is None and b_val is not None:
            lines.append(f"  + {name} (only in second)")
            count += 1
        elif a_val != b_val:
            lines.append(f"  ~ {name}:")
            lines.append(f"    < {format_value(a_val)}")
            lines.append(f"    > {format_value(b_val)}")
            count += 1

    if count == 0:
        print(f"\n{label}: identical")
    else:
        print(f"\n{label}:")
        for line in lines:
            print(line)
        print(f"\n  {count} difference(s)")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("rpm_a", help="First RPM file")
parser.add_argument("rpm_b", help="Second RPM file")
args = parser.parse_args()

a = PackageMetadata.open(args.rpm_a)
b = PackageMetadata.open(args.rpm_b)

print("Comparing:")
print(f"  A: {a.nevra()}")
print(f"  B: {b.nevra()}")

diff_headers(
    "Signature header",
    a.signature.get_all_entries(),
    b.signature.get_all_entries(),
    SignatureTag,
)

diff_headers(
    "Main header",
    a.header.get_all_entries(),
    b.header.get_all_entries(),
    Tag,
)
