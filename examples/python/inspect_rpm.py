"""Inspect an RPM package and print a detailed summary."""

import sys

from rpm_rs import PackageMetadata

if len(sys.argv) < 2:
    print("Usage: inspect_rpm.py <rpm-file>", file=sys.stderr)
    sys.exit(1)

meta = PackageMetadata.open(sys.argv[1])
nevra = meta.nevra()

print(f"Name         : {nevra.name}")
print(f"Epoch        : {nevra.epoch}")
print(f"Version      : {nevra.version}")
print(f"Release      : {nevra.release}")
print(f"Architecture : {nevra.arch}")
print(f"Summary      : {meta.summary}")
print(f"Description  : {meta.description}")
print(f"License      : {meta.license}")

for attr in ("url", "vendor", "packager", "build_host", "build_time", "source_rpm"):
    try:
        print(f"{attr.replace('_', ' ').title():13s}: {getattr(meta, attr)}")
    except RuntimeError:
        pass

print(f"Size         : {meta.installed_size}")

for label, method in [
    ("Provides", "provides"),
    ("Requires", "requires"),
    ("Conflicts", "conflicts"),
    ("Obsoletes", "obsoletes"),
    ("Recommends", "recommends"),
    ("Suggests", "suggests"),
]:
    try:
        deps = getattr(meta, method)()
        if deps:
            print(f"{label}:")
            for dep in deps:
                print(f"  {dep}")
    except RuntimeError:
        pass

entries = meta.file_entries()
if entries:
    print(f"Files ({len(entries)}):")
    for entry in entries:
        print(f"  {entry.path}")
