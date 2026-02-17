"""Build a simple RPM package from scratch."""

import sys

from rpm_rs import FileOptions, PackageBuilder

output = sys.argv[1] if len(sys.argv) > 1 else "example.rpm"

builder = PackageBuilder(
    "example-package",
    "1.0.0",
    "MIT",
    "noarch",
    "An example RPM built with rpm-rs",
)
builder.epoch(0)
builder.release("1.el9")
builder.description("This is a demonstration package built using the rpm-rs library.")
builder.url("https://github.com/rpm-rs/rpm")
builder.vendor("rpm-rs")

builder.requires("bash")
builder.requires("glibc", "2.17")
builder.provides("example-package", "1.0.0-1.el9")

builder.pre_install_script("echo 'Installing example-package...'")
builder.post_install_script("echo 'Installation complete.'")

builder.with_file_contents(
    b"#!/bin/bash\necho 'Hello from example-package!'\n",
    FileOptions.new("/usr/bin/example-hello", permissions=0o755),
)
builder.with_file_contents(
    b"# Example configuration\nkey = value\n",
    FileOptions.new("/etc/example-package.conf", config=True, permissions=0o644),
)

pkg = builder.build()
pkg.write_file(output)
print(f"Built: {output}")
