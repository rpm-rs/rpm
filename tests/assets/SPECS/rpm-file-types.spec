Name:           rpm-file-types
Version:        1.0
Release:        1
Epoch:          0
Summary:        Test RPM handling of various file content types and paths
License:        MIT
BuildArch:      noarch

Source0:        empty_file
Source1:        rpm-rs-logo.png
Source2:        file with spaces & special (chars).txt

%description
A package for exercising RPM handling of different file content types
and unusual file paths.

%install
mkdir -p %{buildroot}/opt/%{name}
cp %{SOURCE0} %{buildroot}/opt/%{name}/empty_file
cp %{SOURCE1} %{buildroot}/opt/%{name}/rpm-rs-logo.png
cp "%{SOURCE2}" "%{buildroot}/opt/%{name}/file with spaces & special (chars).txt"

%files
/opt/%{name}/empty_file
/opt/%{name}/rpm-rs-logo.png
"/opt/%{name}/file with spaces & special (chars).txt"

%changelog
