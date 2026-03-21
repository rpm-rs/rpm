Name:           rpm-hardlinks
Version:        1.0
Release:        1
Summary:        Test RPM hard link handling
License:        MIT
BuildArch:      noarch

%description
A package for exercising RPM hard link handling in the payload.
Contains sets of hard-linked files to test inode deduplication
and the RPMTAG_FILEINODES / RPMTAG_FILENLINKS tags.

%install
mkdir -p %{buildroot}/opt/%{name}

# First set of hard links (3 links to same content)
echo "shared-content-alpha" > %{buildroot}/opt/%{name}/alpha-1
ln %{buildroot}/opt/%{name}/alpha-1 %{buildroot}/opt/%{name}/alpha-2
ln %{buildroot}/opt/%{name}/alpha-1 %{buildroot}/opt/%{name}/alpha-3

# Second set of hard links (2 links to same content)
echo "shared-content-beta" > %{buildroot}/opt/%{name}/beta-1
ln %{buildroot}/opt/%{name}/beta-1 %{buildroot}/opt/%{name}/beta-2

# A regular (non-linked) file for comparison
echo "standalone" > %{buildroot}/opt/%{name}/standalone

%files
/opt/%{name}/alpha-1
/opt/%{name}/alpha-2
/opt/%{name}/alpha-3
/opt/%{name}/beta-1
/opt/%{name}/beta-2
/opt/%{name}/standalone

%changelog
