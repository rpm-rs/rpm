Name:           rpm-scriptlets
Version:        1.0
Release:        1
Summary:        Test RPM scriptlets and triggers
License:        MIT
BuildArch:      noarch

%description
A package for exercising RPM scriptlets, triggers, and file triggers.

%install
mkdir -p %{buildroot}/opt/%{name}
echo "scriptlet-test" > %{buildroot}/opt/%{name}/data

# Pre/post install and uninstall
%pre
echo "pre-install"

# Explicit interpreter
%post -p /bin/sh
echo "post-install"

%preun
echo "pre-uninstall"

%postun
echo "post-uninstall"

# Transaction-level scriptlets
%pretrans
echo "pre-transaction"

%posttrans
echo "post-transaction"

# Verify scriptlet
%verifyscript
echo "verify"

# Triggers (against a hypothetical target package)
%triggerprein -- bash
echo "trigger-pre-install on bash"

%triggerin -- bash
echo "trigger-install on bash"

%triggerun -- bash
echo "trigger-uninstall on bash"

%triggerpostun -- bash
echo "trigger-post-uninstall on bash"

# File triggers
%filetriggerin -- /usr/lib
echo "file-trigger-install in /usr/lib"

%filetriggerun -- /usr/lib
echo "file-trigger-uninstall in /usr/lib"

%filetriggerpostun -- /usr/lib
echo "file-trigger-post-uninstall in /usr/lib"

# Transaction-level file triggers
%transfiletriggerin -- /usr/bin
echo "trans-file-trigger-install in /usr/bin"

%transfiletriggerun -- /usr/bin
echo "trans-file-trigger-uninstall in /usr/bin"

%transfiletriggerpostun -- /usr/bin
echo "trans-file-trigger-post-uninstall in /usr/bin"

%files
/opt/%{name}/data

%changelog
