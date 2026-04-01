Name:           rpm-file-attrs
Version:        1.0
Release:        1
Summary:        Test RPM file attributes
License:        MIT
BuildArch:	    noarch

%description
%{summary}

%install
mkdir -p %{buildroot}/opt/%{name}

echo "normal" > %{buildroot}/opt/%{name}/normal
mkdir -p %{buildroot}/opt/%{name}/dir/
echo "file-in-a-dir" > %{buildroot}/opt/%{name}/dir/normal

# symlinks to a file and directory
mkdir -p %{buildroot}/opt/%{name}/symlink_dir
ln -sr %{buildroot}/opt/%{name}/normal %{buildroot}/opt/%{name}/symlink
ln -sr %{buildroot}/opt/%{name}/dir %{buildroot}/opt/%{name}/symlink_dir

# for virtual attributes testing
echo "artifact" > %{buildroot}/opt/%{name}/artifact
echo "config" > %{buildroot}/opt/%{name}/config
echo "config_noreplace" > %{buildroot}/opt/%{name}/config_noreplace
echo "doc" > %{buildroot}/opt/%{name}/doc
echo "license" > %{buildroot}/opt/%{name}/license
echo "missingok" > %{buildroot}/opt/%{name}/missingok
echo "readme" > %{buildroot}/opt/%{name}/readme

# for owner / groups testing
echo "example-binary" > %{buildroot}/opt/%{name}/example-binary
echo "example-confidential-file" > %{buildroot}/opt/%{name}/example-confidential-file
echo "different-owner-and-group" > %{buildroot}/opt/%{name}/different-owner-and-group

# for file capabilities testing
echo "empty_caps" > %{buildroot}/opt/%{name}/empty_caps
echo "empty_caps2" > %{buildroot}/opt/%{name}/empty_caps2
echo "with_caps" > %{buildroot}/opt/%{name}/with_caps

# for verify flags testing
echo "verify_some" > %{buildroot}/opt/%{name}/verify_some
echo "verify_not" > %{buildroot}/opt/%{name}/verify_not
echo "verify_all" > %{buildroot}/opt/%{name}/verify_all
echo "verify_none" > %{buildroot}/opt/%{name}/verify_none

%files
/opt/%{name}/normal
/opt/%{name}/dir/
/opt/%{name}/symlink
/opt/%{name}/symlink_dir/

# virtual attributes
%dir /opt/%{name}
%artifact /opt/%{name}/artifact
%config /opt/%{name}/config
%config(noreplace) /opt/%{name}/config_noreplace
%doc /opt/%{name}/doc
%ghost /opt/%{name}/ghost
%license /opt/%{name}/license
%missingok /opt/%{name}/missingok
%readme /opt/%{name}/readme

# owner, group and permissions
%attr(644,root,root) /opt/%{name}/example-binary
%attr(600,jane,jane) /opt/%{name}/example-confidential-file
%attr(655,jane,bob) /opt/%{name}/different-owner-and-group

# capabilities + permissions
%attr(0655,root,root) %caps(=) /opt/%{name}/empty_caps
%attr(0655,root,root) %caps()  /opt/%{name}/empty_caps2
%attr(0655,root,root) %caps(cap_sys_admin,cap_sys_ptrace=pe) /opt/%{name}/with_caps

# verify flags
%verify(md5 size mtime) /opt/%{name}/verify_some
%verify(not md5 size) /opt/%{name}/verify_not
%verify(md5 size mode mtime rdev user group link) /opt/%{name}/verify_all
%verify(not md5 size mode mtime rdev user group link) /opt/%{name}/verify_none
