Name:           rpm-feature-coverage
Epoch:          1
Version:        2.3.4
Release:        5.el8
License:        MPLv2
Summary:        A package for exercising many different features of RPM

Group:          Development/Tools
Url:            http://bobloblaw.com
Packager:       Michael Bluth
Vendor:         Bluth Company
Vcs:            https://github.com/rpm-rs/rpm

Requires: fur <= 2
Requires: arson >= 1.0.0-1
Requires(pre): /usr/sbin/useradd
Requires: staircar <= 99.1-3
Requires: /usr/bin/bash

Provides: laughter = 33
Provides: narration(ronhoward)
Provides: /usr/bin/ls

Obsoletes: cornballer < 444
Obsoletes: bluemangroup < 32.1-0

Conflicts: foxnetwork > 5555

Recommends: yacht > 9:11.0-0
Recommends: GeneParmesan(PI)
Recommends: ((hiding and attic) if light-treason)

Suggests: (job or money > 9000)
Suggests: (dove and return)
Suggests: (bobloblaw >= 1.1 if maritimelaw else anyone < 0.5.1-2)

Supplements: comedy = 0:11.1-4
Supplements: ((hiding and illusion) unless alliance-of-magicians)

Enhances: (bananas or magic)

%description
This package attempts to exercise many different features of RPM packages.

%build
echo "Now the story of a wealthy man who lost everything, and the one son who had no choice but to keep them all together." > README
echo OK

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc/complex/
mkdir -p $RPM_BUILD_ROOT/usr/bin/
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}/
mkdir -p $RPM_BUILD_ROOT/var/lib/complex/
mkdir -p $RPM_BUILD_ROOT/var/log/complex/
touch $RPM_BUILD_ROOT/usr/bin/complex_a
touch $RPM_BUILD_ROOT/etc/complex/pkg.cfg

%clean
rm -rf $RPM_BUILD_ROOT

%files
/etc/complex/pkg.cfg
/usr/bin/complex_a
%dir /var/lib/complex/
%ghost /var/log/complex.log
%doc README

%changelog
* Mon Jun 14 2021 George Bluth <george@federalprison.gov> - 3.3.3-3
- There’s always money in the banana stand

* Sun Apr 25 2021 Job Bluth <job@alliance-of-magicians.com> - 2.2.2-2
- I've made a huge mistake

* Wed Mar 31 2021 Lucille Bluth <lucille@bluthcompany.com> - 1.1.1-1
- It's a banana, Michael. How much could it cost, $10?
