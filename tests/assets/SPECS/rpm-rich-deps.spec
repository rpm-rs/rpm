Name:           rpm-rich-deps
Version:        1.0
Release:        1
Summary:        Test RPM rich (boolean) dependencies
License:        MIT
BuildArch:      noarch

# Boolean operators
Requires: (pkgA or pkgB)
Requires: (pkgC and pkgD)
Requires: (pkgE if pkgF)
Requires: (pkgG if pkgH else pkgI)
Supplements: (pkgJ unless pkgK)
Conflicts: (pkgL unless pkgM else pkgN)
Requires: (pkgO with pkgP)
Requires: (pkgQ without pkgR)

# Nested boolean expressions
Requires: ((pkgS or pkgT) and pkgU)
Requires: (pkgV or (pkgW and pkgX))
Recommends: ((pkgY and pkgZ) or pkgAA)

# Boolean deps with version constraints
Requires: (pkgBB >= 2.0 or pkgCC >= 3.0)
Requires: (pkgDD >= 1.0 and pkgEE < 5.0)
Requires: (pkgFF >= 2.0 if pkgGG >= 1.0)

# Rich deps in other dependency types
Recommends: (pkgHH or pkgII)
Suggests: (pkgJJ if pkgKK)
Supplements: (pkgLL and pkgMM)
Enhances: (pkgNN or pkgOO)
Conflicts: (pkgPP and pkgQQ)

%description
A package for exercising RPM rich (boolean) dependency syntax,
including all boolean operators and nesting.

%install
mkdir -p %{buildroot}/opt/%{name}
echo "rich-deps-test" > %{buildroot}/opt/%{name}/data

%files
/opt/%{name}/data

%changelog
