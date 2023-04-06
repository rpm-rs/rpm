#!/bin/sh

for spec in SPECS/*.spec; do
    rpmbuild --define "_topdir `pwd`" --define "_binary_payload w.ufdio" --define "_source_payload w.ufdio" -ba $spec
done

rm -r ./BUILDROOT/
rm -r ./BUILD/
