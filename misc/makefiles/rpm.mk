.PHONY: rpm
rpm: dist
	$(mkinstalldirs) build/{SPECS,RPMS,BUILD,BUILDROOT,SRPMS}
	rpmbuild --define "_topdir `pwd`/build" -ta $(DIST_ARCHIVES)

clean-local::
	/bin/rm -rf build
