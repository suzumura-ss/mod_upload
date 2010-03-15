mod_upload.la: mod_upload.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_upload.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_upload.la
