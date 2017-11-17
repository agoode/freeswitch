include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_baresip

if HAVE_LIBRE

mod_LTLIBRARIES = mod_baresip.la
mod_baresip_la_SOURCES  = mod_baresip.c baresip_profile.c baresip_config.c
mod_baresip_la_CFLAGS   = $(AM_CFLAGS) $(LIBRE_CFLAGS)
mod_baresip_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_baresip_la_LDFLAGS  = -avoid-version -module -no-undefined -shared $(LIBRE_LIBS) $(SWITCH_AM_LDFLAGS)

else

install: error
error:
	$(error You must install libre-dev to build this module)
endif
