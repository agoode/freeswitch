include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_usrloc

mod_LTLIBRARIES = mod_usrloc.la
mod_usrloc_la_SOURCES  = mod_usrloc.c
mod_usrloc_la_CFLAGS   = $(AM_CFLAGS)
mod_usrloc_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_usrloc_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
