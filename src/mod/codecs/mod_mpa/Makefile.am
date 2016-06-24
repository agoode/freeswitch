include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_mpa

if HAVE_MPG123
if HAVE_TWOLAME

mod_LTLIBRARIES = mod_mpa.la
mod_mpa_la_SOURCES  = mod_mpa.c
mod_mpa_la_CFLAGS   = $(AM_CFLAGS)
mod_mpa_la_CPPFLAGS = $(AM_CPPFLAGS) $(TWOLAME_CFLAGS) $(MPG123_CFLAGS)
mod_mpa_la_LIBADD   = $(switch_builddir)/libfreeswitch.la -ltwolame -lmpg123
mod_mpa_la_LDFLAGS  = -avoid-version -module -no-undefined -shared $(TWOLAME_LIBS) $(MPG123_LIBS)

else
install: error
all: error
error:
       $(error You must install libtwolame-dev to build mod_mpa)
endif

else
install: error
all: error
error:
	$(error You must install libmpg123-dev to build mod_mpa)
endif


