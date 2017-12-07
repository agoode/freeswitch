include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_aes_ctr_wav

if HAVE_OPENSSL

mod_LTLIBRARIES = mod_aes_ctr_wav.la
mod_aes_ctr_wav_la_SOURCES  = mod_aes_ctr_wav.c
mod_aes_ctr_wav_la_CFLAGS   = $(AM_CFLAGS) $(AES_CTR_WAV_CFLAGS)
mod_aes_ctr_wav_la_LIBADD   = $(switch_builddir)/libfreeswitch.la $(AES_CTR_WAV_LIBS)
mod_aes_ctr_wav_la_LDFLAGS  = -avoid-version -module -no-undefined -shared

else
install: error
all: error
error:
	$(error You must install libssl-dev to build mod_aes_ctr_wav)
endif
