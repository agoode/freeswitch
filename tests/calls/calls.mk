if HAVE_LIBRE

check_PROGRAMS += tests/calls/invite_simple

tests_calls_invite_simple_SOURCES = tests/calls/invite_simple.c
tests_calls_invite_simple_CFLAGS = $(SWITCH_AM_CFLAGS) $(TAP_CFLAGS) $(libre_CFLAGS)
tests_calls_invite_simple_LDADD = $(FSTESTLD)
EXTRA_tests_calls_invite_simple_DEPENDENCIES = tests/calls/fs_run/freeswitch.pid
tests_calls_invite_simple_LDFLAGS = $(SWITCH_AM_LDFLAGS) $(TAP_LIBS) $(libre_LIBS)

check_PROGRAMS += tests/calls/invite_invalid_headers

tests_calls_invite_invalid_headers_SOURCES = tests/calls/invite_invalid_headers.c
tests_calls_invite_invalid_headers_CFLAGS = $(SWITCH_AM_CFLAGS) $(TAP_CFLAGS) $(libre_CFLAGS)
tests_calls_invite_invalid_headers_LDADD = $(FSTESTLD)
EXTRA_tests_calls_invite_invalid_headers_DEPENDENCIES = tests/calls/fs_run/freeswitch.pid
tests_calls_invite_invalid_headers_LDFLAGS = $(SWITCH_AM_LDFLAGS) $(TAP_LIBS) $(libre_LIBS)

check_PROGRAMS += tests/calls/invite_invalid_sdp

tests_calls_invite_invalid_sdp_SOURCES = tests/calls/invite_invalid_sdp.c
tests_calls_invite_invalid_sdp_CFLAGS = $(SWITCH_AM_CFLAGS) $(TAP_CFLAGS) $(libre_CFLAGS)
tests_calls_invite_invalid_sdp_LDADD = $(FSTESTLD)
EXTRA_tests_calls_invite_invalid_sdp_DEPENDENCIES = tests/calls/fs_run/freeswitch.pid
tests_calls_invite_invalid_sdp_LDFLAGS = $(SWITCH_AM_LDFLAGS) $(TAP_LIBS) $(libre_LIBS)

check_PROGRAMS += tests/calls/invite_invalid_ext

tests_calls_invite_invalid_ext_SOURCES = tests/calls/invite_invalid_ext.c
tests_calls_invite_invalid_ext_CFLAGS = $(SWITCH_AM_CFLAGS) $(TAP_CFLAGS) $(libre_CFLAGS)
tests_calls_invite_invalid_ext_LDADD = $(FSTESTLD)
EXTRA_tests_calls_invite_invalid_ext_DEPENDENCIES = tests/calls/fs_run/freeswitch.pid
tests_calls_invite_invalid_ext_LDFLAGS = $(SWITCH_AM_LDFLAGS) $(TAP_LIBS) $(libre_LIBS)


if HAVE_BARESIP

check_PROGRAMS += tests/calls/ua_register

tests_calls_ua_register_SOURCES = tests/calls/ua_register.c
tests_calls_ua_register_CFLAGS = $(SWITCH_AM_CFLAGS) $(TAP_CFLAGS) $(libre_CFLAGS) $(libbaresip_CFLAGS)
tests_calls_ua_register_LDADD = $(FSTESTLD)
EXTRA_tests_calls_ua_register_DEPENDENCIES = tests/calls/fs_run/freeswitch.pid
tests_calls_ua_register_LDFLAGS = $(SWITCH_AM_LDFLAGS) $(TAP_LIBS) $(libre_LIBS) $(libbaresip_LIBS)

endif # HAVE_BARESIP

endif # HAVE_LIBRE

tests/calls/fs_run/freeswitch.pid:
	./.libs/freeswitch -cfgname freeswitch.xml -conf ./conf/testing/ -db ./tests/calls/fs_run/ -log ./tests/calls/fs_run/ -run ./tests/calls/fs_run/ -ncwait -nonat

clean-local-calls:
	kill -9 `cat tests/calls/fs_run/freeswitch.pid`
	rm -Rf ./tests/calls/fs_run/


