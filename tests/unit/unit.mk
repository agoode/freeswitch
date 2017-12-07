if HAVE_TAP

check_PROGRAMS += tests/unit/switch_event

tests_unit_switch_event_SOURCES = tests/unit/switch_event.c
tests_unit_switch_event_CFLAGS = $(SWITCH_AM_CFLAGS) $(TAP_CFLAGS)
tests_unit_switch_event_LDADD = $(FSTESTLD)
tests_unit_switch_event_LDFLAGS = $(SWITCH_AM_LDFLAGS) $(TAP_LIBS)

check_PROGRAMS += tests/unit/switch_hash

tests_unit_switch_hash_SOURCES = tests/unit/switch_hash.c
tests_unit_switch_hash_CFLAGS = $(SWITCH_AM_CFLAGS) $(TAP_CFLAGS)
tests_unit_switch_hash_LDADD = $(FSTESTLD)
tests_unit_switch_hash_LDFLAGS = $(SWITCH_AM_LDFLAGS) $(TAP_LIBS)

endif # HAVE_TAP
