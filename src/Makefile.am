pluginsdir = $(WIRESHARK_PLUGINS_DIR)
plugins_LTLIBRARIES=rhcs.la

INCLUDES = $(WIRESHARK_CFLAGS)
LDADDS   = $(WIRESHARK_LIBS)

rhcs_la_LDFLAGS = -rpath $(pluginsdir) -avoid-version -module
rhcs_la_SOURCES = \
	packet-corosync-totemnet.c		\
	packet-corosync-totemsrp.c		\
	packet-corosync-totemsrp.h		\
	packet-corosync-totempg.c		\
	packet-corosync-totempg.h		\
	\
	packet-openais-a.c			\
	packet-openais-a.h			\
	packet-openais-clm.c			\
	packet-openais-cman.c			\
	packet-openais-cpg.c			\
	packet-openais-evt.c			\
	packet-openais-flowcontrol.c		\
	packet-openais-sync.c			\
	\
	packet-groupd.c				\
	packet-rgmanager.c			\
	packet-clumond.c			\
	packet-clvmd.c                          \
	\
	plugin.c                                \
	\
	$(NULL)
rhcs_la_LIBADD = $(LDADDS)

# See https://bugzilla.redhat.com/show_bug.cgi?id=662969
EXTRA_DIST = \
	packet-ccsd.c       \
	packet-rhcs4-cman.c \
	\
	$(NULL)
