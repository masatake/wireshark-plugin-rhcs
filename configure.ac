m4_define([pkg_name],    [wireshark-plugin-rhcs])
m4_define([pkg_verison], [0.0.0])


AC_INIT(pkg_name, pkg_verison)
AC_CONFIG_AUX_DIR(misc/ac-aux)
AM_INIT_AUTOMAKE([no-dist-gzip dist-bzip2])
AC_CONFIG_MACRO_DIR([misc/m4])

AC_PROG_CC
AC_PROG_CC_STDC

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AM_PATH_WIRESHARK
WIRESHARK_PLUGINS_DIR=`pkg-config --variable=libdir wireshark`/wireshark/plugins/$WIRESHARK_VERSION
AC_SUBST(WIRESHARK_PLUGINS_DIR)

MY_CFLAGS="$CFLAGS"
MY_LIBS="$LIBS"
CFLAGS="$CFLAGS $WIRESHARK_CFLAGS"
LIBS="$LIBS $WIRESHARK_LIBS"
AC_CHECK_MEMBERS(
[fragment_items.hf_fragment_count, 
 fragment_items.hf_reassembled_length],[],[],
[[#include <glib.h>
  #include <epan/packet.h>
  #include <epan/reassemble.h>]])
AC_CHECK_FUNCS([tvb_format_stringzpad])
AC_CHECK_FUNCS([sha1_hmac])
CFLAGS="${MY_CFLAGS}"
LIBS="${MY_LIBS}"

AC_OUTPUT([
	   Makefile
           misc/Makefile 
           misc/ac-aux/Makefile 
	   misc/m4/Makefile
	   misc/makefiles/Makefile
	   misc/specs/Makefile
	   misc/specs/wireshark-plugin-rhcs.spec
	   src/Makefile
	  ])
