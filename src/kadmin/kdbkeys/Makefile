#
# $Id$ 
#

TOP = ../..
include $(TOP)/config.mk/template

PROG := kdbkeys
OBJS := kdbkeys.o
SRCS := kdbkeys.c

LIBS = $(LIBADMSRV) $(LIBDB) $(LIBCOM_ERR) $(LIBRPCLIB) $(LIBDYN) \
    $(LIBKDB5) $(LIBKRB5) $(LIBCRYPTO) $(NDBMLIB) $(BSDLIB) $(NETLIB)

expand Program

# Need $(STOP_SERVERS_LOCAL) because any running servers need to be
# killed so that they won't keep the database open so that we can't
# blow it away.
# 
# Need $(FIX_CONF_FILES) so that /etc/krb.conf has the correct realm
# in it so that kdb5_edit will be in the right realm.

unit-test:: unit-test-setup unit-test-body unit-test-cleanup

unit-test-setup::
	$(STOP_SERVERS_LOCAL)
	$(SAVE_FILES)
	$(FIX_CONF_FILES)

unit-test-body::
	$(PERL) ./do-test.pl 25

unit-test-cleanup::
	$(RESTORE_FILES)
