#
# $Id$
#

TOP = ../..
include $(TOP)/config.mk/template

unit-test:: unit-test-setup unit-test-body unit-test-cleanup

unit-test-setup::
	$(START_SERVERS_LOCAL) -v4files -kdcport 750 -keysalt des-cbc-crc:v4
	$(LOCAL_MAKE_KEYTAB) -princ changepw/kerberos /krb5/ovsec_adm.srvtab

unit-test-body::
	$(RUNTEST) V4SERVER=../ovsec_v4adm_server --tool v4server \
		KDB5_EDIT=../../../admin/edit/kdb5_edit

unit-test-cleanup::
	$(STOP_SERVERS_LOCAL) -v4files
