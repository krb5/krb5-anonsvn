/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 * 
 * $Log$
 * Revision 1.1.2.1  1996/06/20 23:42:06  marc
 * File added to the repository on a branch
 *
# Revision 1.1  1993/11/03  23:53:58  bjaspan
# Initial revision
#
 */

program RPC_TEST_PROG {
	version RPC_TEST_VERS_1 {
		string RPC_TEST_ECHO(string) = 1;
	} = 1;
} = 1000001;
