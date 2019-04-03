/*
* virmktme.c: interaction with processes
*
* Copyright (C) 2010-2015 Red Hat, Inc.
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library.  If not, see
* <http://www.gnu.org/licenses/>.
*
*/
#ifdef __linux__
#include <config.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <asm/unistd.h>
#include <linux/keyctl.h>
#endif
#include "virerror.h"
#include "virlog.h"
#include "viraudit.h"
#include "virfile.h"
#include "viralloc.h"
#include "virutil.h"
#include "virstring.h"
#include "virmktme.h"

VIR_LOG_INIT("util.mktme");
// Libvirt thread specific dest keyring
#define VIR_FROM_THIS VIR_FROM_NONE

/**
* virGetMktmeKey:
* @id: mktme id-string
* @type :  mktme key type
* @key :  user key value
* @encyption_algorithm : encryption algorithm
*
* returns mktme key-handle , this handle is used to encrypt the memory
* return -1 in case of failue
*/

#ifdef __linux__
#define GET_MKTME_DEST_RING()						\
{									\
    destringid = syscall(__NR_request_key,"keyring",			\
	   LIBVIRT_MKTME_KEY_RING_NAME, KEY_SPEC_PROCESS_KEYRING);	\
}
#else
#define GET_MKTME_DEST_RING()
#endif

int
virGetMktmeKeyHandle(const char* id,
	const char* type,
	const char* key,
	const char *algorithm)
{
    char *callout = NULL;
    int destringid = -1;

    int ret = -1;

    if (!id || !type || !algorithm )
       return -1;

    GET_MKTME_DEST_RING();
    if(destringid < 0)
        return -1;

    if (key) {
        if (virAsprintf(&callout, "type=%s algorithm=%s key=%s",
		        type, algorithm, key) < 0)
	    return -1;
	}
	else {
	    if (virAsprintf(&callout, "type=%s algorithm=%s", type, algorithm) < 0)
		return -1;
	}

#ifdef __linux__
    ret = syscall(__NR_request_key,"mktme", id, callout, destringid);
    VIR_FREE(callout);
#endif
    return ret;
}

/**
* virMktmeIsEnabled:
*
* Returns MKTME initialization status
*/
int
virMktmeIsEnabled(void)
{
    int destringid = -1;
    GET_MKTME_DEST_RING();
    if(destringid < 0)
       return 0;

    return 1;
}
