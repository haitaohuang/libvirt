/*
 * virmktme.c: interaction with mktme key ring services
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
#include "virrandom.h"
#include "virmktme.h"

VIR_LOG_INIT("util.mktme");

#define VIR_FROM_THIS VIR_FROM_NONE

#define MKTME_AES_XTS_SIZE 16

#ifdef __linux__
#define GET_MKTME_DEST_RING() \
        { \
            destringid = syscall(__NR_request_key, \
                                 "keyring", \
                                 LIBVIRT_MKTME_KEY_RING_NAME, \
                                 KEY_SPEC_PROCESS_KEYRING); \
        }
#else
#define GET_MKTME_DEST_RING()
#endif

/**
 * virGetMktmeKey:
 * @id: mktme id-string
 * @type: mktme key type
 * @key: user key value
 * @encyption_algorithm: encryption algorithm
 *
 * Request's a key handle, which is required to launch a encrypted guest
 *
 * Returns mktme key handle in case of success, and -1 in case of failure
 */
int
virGetMktmeKeyHandle(const char *id,
                     const char *type,
                     const char *key,
                     const char *algorithm)
{
    char *callout = NULL;
    int destringid = -1;
    unsigned char kern_entropy[MKTME_AES_XTS_SIZE];

    int ret = -1;

    if (!id || !type || !algorithm)
        return -1;

    GET_MKTME_DEST_RING();
    if (destringid < 0)
        return -1;

    if (key) {
        if (sizeof(key) != MKTME_AES_XTS_SIZE) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Invalid MKTME key length"));
            return -1;
        }
        if (virRandomBytes(kern_entropy, MKTME_AES_XTS_SIZE) < 0)
            return -1;
        if (virAsprintf(&callout, "type=%s algorithm=%s key=%s tweak=%s",
                        type, algorithm, key, kern_entropy) < 0)
            return -1;
    } else {
        if (virAsprintf(&callout, "type=%s algorithm=%s", type, algorithm) < 0)
            return -1;
    }

#ifdef __linux__
    ret = syscall(__NR_request_key, "mktme", id, callout, destringid);
    VIR_FREE(callout);
#endif
    return ret;
}

/**
 * virIsMktmeEnabled:
 *
 * Check if mktme key ring exists.
 *
 * Returns 0 in case mktme key ring exists, and -1 in case not present
 */
int
virIsMktmeEnabled(void)
{
    int destringid = -1;
    GET_MKTME_DEST_RING();
    if (destringid < 0)
        return -1;

    return 0;
}
