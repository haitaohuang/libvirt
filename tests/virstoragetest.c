/*
 * Copyright (C) 2013-2014 Red Hat, Inc.
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
 * Author: Eric Blake <eblake@redhat.com>
 */

#include <config.h>

#include <stdlib.h>

#include "testutils.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virstoragefile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.storagetest");

#define datadir abs_builddir "/virstoragedata"

/* This test creates the following files, all in datadir:

 * raw: 1024-byte raw file
 * qcow2: qcow2 file with 'raw' as backing
 * wrap: qcow2 file with 'qcow2' as backing
 * qed: qed file with 'raw' as backing
 * sub/link1: symlink to qcow2
 * sub/link2: symlink to wrap
 *
 * Relative names to these files are known at compile time, but absolute
 * and canonical names depend on where the test is run; for convenience,
 * we pre-populate the computation of these names for use during the test.
*/

static char *qemuimg;
static char *absraw;
static char *canonraw;
static char *absqcow2;
static char *canonqcow2;
static char *abswrap;
static char *absqed;
static char *absdir;
static char *abslink2;

static void
testCleanupImages(void)
{
    VIR_FREE(qemuimg);
    VIR_FREE(absraw);
    VIR_FREE(canonraw);
    VIR_FREE(absqcow2);
    VIR_FREE(canonqcow2);
    VIR_FREE(abswrap);
    VIR_FREE(absqed);
    VIR_FREE(absdir);
    VIR_FREE(abslink2);

    if (chdir(abs_builddir) < 0) {
        fprintf(stderr, "unable to return to correct directory, refusing to "
                "clean up %s\n", datadir);
        return;
    }

    virFileDeleteTree(datadir);
}

static int
testPrepImages(void)
{
    int ret = EXIT_FAILURE;
    virCommandPtr cmd = NULL;
    char *buf = NULL;
    bool compat = false;

    qemuimg = virFindFileInPath("kvm-img");
    if (!qemuimg)
        qemuimg = virFindFileInPath("qemu-img");
    if (!qemuimg)
        goto skip;

    /* See if qemu-img supports '-o compat=xxx'.  If so, we force the
     * use of both v2 and v3 files; if not, it is v2 only but the test
     * still works. */
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qcow2",
                               "-o?", "/dev/null", NULL);
    virCommandSetOutputBuffer(cmd, &buf);
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;
    if (strstr(buf, "compat "))
        compat = true;
    VIR_FREE(buf);

    if (virAsprintf(&absraw, "%s/raw", datadir) < 0 ||
        virAsprintf(&absqcow2, "%s/qcow2", datadir) < 0 ||
        virAsprintf(&abswrap, "%s/wrap", datadir) < 0 ||
        virAsprintf(&absqed, "%s/qed", datadir) < 0 ||
        virAsprintf(&absdir, "%s/dir", datadir) < 0 ||
        virAsprintf(&abslink2, "%s/sub/link2", datadir) < 0)
        goto cleanup;

    if (virFileMakePath(datadir "/sub") < 0) {
        fprintf(stderr, "unable to create directory %s\n", datadir "/sub");
        goto cleanup;
    }
    if (virFileMakePath(datadir "/dir") < 0) {
        fprintf(stderr, "unable to create directory %s\n", datadir "/dir");
        goto cleanup;
    }

    if (chdir(datadir) < 0) {
        fprintf(stderr, "unable to test relative backing chains\n");
        goto cleanup;
    }

    if (virAsprintf(&buf, "%1024d", 0) < 0 ||
        virFileWriteStr("raw", buf, 0600) < 0) {
        fprintf(stderr, "unable to create raw file\n");
        goto cleanup;
    }
    if (!(canonraw = canonicalize_file_name(absraw))) {
        virReportOOMError();
        goto cleanup;
    }

    /* Create a qcow2 wrapping relative raw; later on, we modify its
     * metadata to test other configurations */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qcow2", NULL);
    virCommandAddArgFormat(cmd, "-obacking_file=raw,backing_fmt=raw%s",
                           compat ? ",compat=0.10" : "");
    virCommandAddArg(cmd, "qcow2");
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;
    /* Make sure our later uses of 'qemu-img rebase' will work */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "raw", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;
    if (!(canonqcow2 = canonicalize_file_name(absqcow2))) {
        virReportOOMError();
        goto cleanup;
    }

    /* Create a second qcow2 wrapping the first, to be sure that we
     * can correctly avoid insecure probing.  */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qcow2", NULL);
    virCommandAddArgFormat(cmd, "-obacking_file=%s,backing_fmt=qcow2%s",
                           absqcow2, compat ? ",compat=1.1" : "");
    virCommandAddArg(cmd, "wrap");
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;

    /* Create a qed file. */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qed", NULL);
    virCommandAddArgFormat(cmd, "-obacking_file=%s,backing_fmt=raw",
                           absraw);
    virCommandAddArg(cmd, "qed");
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;

#ifdef HAVE_SYMLINK
    /* Create some symlinks in a sub-directory. */
    if (symlink("../qcow2", datadir "/sub/link1") < 0 ||
        symlink("../wrap", datadir "/sub/link2") < 0) {
        fprintf(stderr, "unable to create symlink");
        goto cleanup;
    }
#endif

    ret = 0;
 cleanup:
    VIR_FREE(buf);
    virCommandFree(cmd);
    if (ret)
        testCleanupImages();
    return ret;

 skip:
    fputs("qemu-img is too old; skipping this test\n", stderr);
    ret = EXIT_AM_SKIP;
    goto cleanup;
}

/* Many fields of virStorageFileMetadata have the same content whether
 * we access the file relatively or absolutely; but file names differ
 * depending on how the chain was opened.  For ease of testing, we
 * test both relative and absolute starts, and use a flag to say which
 * of the two variations to compare against.  */
typedef struct _testFileData testFileData;
struct _testFileData
{
    const char *expBackingStore;
    const char *expBackingStoreRaw;
    const char *expDirectoryRel;
    const char *expDirectoryAbs;
    enum virStorageFileFormat expFormat;
    bool expIsFile;
    unsigned long long expCapacity;
    bool expEncrypted;
};

enum {
    EXP_PASS = 0,
    EXP_FAIL = 1,
    EXP_WARN = 2,
    ALLOW_PROBE = 4,
    ABS_START = 8,
};

struct testChainData
{
    const char *start;
    enum virStorageFileFormat format;
    const testFileData *files[4];
    int nfiles;
    unsigned int flags;
};

static int
testStorageChain(const void *args)
{
    const struct testChainData *data = args;
    int ret = -1;
    virStorageFileMetadataPtr meta;
    virStorageFileMetadataPtr elt;
    size_t i = 0;
    char *broken = NULL;
    bool abs = !!(data->flags & ABS_START);

    meta = virStorageFileGetMetadata(data->start, data->format, -1, -1,
                                     (data->flags & ALLOW_PROBE) != 0);
    if (!meta) {
        if (data->flags & EXP_FAIL) {
            virResetLastError();
            ret = 0;
        }
        goto cleanup;
    } else if (data->flags & EXP_FAIL) {
        fprintf(stderr, "call should have failed\n");
        goto cleanup;
    }
    if (data->flags & EXP_WARN) {
        if (!virGetLastError()) {
            fprintf(stderr, "call should have warned\n");
            goto cleanup;
        }
        virResetLastError();
        if (virStorageFileChainGetBroken(meta, &broken) || !broken) {
            fprintf(stderr, "call should identify broken part of chain\n");
            goto cleanup;
        }
    } else {
        if (virGetLastError()) {
            fprintf(stderr, "call should not have warned\n");
            goto cleanup;
        }
        if (virStorageFileChainGetBroken(meta, &broken) || broken) {
            fprintf(stderr, "chain should not be identified as broken\n");
            goto cleanup;
        }
    }

    elt = meta;
    while (elt) {
        char *expect = NULL;
        char *actual = NULL;
        const char *expDirectory;

        if (i == data->nfiles) {
            fprintf(stderr, "probed chain was too long\n");
            goto cleanup;
        }

        expDirectory = abs ? data->files[i]->expDirectoryAbs
            : data->files[i]->expDirectoryRel;
        if (virAsprintf(&expect,
                        "store:%s\nraw:%s\ndirectory:%s\nother:%d %d %lld %d",
                        NULLSTR(data->files[i]->expBackingStore),
                        NULLSTR(data->files[i]->expBackingStoreRaw),
                        NULLSTR(expDirectory),
                        data->files[i]->expFormat,
                        data->files[i]->expIsFile,
                        data->files[i]->expCapacity,
                        data->files[i]->expEncrypted) < 0 ||
            virAsprintf(&actual,
                        "store:%s\nraw:%s\ndirectory:%s\nother:%d %d %lld %d",
                        NULLSTR(elt->backingStore),
                        NULLSTR(elt->backingStoreRaw),
                        NULLSTR(elt->directory),
                        elt->backingStoreFormat, elt->backingStoreIsFile,
                        elt->capacity, !!elt->encryption) < 0) {
            VIR_FREE(expect);
            VIR_FREE(actual);
            goto cleanup;
        }
        if (STRNEQ(expect, actual)) {
            fprintf(stderr, "chain member %zu", i);
            virtTestDifference(stderr, expect, actual);
            VIR_FREE(expect);
            VIR_FREE(actual);
            goto cleanup;
        }
        VIR_FREE(expect);
        VIR_FREE(actual);
        elt = elt->backingMeta;
        i++;
    }
    if (i != data->nfiles) {
        fprintf(stderr, "probed chain was too short\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(broken);
    virStorageFileFreeMetadata(meta);
    return ret;
}

static int
mymain(void)
{
    int ret;
    virCommandPtr cmd = NULL;
    struct testChainData data;

    /* Prep some files with qemu-img; if that is not found on PATH, or
     * if it lacks support for qcow2 and qed, skip this test.  */
    if ((ret = testPrepImages()) != 0)
        return ret;

#define TEST_ONE_CHAIN(id, start, format, flags, ...)                \
    do {                                                             \
        size_t i;                                                    \
        memset(&data, 0, sizeof(data));                              \
        data = (struct testChainData){                               \
            start, format, { __VA_ARGS__ }, 0, flags,                \
        };                                                           \
        for (i = 0; i < ARRAY_CARDINALITY(data.files); i++)          \
            if (data.files[i])                                       \
                data.nfiles++;                                       \
        if (virtTestRun("Storage backing chain " id,                 \
                        testStorageChain, &data) < 0)                \
            ret = -1;                                                \
    } while (0)

#define VIR_FLATTEN_2(...) __VA_ARGS__
#define VIR_FLATTEN_1(_1) VIR_FLATTEN_2 _1

#define TEST_CHAIN(id, relstart, absstart, format, chain1, flags1,   \
                   chain2, flags2, chain3, flags3, chain4, flags4)   \
    do {                                                             \
        TEST_ONE_CHAIN(#id "a", relstart, format, flags1,            \
                       VIR_FLATTEN_1(chain1));                       \
        TEST_ONE_CHAIN(#id "b", relstart, format, flags2,            \
                       VIR_FLATTEN_1(chain2));                       \
        TEST_ONE_CHAIN(#id "c", absstart, format, flags3 | ABS_START,\
                       VIR_FLATTEN_1(chain3));                       \
        TEST_ONE_CHAIN(#id "d", absstart, format, flags4 | ABS_START,\
                       VIR_FLATTEN_1(chain4));                       \
    } while (0)

    /* The actual tests, in several groups. */

    /* Missing file */
    TEST_ONE_CHAIN("0", "bogus", VIR_STORAGE_FILE_RAW, EXP_FAIL);

    /* Raw image, whether with right format or no specified format */
    testFileData raw = {
        .expFormat = VIR_STORAGE_FILE_NONE,
    };
    TEST_CHAIN(1, "raw", absraw, VIR_STORAGE_FILE_RAW,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(2, "raw", absraw, VIR_STORAGE_FILE_AUTO,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS);

    /* Qcow2 file with relative raw backing, format provided */
    testFileData qcow2 = {
        .expBackingStore = canonraw,
        .expBackingStoreRaw = "raw",
        .expDirectoryRel = ".",
        .expDirectoryAbs = datadir,
        .expFormat = VIR_STORAGE_FILE_RAW,
        .expIsFile = true,
        .expCapacity = 1024,
    };
    TEST_CHAIN(3, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(4, "qcow2", absqcow2, VIR_STORAGE_FILE_AUTO,
               (&raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 file to use absolute backing name */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", absraw, "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = absraw;
    qcow2.expDirectoryRel = datadir;

    /* Qcow2 file with raw as absolute backing, backing format provided */
    TEST_CHAIN(5, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(6, "qcow2", absqcow2, VIR_STORAGE_FILE_AUTO,
               (&raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Wrapped file access */
    testFileData wrap = {
        .expBackingStore = canonqcow2,
        .expBackingStoreRaw = absqcow2,
        .expDirectoryRel = datadir,
        .expDirectoryAbs = datadir,
        .expFormat = VIR_STORAGE_FILE_QCOW2,
        .expIsFile = true,
        .expCapacity = 1024,
    };
    TEST_CHAIN(7, "wrap", abswrap, VIR_STORAGE_FILE_QCOW2,
               (&wrap, &qcow2, &raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&wrap, &qcow2, &raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 and wrap file to omit backing file type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-b", absraw, "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-b", absqcow2, "wrap", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    wrap.expFormat = VIR_STORAGE_FILE_AUTO;
    qcow2.expFormat = VIR_STORAGE_FILE_AUTO;

    /* Qcow2 file with raw as absolute backing, backing format omitted */
    testFileData wrap_as_raw = {
        .expBackingStore = canonqcow2,
        .expBackingStoreRaw = absqcow2,
        .expDirectoryRel = datadir,
        .expDirectoryAbs = datadir,
        .expFormat = VIR_STORAGE_FILE_RAW,
        .expIsFile = true,
        .expCapacity = 1024,
    };
    TEST_CHAIN(8, "wrap", abswrap, VIR_STORAGE_FILE_QCOW2,
               (&wrap_as_raw, &raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&wrap_as_raw, &raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 to a missing backing file, with backing type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", datadir "/bogus",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStore = NULL;
    qcow2.expBackingStoreRaw = datadir "/bogus";
    qcow2.expFormat = VIR_STORAGE_FILE_NONE;
    qcow2.expIsFile = false;

    /* Qcow2 file with missing backing file but specified type */
    TEST_CHAIN(9, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to a missing backing file, without backing type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-b", datadir "/bogus", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Qcow2 file with missing backing file and no specified type */
    TEST_CHAIN(10, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to use an nbd: protocol as backend */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "nbd:example.org:6000",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStore = "nbd:example.org:6000";
    qcow2.expBackingStoreRaw = NULL;
    qcow2.expDirectoryRel = NULL;
    qcow2.expDirectoryAbs = NULL;
    qcow2.expFormat = VIR_STORAGE_FILE_RAW;

    /* Qcow2 file with backing protocol instead of file */
    TEST_CHAIN(11, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_PASS,
               (&qcow2), ALLOW_PROBE | EXP_PASS,
               (&qcow2), EXP_PASS,
               (&qcow2), ALLOW_PROBE | EXP_PASS);

    /* qed file */
    testFileData qed = {
        .expBackingStore = canonraw,
        .expBackingStoreRaw = absraw,
        .expDirectoryRel = datadir,
        .expDirectoryAbs = datadir,
        .expFormat = VIR_STORAGE_FILE_RAW,
        .expIsFile = true,
        .expCapacity = 1024,
    };
    TEST_CHAIN(12, "qed", absqed, VIR_STORAGE_FILE_AUTO,
               (&raw), EXP_PASS,
               (&qed, &raw), ALLOW_PROBE | EXP_PASS,
               (&raw), EXP_PASS,
               (&qed, &raw), ALLOW_PROBE | EXP_PASS);

    /* directory */
    testFileData dir = {
        .expIsFile = false,
    };
    TEST_CHAIN(13, "dir", absdir, VIR_STORAGE_FILE_AUTO,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(14, "dir", absdir, VIR_STORAGE_FILE_DIR,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS);

#ifdef HAVE_SYMLINK
    /* Rewrite qcow2 and wrap file to use backing names relative to a
     * symlink from a different directory */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "../raw", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "../sub/link1", "wrap",
                               NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Behavior of symlinks to qcow2 with relative backing files */
    testFileData link1 = {
        .expBackingStore = canonraw,
        .expBackingStoreRaw = "../raw",
        .expDirectoryRel = "sub/../sub/..",
        .expDirectoryAbs = datadir "/sub/../sub/..",
        .expFormat = VIR_STORAGE_FILE_RAW,
        .expIsFile = true,
        .expCapacity = 1024,
    };
    testFileData link2 = {
        .expBackingStore = canonqcow2,
        .expBackingStoreRaw = "../sub/link1",
        .expDirectoryRel = "sub/../sub",
        .expDirectoryAbs = datadir "/sub/../sub",
        .expFormat = VIR_STORAGE_FILE_QCOW2,
        .expIsFile = true,
        .expCapacity = 1024,
    };
    TEST_CHAIN(15, "sub/link2", abslink2, VIR_STORAGE_FILE_QCOW2,
               (&link2, &link1, &raw), EXP_PASS,
               (&link2, &link1, &raw), ALLOW_PROBE | EXP_PASS,
               (&link2, &link1, &raw), EXP_PASS,
               (&link2, &link1, &raw), ALLOW_PROBE | EXP_PASS);
#endif

    /* Rewrite qcow2 to be a self-referential loop */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "qcow2", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStore = NULL;
    qcow2.expBackingStoreRaw = "qcow2";
    qcow2.expDirectoryRel = ".";
    qcow2.expDirectoryAbs = datadir;
    qcow2.expFormat= VIR_STORAGE_FILE_NONE;
    qcow2.expIsFile = true;

    /* Behavior of an infinite loop chain */
    TEST_CHAIN(16, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite wrap and qcow2 to be mutually-referential loop */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "wrap", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", absqcow2, "wrap", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = "wrap";
    qcow2.expDirectoryRel = datadir;
    wrap.expFormat = VIR_STORAGE_FILE_QCOW2;

    /* Behavior of an infinite loop chain */
    TEST_CHAIN(17, "wrap", abswrap, VIR_STORAGE_FILE_QCOW2,
               (&wrap, &qcow2), EXP_WARN,
               (&wrap, &qcow2), ALLOW_PROBE | EXP_WARN,
               (&wrap, &qcow2), EXP_WARN,
               (&wrap, &qcow2), ALLOW_PROBE | EXP_WARN);

    /* Final cleanup */
    testCleanupImages();
    virCommandFree(cmd);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
