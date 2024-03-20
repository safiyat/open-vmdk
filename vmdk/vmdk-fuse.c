/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * This "filesystem" provides only a single file. The mountpoint
 * needs to be a file rather than a directory. All writes to the
 * file will be discarded, and reading the file always returns
 * \0.
 *
 * Compile with:
 *
 *     gcc -Wall null.c `pkg-config fuse3 --cflags --libs` -o null
 *
 * ## Source code ##
 * \include passthrough_fh.c
 */


#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "diskinfo.h"

char *toolsVersion = "2147483647";

struct options {
    char *vmdk_path;
};

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
                OPTION("--file=%s", vmdk_path),
                FUSE_OPT_END
};

struct vmdk_data {
    struct options options;
    off_t capacity;
};

static int vmdk_getattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi)
{
	(void) fi;
    struct stat st;
    struct vmdk_data *data = (struct vmdk_data *)fuse_get_context()->private_data;
    char *vmdk_path = data->options.vmdk_path;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

    stat(vmdk_path, &st);

	stbuf->st_mode = st.st_mode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_size = data->capacity;
	stbuf->st_blocks = 0;
	stbuf->st_atime = st.st_atime;
    stbuf->st_mtime = st.st_mtime;
    stbuf->st_ctime = st.st_ctime;

	return 0;
}

static int vmdk_truncate(const char *path, off_t size,
			 struct fuse_file_info *fi)
{
	(void) size;
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	return 0;
}

static int vmdk_open(const char *path, struct fuse_file_info *fi)
{
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	return 0;
}

static int vmdk_read(const char *path, char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	(void) buf;
	(void) offset;
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	if (offset >= (1ULL << 32))
		return 0;

	memset(buf, 0, size);
	return size;
}

static int vmdk_write(const char *path, const char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	(void) buf;
	(void) offset;
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	return size;
}

static const struct fuse_operations vmdk_oper = {
	.getattr	= vmdk_getattr,
	.truncate	= vmdk_truncate,
	.open		= vmdk_open,
	.read		= vmdk_read,
	.write		= vmdk_write,
};

int vmdk_init(struct vmdk_data *data)
{
    DiskInfo *di;

    di = Sparse_Open(data->options.vmdk_path);
    if (di == NULL) {
        fprintf(stderr, "could not read %s\n", data->options.vmdk_path);
        return 1;
    }
    data->capacity = di->vmt->getCapacity(di);
    di->vmt->close(di);

    return 0;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts;
	struct stat stbuf;
    struct vmdk_data data = {0};

    if (fuse_opt_parse(&args, &data.options, option_spec, NULL) == -1)
            return 1;

    if (!data.options.vmdk_path) {
		fprintf(stderr, "missing vmdk file parameter (file=)\n");
		return 1;        
    } else {
        char *tmp = data.options.vmdk_path;
        data.options.vmdk_path = realpath(data.options.vmdk_path, NULL);
        free(tmp);
    }

	if (stat(data.options.vmdk_path, &stbuf) == -1) {
		fprintf(stderr ,"failed to access vmdk file %s: %s\n",
			data.options.vmdk_path, strerror(errno));
		free(data.options.vmdk_path);
		return 1;
	}
	if (!S_ISREG(stbuf.st_mode)) {
		fprintf(stderr, "vmdk file %s is not a regular file\n", data.options.vmdk_path);
		return 1;
	}

    /*
	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (!opts.mountpoint) {
		fprintf(stderr, "missing mountpoint parameter\n");
		return 1;
	}
	if (stat(opts.mountpoint, &stbuf) == -1) {
		fprintf(stderr ,"failed to access mountpoint %s: %s\n",
			opts.mountpoint, strerror(errno));
		free(opts.mountpoint);
		return 1;
	}
	if (!S_ISREG(stbuf.st_mode)) {
		fprintf(stderr, "mountpoint %s is not a regular file\n", opts.mountpoint);
		return 1;
	}
    */

    if (vmdk_init(&data) != 0) {
        return 1;
    }

    printf("before fuse_main\n");
	return fuse_main(args.argc, args.argv, &vmdk_oper, (void *)&data);
}
