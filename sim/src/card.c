// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The SD card is a host folder. Paths under "/SD:" map into it.
// The card can be taken out and put back in, which is what card_present() reports to sdcard.c.
// While it is out, the disk does not start and every path fails, as with a pulled card.

#include "card_detect.h"
#include "sim.h"
#include <stdatomic.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zephyr/fs/fs.h>
#include <zephyr/storage/disk_access.h>

#define MOUNT "/SD:"

static char root[PATH_MAX];
static atomic_bool present;

bool sim_card_init(const char *dir, bool in)
{
    struct stat st;

    present = in;
    return stat(dir, &st) == 0 && S_ISDIR(st.st_mode) && realpath(dir, root);
}

const char *sim_card_dir(void)
{
    return root;
}

bool sim_card_in(void)
{
    return present;
}

void sim_card_set(bool in)
{
    present = in;
    fprintf(stderr, "[SIM] card %s\n", in ? "in" : "out");
}

bool card_present(void)
{
    return present;
}

// Only paths at the top of the card exist. The firmware never uses any other.
static int host_path(const char *path, char *out, size_t n)
{
    size_t m = strlen(MOUNT);

    if (!present) {
        return -EIO;
    } else if (strncmp(path, MOUNT, m) != 0) {
        return -ENOENT;
    } else {
        path += m;
    }
    while (*path == '/') {
        path++;
    }
    if (strchr(path, '/') || !strcmp(path, "..")) {
        return -ENOENT;
    }
    snprintf(out, n, "%s/%s", root, path);
    return 0;
}

int disk_access_ioctl(const char *pdrv, uint8_t cmd, void *buff)
{
    (void)pdrv;
    (void)buff;
    if (cmd == DISK_IOCTL_CTRL_INIT) {
        return present ? 0 : -EIO;
    }
    return 0;
}

int fs_mount(struct fs_mount_t *mp)
{
    return present && !strcmp(mp->mnt_point, MOUNT) ? 0 : -ENODEV;
}

int fs_unmount(struct fs_mount_t *mp)
{
    (void)mp;
    return 0;
}

int fs_open(struct fs_file_t *f, const char *path, int flags)
{
    char p[PATH_MAX];
    const char *mode = "rb";

    int rc = host_path(path, p, sizeof(p));

    if (rc != 0) {
        return rc;
    }
    if (flags & FS_O_WRITE) {
        mode = (flags & FS_O_TRUNC) ? "wb" : ((flags & FS_O_CREATE) ? "ab" : "r+b");
    }
    f->fp = fopen(p, mode);
    return f->fp ? 0 : -errno;
}

ssize_t fs_read(struct fs_file_t *f, void *buf, size_t n)
{
    size_t got = fread(buf, 1, n, f->fp);

    return ferror(f->fp) ? -EIO : (ssize_t)got;
}

ssize_t fs_write(struct fs_file_t *f, const void *buf, size_t n)
{
    size_t put = fwrite(buf, 1, n, f->fp);

    return put == n ? (ssize_t)put : -EIO;
}

int fs_sync(struct fs_file_t *f)
{
    return fflush(f->fp) == 0 ? 0 : -EIO;
}

int fs_close(struct fs_file_t *f)
{
    int rc = fclose(f->fp) == 0 ? 0 : -EIO;

    f->fp = NULL;
    return rc;
}

int fs_unlink(const char *path)
{
    char p[PATH_MAX];
    int rc = host_path(path, p, sizeof(p));

    if (rc != 0) {
        return rc;
    }
    return remove(p) == 0 ? 0 : -errno;
}

int fs_seek(struct fs_file_t *f, off_t offset, int whence)
{
    return fseeko(f->fp, offset, whence == FS_SEEK_SET ? SEEK_SET : SEEK_CUR) == 0 ? 0 : -EIO;
}

int fs_stat(const char *path, struct fs_dirent *e)
{
    char p[PATH_MAX];
    struct stat st;

    int rc = host_path(path, p, sizeof(p));

    if (rc != 0) {
        return rc;
    }
    if (stat(p, &st) != 0) {
        return -ENOENT;
    }
    memset(e, 0, sizeof(*e));
    e->type = S_ISDIR(st.st_mode) ? FS_DIR_ENTRY_DIR : FS_DIR_ENTRY_FILE;
    e->size = st.st_size;
    return 0;
}

int fs_opendir(struct fs_dir_t *d, const char *path)
{
    char p[PATH_MAX];

    int rc = host_path(path, p, sizeof(p));

    if (rc != 0) {
        return rc;
    }
    d->dir = opendir(p);
    return d->dir ? 0 : -errno;
}

// FAT has no "." and "..", so they are left out. An empty name ends the list.
int fs_readdir(struct fs_dir_t *d, struct fs_dirent *e)
{
    struct dirent *de;

    while ((de = readdir(d->dir)) != NULL) {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
            break;
        }
    }
    memset(e, 0, sizeof(*e));
    if (!de) {
        return 0;
    }
    snprintf(e->name, sizeof(e->name), "%s", de->d_name);
    e->type = de->d_type == DT_DIR ? FS_DIR_ENTRY_DIR : FS_DIR_ENTRY_FILE;
    return 0;
}

int fs_closedir(struct fs_dir_t *d)
{
    closedir(d->dir);
    d->dir = NULL;
    return 0;
}
