// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// Zephyr's file system API on a host folder. "/SD:" is the folder sigu-sim got with --card.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define FS_FATFS 0

#define FS_O_READ 0x01
#define FS_O_WRITE 0x02
#define FS_O_CREATE 0x10
#define FS_O_TRUNC 0x40

#define FS_SEEK_SET 0

enum fs_dir_entry_type {
    FS_DIR_ENTRY_FILE = 0,
    FS_DIR_ENTRY_DIR,
};

struct fs_dirent {
    enum fs_dir_entry_type type;
    char name[256];
    size_t size;
};

struct fs_file_t {
    void *fp;
};

struct fs_dir_t {
    void *dir;
};

struct fs_mount_t {
    int type;
    const char *mnt_point;
    void *fs_data;
    void *storage_dev;
};

static inline void fs_file_t_init(struct fs_file_t *f)
{
    f->fp = NULL;
}

static inline void fs_dir_t_init(struct fs_dir_t *d)
{
    d->dir = NULL;
}

int fs_mount(struct fs_mount_t *mp);
int fs_unmount(struct fs_mount_t *mp);
int fs_open(struct fs_file_t *f, const char *path, int flags);
ssize_t fs_read(struct fs_file_t *f, void *buf, size_t n);
ssize_t fs_write(struct fs_file_t *f, const void *buf, size_t n);
int fs_sync(struct fs_file_t *f);
int fs_close(struct fs_file_t *f);
int fs_seek(struct fs_file_t *f, off_t offset, int whence);
int fs_unlink(const char *path);
int fs_stat(const char *path, struct fs_dirent *e);
int fs_opendir(struct fs_dir_t *d, const char *path);
int fs_readdir(struct fs_dir_t *d, struct fs_dirent *e);
int fs_closedir(struct fs_dir_t *d);
