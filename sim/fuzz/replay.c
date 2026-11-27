// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// main() for a compiler without libFuzzer (Apple clang).
// It runs each file once, and each file in a directory argument,
// so a corpus or a crash file from CI can be replayed under ASan.

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long len;

    if (!f || fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "%s: cannot read\n", path);
        if (f) {
            fclose(f);
        }
        return 1;
    }
    // The exact size, so ASan sees a read one past the end.
    buf = malloc(len ? (size_t)len : 1);
    if (!buf || fread(buf, 1, (size_t)len, f) != (size_t)len) {
        fprintf(stderr, "%s: cannot read\n", path);
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);
    LLVMFuzzerTestOneInput(buf, (size_t)len);
    free(buf);
    return 0;
}

static int run_dir(const char *dir, int *count)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char path[4096];
    struct stat st;
    int err = 0;

    if (!d) {
        fprintf(stderr, "%s: cannot open\n", dir);
        return 1;
    }
    while ((e = readdir(d))) {
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            err |= run_file(path);
            (*count)++;
        }
    }
    closedir(d);
    return err;
}

int main(int argc, char **argv)
{
    struct stat st;
    int count = 0;
    int err = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            continue; // libFuzzer flags, so the same command line works
        }
        if (stat(argv[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            err |= run_dir(argv[i], &count);
        } else {
            err |= run_file(argv[i]);
            count++;
        }
    }
    fprintf(stderr, "replayed %d inputs\n", count);
    return err;
}
