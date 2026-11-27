#pragma once

#include <stdint.h>

#define DISK_IOCTL_CTRL_INIT 5
#define DISK_IOCTL_CTRL_DEINIT 6

// The card folder exists: 0. Else -EIO, as a card that does not start.
int disk_access_ioctl(const char *pdrv, uint8_t cmd, void *buff);
