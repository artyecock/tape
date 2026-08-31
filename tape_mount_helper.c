/*
 * tape_mount_helper.c - udev-invoked helper for the CMS Tape Proxy scheme
 *
 * Verbs:
 *   ATTACH <ccw_bus_id>              vdev attached by CP (informational/audit)
 *   DETACH <ccw_bus_id>              vdev detached by CP (cleans up stray locks)
 *   MOUNT  <kernel_name> <dev_path>  character device node appeared - resolve
 *                                     its vdev via sysfs, then apply ownership
 *                                     from /run/tape/<vdev>.owner
 *   UMOUNT <kernel_name>             character device node removed - clean up
 *                                     the owner-request file
 *
 * IMPORTANT: udev's %n substitution is the trailing "kernel number" of the
 * device name (e.g. "0" for ntibm0) - NOT the vdev address. Do not pass %n
 * for MOUNT/UMOUNT; pass %k (the kernel device name) and let this helper
 * resolve the vdev itself via sysfs, exactly as tape.c does.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#define OWNER_DIR "/run/tape"
#define LOCK_DIR  "/run/lock/tape"
#define TAPE_SYSFS_CLASS "tape390"

void normalize_vdev(const char *in, char *out, size_t out_size) {
    const char *p = in;
    if (strncasecmp(p, "0x", 2) == 0) p += 2;
    const char *dot = strstr(p, "0.0.");
    if (dot) p = dot + 4;
    unsigned int v = (unsigned int) strtoul(p, NULL, 16);
    snprintf(out, out_size, "%04X", v & 0xFFFF);
}

/* Same two-"0.0." symlink structure as tape.c's resolve_vdev_for_device_path():
 *   /sys/class/tape390/<kernel_name> -> ../../devices/css0/0.0.<subchan>/0.0.<vdev>/tape390/<kernel_name>
 */
int resolve_vdev_from_kernel_name(const char *kernel_name, char *out4, size_t out4_size) {
    char sys_path[256], resolved[256];
    snprintf(sys_path, sizeof(sys_path), "/sys/class/" TAPE_SYSFS_CLASS "/%s", kernel_name);

    ssize_t len = readlink(sys_path, resolved, sizeof(resolved) - 1);
    if (len <= 0) return -1;
    resolved[len] = '\0';

    const char *p = strstr(resolved, "0.0.");
    if (!p) return -1;
    p = strstr(p + 4, "0.0.");
    if (!p) return -1;

    snprintf(out4, out4_size, "%.4s", p + 4);
    for (char *q = out4; *q; q++) *q = toupper((unsigned char) *q);
    return 0;
}

int read_owner_request(const char *vdev, uid_t *uid_out, char *mode_out, size_t mode_size) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.owner", OWNER_DIR, vdev);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[128];
    int got_uid = 0, got_mode = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "UID=", 4) == 0) {
            *uid_out = (uid_t) atoi(line + 4);
            got_uid = 1;
        } else if (strncmp(line, "MODE=", 5) == 0) {
            char *p = line + 5;
            char *nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            snprintf(mode_out, mode_size, "%s", p);
            got_mode = 1;
        }
    }
    fclose(f);
    return (got_uid && got_mode) ? 0 : -1;
}

void handle_attach(const char *bus_id) {
    syslog(LOG_INFO, "tape_mount_helper: ATTACH %s", bus_id);
}

void handle_detach(const char *bus_id) {
    syslog(LOG_INFO, "tape_mount_helper: DETACH %s", bus_id);

    char norm[8];
    normalize_vdev(bus_id, norm, sizeof(norm));
    char lock_path[256];
    snprintf(lock_path, sizeof(lock_path), "%s/%s.lock", LOCK_DIR, norm);
    if (unlink(lock_path) == 0)
        syslog(LOG_INFO, "tape_mount_helper: removed stale lock %s", lock_path);
}

int handle_mount(const char *kernel_name, const char *device_path) {
    char vdev[8];
    if (resolve_vdev_from_kernel_name(kernel_name, vdev, sizeof(vdev)) != 0) {
        syslog(LOG_ERR, "tape_mount_helper: MOUNT could not resolve vdev for %s", kernel_name);
        return 1;
    }

    uid_t uid;
    char mode[16];
    if (read_owner_request(vdev, &uid, mode, sizeof(mode)) != 0) {
        syslog(LOG_WARNING, "tape_mount_helper: MOUNT %s (vdev %s) %s - no owner request found",
               kernel_name, vdev, device_path);
        return 1;
    }

    if (chown(device_path, uid, 0) != 0) {
        syslog(LOG_ERR, "tape_mount_helper: chown %s to uid %d failed: %s",
               device_path, uid, strerror(errno));
        return 1;
    }

    mode_t perm = (strcmp(mode, "WRITE") == 0) ? 0600 : 0400;
    if (chmod(device_path, perm) != 0) {
        syslog(LOG_ERR, "tape_mount_helper: chmod %s to %o failed: %s",
               device_path, perm, strerror(errno));
        return 1;
    }

    syslog(LOG_INFO, "tape_mount_helper: MOUNT %s (vdev %s) %s -> uid=%d mode=%s (%o)",
           kernel_name, vdev, device_path, uid, mode, perm);
    return 0;
}

void handle_umount(const char *kernel_name) {
    char vdev[8];
    if (resolve_vdev_from_kernel_name(kernel_name, vdev, sizeof(vdev)) != 0) {
        syslog(LOG_WARNING, "tape_mount_helper: UMOUNT could not resolve vdev for %s "
                             "(device node likely already gone)", kernel_name);
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/%s.owner", OWNER_DIR, vdev);
    if (unlink(path) == 0)
        syslog(LOG_INFO, "tape_mount_helper: UMOUNT %s (vdev %s) - removed owner request",
               kernel_name, vdev);
    else
        syslog(LOG_INFO, "tape_mount_helper: UMOUNT %s (vdev %s) - no owner request present",
               kernel_name, vdev);
}

int main(int argc, char *argv[]) {
    openlog("tape_mount_helper", LOG_PID | LOG_CONS, LOG_DAEMON);

    if (argc < 3) {
        syslog(LOG_ERR, "tape_mount_helper: insufficient arguments");
        closelog();
        return 1;
    }

    const char *verb = argv[1];
    int rc = 0;

    if (strcasecmp(verb, "ATTACH") == 0) {
        handle_attach(argv[2]);
    } else if (strcasecmp(verb, "DETACH") == 0) {
        handle_detach(argv[2]);
    } else if (strcasecmp(verb, "MOUNT") == 0) {
        if (argc < 4) {
            syslog(LOG_ERR, "tape_mount_helper: MOUNT requires <kernel_name> <device_path>");
            rc = 1;
        } else {
            rc = handle_mount(argv[2], argv[3]);
        }
    } else if (strcasecmp(verb, "UMOUNT") == 0) {
        handle_umount(argv[2]);
    } else {
        syslog(LOG_ERR, "tape_mount_helper: unknown verb '%s'", verb);
        rc = 1;
    }

    closelog();
    return rc;
}
