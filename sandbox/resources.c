#include "resources.h"
#include <fcntl.h>
#include <math.h>
#include <sched.h>
#include <systemd/sd-bus.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <linux/limits.h>
#include "include/types.h"

int allocate_resources(const pid_t child_pid, const uint64_t ram_mb, const uint64_t cpu_us, const uint64_t pid_limit, const device_t *devices, const int device_count) {
    sd_bus *bus = NULL;
    sd_bus_message *m = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;

    // connect to dbus
    int r;
    if (getuid() == 0) {
        // use system bus if running as root
        r = sd_bus_default_system(&bus);
    } else {
        r = sd_bus_default_user(&bus);
    }

    if (r < 0) {
        fprintf(stderr, "d-bus: %s\n", strerror(-r));
        return r;
    }

    char scope_name[64];
    snprintf(scope_name, sizeof(scope_name), "sandbox-%d.scope", child_pid);

    // setup message
    r = sd_bus_message_new_method_call(bus, &m,"org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartTransientUnit");
    if (r < 0) {
        sd_bus_error_free(&error);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);

        return r;
    }

    // set scope to fail
    sd_bus_message_append(m, "ss", scope_name, "fail");

    // set properties
    sd_bus_message_open_container(m, 'a', "(sv)");

    // set pid limit
    sd_bus_message_open_container(m, 'r', "sv");
    sd_bus_message_append(m, "s", "PIDs");

    sd_bus_message_open_container(m, 'v', "au");
    sd_bus_message_open_container(m, 'a', "u");
    const uint32_t pid = (uint32_t) child_pid;
    sd_bus_message_append(m, "u", pid);
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);

    // set ram limit if set
    if (ram_mb > 0) {
        const uint64_t memory_bytes = ram_mb * 1024 * 1024;
        sd_bus_message_open_container(m, 'r', "sv");
        sd_bus_message_append(m, "s", "MemoryMax");
        sd_bus_message_open_container(m, 'v', "t");
        sd_bus_message_append(m, "t", memory_bytes);
        sd_bus_message_close_container(m);
        sd_bus_message_close_container(m);

        // set ram high limit to 90% of ram limit
        const uint64_t memory_high_bytes = (memory_bytes * 9) / 10;
        sd_bus_message_open_container(m, 'r', "sv");
        sd_bus_message_append(m, "s", "MemoryHigh");
        sd_bus_message_open_container(m, 'v', "t");
        sd_bus_message_append(m, "t", memory_high_bytes);
        sd_bus_message_close_container(m);
        sd_bus_message_close_container(m);
    }

    // disable swap
    sd_bus_message_open_container(m, 'r', "sv");
    sd_bus_message_append(m, "s", "MemorySwapMax");
    sd_bus_message_open_container(m, 'v', "t");
    sd_bus_message_append(m, "t", (uint64_t) 0);
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);

    // set pid limit
    const uint64_t pid_max = (pid_limit > 0) ? pid_limit : UINT64_MAX;
    sd_bus_message_open_container(m, 'r', "sv");
    sd_bus_message_append(m, "s", "TasksMax");
    sd_bus_message_open_container(m, 'v', "t");
    sd_bus_message_append(m, "t", pid_max);
    sd_bus_message_close_container(m);
    sd_bus_message_close_container(m);

    // set cpu limit if set
    if (cpu_us > 0) {
        sd_bus_message_open_container(m, 'r', "sv");
        sd_bus_message_append(m, "s", "CPUQuotaPerSecUSec");
        sd_bus_message_open_container(m, 'v', "t");
        sd_bus_message_append(m, "t", cpu_us);
        sd_bus_message_close_container(m);
        sd_bus_message_close_container(m);
    }

    // set devices
    if (device_count > 0) {
        int global_allow_set = 0;
        int global_allow_value = 1;
        int explicit_devices = 0;

        for (int i = 0; i < device_count; i++) {
            if (devices[i].path[0] == '\0') {
                global_allow_set = 1;
                global_allow_value = devices[i].allow;
            }

            if (devices[i].allow) {
                explicit_devices++;
            }
        }

        if (global_allow_set) {
            sd_bus_message_open_container(m, 'r', "sv");
            sd_bus_message_append(m, "s", "DevicePolicy");
            sd_bus_message_open_container(m, 'v', "s");

            sd_bus_message_append(m, "s", global_allow_value ? "auto" : "strict");

            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
        }

        if (explicit_devices > 0) {
            sd_bus_message_open_container(m, 'r', "sv");
            sd_bus_message_append(m, "s", "DeviceAllow");

            sd_bus_message_open_container(m, 'v', "a(ss)");
            sd_bus_message_open_container(m, 'a', "(ss)");


            for (int i = 0; i < device_count; i++) {
                if (devices[i].path[0] == '\0') {
                    continue;
                }

                if (devices[i].allow) {
                    sd_bus_message_open_container(m, 'r', "ss");
                    sd_bus_message_append(m, "ss", devices[i].path, devices[i].access);
                    sd_bus_message_close_container(m);
                }
            }

            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
            sd_bus_message_close_container(m);
        }
    }

    // end properties
    sd_bus_message_close_container(m);

    sd_bus_message_open_container(m, 'a', "(sa(sv))");
    sd_bus_message_close_container(m);

    // disable interactive authorization
    sd_bus_message_set_allow_interactive_authorization(m, 0);

    // send message to systemd
    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0) {
        fprintf(stderr, "systemd: %s\n", error.message);
    }

    // cleanup
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r;
}

int set_limits(const int oom_score_adj) {
    // do not modify the value by default
    if (oom_score_adj == 0) {
        return 0;
    }

    // write oom score adjust limit
    const int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd < 0) {
        perror("open oom_score_adj");
        return -1;
    }

    char buffer[32];
    const int len = snprintf(buffer, sizeof(buffer), "%d", oom_score_adj);
    if (write(fd, buffer, len) < 0) {
        perror("write oom_score_adj");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int setup_sysctl(const object_t *sysctl, const int sysctl_count) {
    if (sysctl_count == 0) {
        // do not change anything if no config values are provided
        return 0;
    }

    for (int i = 0; i < sysctl_count; i++) {
        const char *key = sysctl[i].key;
        const char *value = sysctl[i].value;

        if (!key || !value) {
            continue;
        }

        // resolve path
        char sysctl_path[PATH_MAX];
        snprintf(sysctl_path, sizeof(sysctl_path), "/proc/sys/%s", key);

        // replace dots with slashes
        for (int j = 10; sysctl_path[j] != '\0'; j++) {
            if (sysctl_path[j] == '.') {
                sysctl_path[j] = '/';
            }
        }

        // write the sysctl value
        const int fd = open(sysctl_path, O_WRONLY);
        if (fd < 0) {
            perror("open sysctl");
            return -1;
        }

        const ssize_t r = write(fd, value, strlen(value));
        close(fd);

        if (r < 0) {
            perror("write sysctl");
            return -1;
        }
    }

    return 0;
}
