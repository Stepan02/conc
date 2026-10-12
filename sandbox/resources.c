#include "resources.h"
#include <fcntl.h>
#include <sched.h>
#include <systemd/sd-bus.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int allocate_resources(const pid_t child_pid, const uint64_t ram_mb, const uint64_t cpu_us, const uint64_t pid_limit) {
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

    // set ram limit
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

    // set cpu limit
    if (cpu_us > 0) {
        sd_bus_message_open_container(m, 'r', "sv");
        sd_bus_message_append(m, "s", "CPUQuotaPerSecUSec");
        sd_bus_message_open_container(m, 'v', "t");
        sd_bus_message_append(m, "t", cpu_us);
        sd_bus_message_close_container(m);
        sd_bus_message_close_container(m);
    }

    // end properties
    sd_bus_message_close_container(m);

    sd_bus_message_open_container(m, 'a', "(sa(sv))");
    sd_bus_message_close_container(m);

    // send message to systemd
    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0) {
        fprintf(stderr, "systemd: %s\n", error.message);
    }

    // cleanup
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    // set oom score if set


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
