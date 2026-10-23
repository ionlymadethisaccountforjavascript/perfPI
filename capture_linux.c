#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/perf_event.h>

#define PERF_CSV_OUT "linux_perf.csv"
#define HPC_CSV_OUT  "hpc.csv"
#define SAMPLE_MS    900

enum {
    CNT_INSTRUCTIONS = 0,
    CNT_CYCLES,
    CNT_CACHE_MISSES,
    CNT_BRANCH_MISSES,
    CNT_CSWITCH,
    NUM_COUNTERS
};

typedef struct {
    unsigned long minflt;
    unsigned long majflt;
    unsigned long utime;
    unsigned long stime;
    long num_threads;
    unsigned long long rchar;
    unsigned long long wchar;
    unsigned long long syscr;
    unsigned long long syscw;
    unsigned long long sys_ctxt;
} proc_sample_t;

typedef struct {
    int *fds[NUM_COUNTERS];
    size_t count[NUM_COUNTERS];
    int enabled[NUM_COUNTERS];
} pmu_group_t;

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int sig)
{
    (void)sig;
    stop_requested = 1;
}

static double now_epoch(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int perf_event_open_sys(struct perf_event_attr *attr, pid_t tid)
{
    return (int)syscall(__NR_perf_event_open, attr, tid, -1, -1, 0);
}

static int read_process_name(pid_t pid, char *out, size_t out_sz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    if (fgets(out, (int)out_sz, f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);

    out[strcspn(out, "\r\n")] = '\0';
    return 0;
}

static int read_proc_stat(pid_t pid, proc_sample_t *s)
{
    char path[64];
    char buf[2048];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Field 2 is "(comm)" and may contain spaces or parentheses */
    char *rparen = strrchr(buf, ')');
    if (rparen == NULL || rparen[1] != ' ') {
        return -1;
    }

    char state;
    unsigned long cminflt, cmajflt;
    long cutime, cstime, priority, nice;

    int matched = sscanf(
        rparen + 2,
        "%c %*d %*d %*d %*d %*d %*u "
        "%lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld",
        &state,
        &s->minflt, &cminflt, &s->majflt, &cmajflt,
        &s->utime, &s->stime, &cutime, &cstime,
        &priority, &nice, &s->num_threads
    );

    return (matched == 12) ? 0 : -1;
}

static int read_proc_io(pid_t pid, proc_sample_t *s, int *warned_io)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/io", (int)pid);

    s->rchar = 0;
    s->wchar = 0;
    s->syscr = 0;
    s->syscw = 0;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        if (!*warned_io) {
            fprintf(stderr,
                    "Warning: cannot read %s (%s). Run with sudo for I/O counters.\n",
                    path, strerror(errno));
            *warned_io = 1;
        }
        return 0;
    }

    char key[64];
    unsigned long long val;
    while (fscanf(f, "%63s %llu", key, &val) == 2) {
        if (strcmp(key, "rchar:") == 0) {
            s->rchar = val;
        } else if (strcmp(key, "wchar:") == 0) {
            s->wchar = val;
        } else if (strcmp(key, "syscr:") == 0) {
            s->syscr = val;
        } else if (strcmp(key, "syscw:") == 0) {
            s->syscw = val;
        }
    }

    fclose(f);
    return 0;
}

static int read_system_ctxt(proc_sample_t *s)
{
    FILE *f = fopen("/proc/stat", "r");
    if (f == NULL) {
        return -1;
    }

    char line[512];
    int rc = -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "ctxt ", 5) == 0) {
            if (sscanf(line + 5, "%llu", &s->sys_ctxt) == 1) {
                rc = 0;
            }
            break;
        }
    }

    fclose(f);
    return rc;
}

static int read_sample(pid_t pid, proc_sample_t *s, int *warned_io)
{
    if (read_proc_stat(pid, s) != 0) {
        return -1;
    }
    if (read_proc_io(pid, s, warned_io) != 0) {
        return -1;
    }
    if (read_system_ctxt(s) != 0) {
        return -1;
    }
    return 0;
}

static int collect_tids(pid_t pid, pid_t **out_tids, size_t *out_count)
{
    char task_dir[64];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", (int)pid);

    DIR *dir = opendir(task_dir);
    if (dir == NULL) {
        return -1;
    }

    size_t cap = 32;
    size_t count = 0;
    pid_t *tids = malloc(cap * sizeof(pid_t));
    if (tids == NULL) {
        closedir(dir);
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        char *endptr = NULL;
        long tid = strtol(ent->d_name, &endptr, 10);
        if (ent->d_name[0] == '\0' || *endptr != '\0' || tid <= 0) {
            continue;
        }
        if (count == cap) {
            cap *= 2;
            pid_t *grown = realloc(tids, cap * sizeof(pid_t));
            if (grown == NULL) {
                free(tids);
                closedir(dir);
                return -1;
            }
            tids = grown;
        }
        tids[count++] = (pid_t)tid;
    }

    closedir(dir);

    if (count == 0) {
        free(tids);
        return -1;
    }

    *out_tids = tids;
    *out_count = count;
    return 0;
}

static void init_pmu_group(pid_t pid, pmu_group_t *pmu)
{
    static const struct {
        uint32_t type;
        uint64_t config;
        const char *name;
    } specs[NUM_COUNTERS] = {
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS,     "instructions" },
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES,       "cycles" },
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES,     "cache_misses" },
        { PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES,    "branch_misses" },
        { PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, "context_switches" }
    };

    memset(pmu, 0, sizeof(*pmu));

    pid_t *tids = NULL;
    size_t n_tids = 0;
    if (collect_tids(pid, &tids, &n_tids) != 0) {
        return;
    }

    for (int c = 0; c < NUM_COUNTERS; c++) {
        pmu->fds[c] = malloc(n_tids * sizeof(int));
        if (pmu->fds[c] == NULL) {
            continue;
        }

        size_t opened = 0;
        int last_err = 0;

        for (size_t i = 0; i < n_tids; i++) {
            struct perf_event_attr attr;
            memset(&attr, 0, sizeof(attr));
            attr.type = specs[c].type;
            attr.size = sizeof(attr);
            attr.config = specs[c].config;
            attr.disabled = 1;
            attr.inherit = 1;
            attr.exclude_hv = 1;

            int fd = perf_event_open_sys(&attr, tids[i]);
            if (fd < 0) {
                last_err = errno;
                continue;
            }

            ioctl(fd, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
            pmu->fds[c][opened++] = fd;
        }

        pmu->count[c] = opened;
        pmu->enabled[c] = (opened > 0);

        if (opened == 0) {
            if (last_err == EACCES) {
                fprintf(stderr,
                        "Note: PMU counter '%s' permission denied "
                        "(run with sudo or set kernel.perf_event_paranoid<=1).\n",
                        specs[c].name);
            } else {
                fprintf(stderr,
                        "Note: PMU counter '%s' unavailable (%s).\n",
                        specs[c].name, strerror(last_err));
            }
        }
    }

    free(tids);
}

static void read_pmu_totals(const pmu_group_t *pmu, uint64_t out_vals[NUM_COUNTERS])
{
    for (int c = 0; c < NUM_COUNTERS; c++) {
        uint64_t sum = 0;
        for (size_t i = 0; i < pmu->count[c]; i++) {
            uint64_t val = 0;
            if (read(pmu->fds[c][i], &val, sizeof(val)) == (ssize_t)sizeof(val)) {
                sum += val;
            }
        }
        out_vals[c] = sum;
    }
}

static void close_pmu_group(pmu_group_t *pmu)
{
    for (int c = 0; c < NUM_COUNTERS; c++) {
        for (size_t i = 0; i < pmu->count[c]; i++) {
            ioctl(pmu->fds[c][i], PERF_EVENT_IOC_DISABLE, 0);
            close(pmu->fds[c][i]);
        }
        free(pmu->fds[c]);
        pmu->fds[c] = NULL;
        pmu->count[c] = 0;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <PID> <duration_seconds>\n", argv[0]);
        return 1;
    }

    char *endptr = NULL;
    long pid_arg = strtol(argv[1], &endptr, 10);
    if (*argv[1] == '\0' || *endptr != '\0' || pid_arg <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }

    long duration = strtol(argv[2], &endptr, 10);
    if (*argv[2] == '\0' || *endptr != '\0' || duration <= 0) {
        fprintf(stderr, "Invalid duration: %s\n", argv[2]);
        return 1;
    }

    pid_t pid = (pid_t)pid_arg;
    char proc_name[128];
    if (read_process_name(pid, proc_name, sizeof(proc_name)) != 0) {
        fprintf(stderr, "Process with PID %d was not found.\n", (int)pid);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("\n========================================\n");
    printf(" perfPI Linux telemetry collection\n");
    printf("========================================\n");
    printf("PID: %d\n", (int)pid);
    printf("Process: %s\n", proc_name);
    printf("Duration: %ld seconds\n\n", duration);

    long clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) {
        clk_tck = 100;
    }

    int warned_io = 0;
    proc_sample_t prev_proc, curr_proc;
    if (read_sample(pid, &prev_proc, &warned_io) != 0) {
        fprintf(stderr, "Could not read initial /proc stats for PID %d.\n", (int)pid);
        return 1;
    }

    printf("Starting PMU recording via perf_event_open...\n");
    pmu_group_t pmu;
    init_pmu_group(pid, &pmu);

    uint64_t prev_pmu[NUM_COUNTERS];
    uint64_t curr_pmu[NUM_COUNTERS];
    read_pmu_totals(&pmu, prev_pmu);

    double prev_time = now_epoch();

    FILE *perf_csv = fopen(PERF_CSV_OUT, "w");
    if (perf_csv == NULL) {
        perror("fopen " PERF_CSV_OUT);
        close_pmu_group(&pmu);
        return 1;
    }

    FILE *hpc_csv = fopen(HPC_CSV_OUT, "w");
    if (hpc_csv == NULL) {
        perror("fopen " HPC_CSV_OUT);
        fclose(perf_csv);
        close_pmu_group(&pmu);
        return 1;
    }

    fprintf(perf_csv,
            "timestamp,pid,cpu_percent,io_bytes_sec,io_ops_sec,"
            "page_faults_sec,thread_count,context_switches_sec\n");
    fprintf(hpc_csv,
            "timestamp,pid,instructions,cycles,ipc,"
            "cache_misses,branch_misses,proc_context_switches\n");

    double end_time = prev_time + (double)duration;
    long sample_number = 0;
    struct timespec sleep_ts = {
        .tv_sec = SAMPLE_MS / 1000,
        .tv_nsec = (SAMPLE_MS % 1000) * 1000000L
    };

    printf("Collecting telemetry samples...\n");

    while (!stop_requested && now_epoch() < end_time) {
        nanosleep(&sleep_ts, NULL);
        if (stop_requested) {
            break;
        }

        double curr_time = now_epoch();
        if (read_sample(pid, &curr_proc, &warned_io) != 0) {
            fprintf(stderr, "Target PID %d exited during collection.\n", (int)pid);
            break;
        }
        read_pmu_totals(&pmu, curr_pmu);

        double dt = curr_time - prev_time;
        if (dt <= 0.0) {
            continue;
        }

        unsigned long d_ticks =
            (curr_proc.utime + curr_proc.stime) - (prev_proc.utime + prev_proc.stime);
        double cpu_pct = ((double)d_ticks / (double)clk_tck) / dt * 100.0;

        double io_bytes_sec =
            (double)((curr_proc.rchar + curr_proc.wchar) - (prev_proc.rchar + prev_proc.wchar)) / dt;
        double io_ops_sec =
            (double)((curr_proc.syscr + curr_proc.syscw) - (prev_proc.syscr + prev_proc.syscw)) / dt;
        double page_faults_sec =
            (double)((curr_proc.minflt + curr_proc.majflt) - (prev_proc.minflt + prev_proc.majflt)) / dt;
        double sys_ctxt_sec =
            (double)(curr_proc.sys_ctxt - prev_proc.sys_ctxt) / dt;

        uint64_t d_instr  = curr_pmu[CNT_INSTRUCTIONS]  - prev_pmu[CNT_INSTRUCTIONS];
        uint64_t d_cycles = curr_pmu[CNT_CYCLES]        - prev_pmu[CNT_CYCLES];
        uint64_t d_cache  = curr_pmu[CNT_CACHE_MISSES]  - prev_pmu[CNT_CACHE_MISSES];
        uint64_t d_branch = curr_pmu[CNT_BRANCH_MISSES] - prev_pmu[CNT_BRANCH_MISSES];
        uint64_t d_csw    = curr_pmu[CNT_CSWITCH]       - prev_pmu[CNT_CSWITCH];
        double ipc = (d_cycles > 0) ? ((double)d_instr / (double)d_cycles) : 0.0;

        fprintf(perf_csv,
                "%.6f,%d,%.2f,%.2f,%.2f,%.2f,%ld,%.2f\n",
                curr_time, (int)pid, cpu_pct, io_bytes_sec, io_ops_sec,
                page_faults_sec, curr_proc.num_threads, sys_ctxt_sec);
        fflush(perf_csv);

        fprintf(hpc_csv,
                "%.6f,%d,%llu,%llu,%.4f,%llu,%llu,%llu\n",
                curr_time, (int)pid,
                (unsigned long long)d_instr,
                (unsigned long long)d_cycles,
                ipc,
                (unsigned long long)d_cache,
                (unsigned long long)d_branch,
                (unsigned long long)d_csw);
        fflush(hpc_csv);

        sample_number++;
        printf("Sample %ld\n", sample_number);

        prev_proc = curr_proc;
        memcpy(prev_pmu, curr_pmu, sizeof(prev_pmu));
        prev_time = curr_time;
    }

    fclose(perf_csv);
    fclose(hpc_csv);
    close_pmu_group(&pmu);

    printf("\n========================================\n");
    printf(" Collection complete\n");
    printf("========================================\n");
    printf("Created: %s\n", PERF_CSV_OUT);
    printf("Created: %s\n", HPC_CSV_OUT);

    return 0;
}
