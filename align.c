#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define HPC_FILE          "hpc.csv"
#define PACKET_FILE       "packet_data.csv"
#define OUTPUT_FILE       "synced.csv"
#define DEFAULT_MAX_DELTA 1.0   /* max allowed |hpc_ts - pkt_ts| in seconds */

typedef struct {
    double ts;
    char *line;
} csv_row_t;

static void strip_eol(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

/* Parse timestamp from column 0 (handles both plain and "quoted" numbers) */
static int parse_first_col_ts(const char *line, double *out_ts)
{
    const char *p = line;
    while (*p != '\0' && (isspace((unsigned char)*p) || *p == '"')) {
        p++;
    }
    if (*p == '\0') {
        return -1;
    }

    char *end = NULL;
    double val = strtod(p, &end);
    if (end == p || (*end != ',' && *end != '"' && *end != '\0')) {
        return -1;
    }

    *out_ts = val;
    return 0;
}

static int cmp_rows(const void *a, const void *b)
{
    double ta = ((const csv_row_t *)a)->ts;
    double tb = ((const csv_row_t *)b)->ts;
    return (ta > tb) - (ta < tb);
}

static int load_csv(const char *path,
                    char **out_header,
                    csv_row_t **out_rows,
                    size_t *out_count)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        perror(path);
        return -1;
    }

    char *header = NULL;
    size_t cap = 256, count = 0;
    csv_row_t *rows = malloc(cap * sizeof(csv_row_t));
    if (rows == NULL) {
        fclose(f);
        return -1;
    }

    char buf[4096];
    while (fgets(buf, sizeof(buf), f) != NULL) {
        strip_eol(buf);
        if (buf[0] == '\0' || buf[0] == '#') {
            continue;
        }

        double ts;
        if (parse_first_col_ts(buf, &ts) != 0) {
            if (header == NULL) {
                header = strdup(buf);
            }
            continue;
        }

        if (count == cap) {
            cap *= 2;
            csv_row_t *grown = realloc(rows, cap * sizeof(csv_row_t));
            if (grown == NULL) {
                fclose(f);
                free(header);
                for (size_t i = 0; i < count; i++) free(rows[i].line);
                free(rows);
                return -1;
            }
            rows = grown;
        }

        rows[count].ts = ts;
        rows[count].line = strdup(buf);
        if (rows[count].line == NULL) {
            fclose(f);
            free(header);
            for (size_t i = 0; i < count; i++) free(rows[i].line);
            free(rows);
            return -1;
        }
        count++;
    }

    fclose(f);

    if (count == 0) {
        fprintf(stderr, "Error: no timestamped rows found in %s\n", path);
        free(header);
        free(rows);
        return -1;
    }

    qsort(rows, count, sizeof(csv_row_t), cmp_rows);
    *out_header = header;
    *out_rows = rows;
    *out_count = count;
    return 0;
}

static size_t find_closest(const csv_row_t *rows, size_t count, double target_ts)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (rows[mid].ts < target_ts) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if (lo == 0) return 0;
    if (lo >= count) return count - 1;

    double d_prev = fabs(target_ts - rows[lo - 1].ts);
    double d_curr = fabs(rows[lo].ts - target_ts);
    return (d_prev <= d_curr) ? (lo - 1) : lo;
}

static void free_csv(char *header, csv_row_t *rows, size_t count)
{
    free(header);
    for (size_t i = 0; i < count; i++) {
        free(rows[i].line);
    }
    free(rows);
}

int main(int argc, char *argv[])
{
    double max_delta = DEFAULT_MAX_DELTA;

    if (argc == 2) {
        char *end = NULL;
        max_delta = strtod(argv[1], &end);
        if (*argv[1] == '\0' || *end != '\0' || max_delta <= 0.0) {
            fprintf(stderr, "Usage: %s [max_delta_seconds]\n", argv[0]);
            return 1;
        }
    } else if (argc > 2) {
        fprintf(stderr, "Usage: %s [max_delta_seconds]\n", argv[0]);
        return 1;
    }

    char *hpc_header = NULL, *pkt_header = NULL;
    csv_row_t *hpc = NULL, *pkts = NULL;
    size_t n_hpc = 0, n_pkts = 0;

    if (load_csv(HPC_FILE, &hpc_header, &hpc, &n_hpc) != 0) {
        return 1;
    }
    if (load_csv(PACKET_FILE, &pkt_header, &pkts, &n_pkts) != 0) {
        free_csv(hpc_header, hpc, n_hpc);
        return 1;
    }

    FILE *out = fopen(OUTPUT_FILE, "w");
    if (out == NULL) {
        perror(OUTPUT_FILE);
        free_csv(hpc_header, hpc, n_hpc);
        free_csv(pkt_header, pkts, n_pkts);
        return 1;
    }

    if (hpc_header != NULL && pkt_header != NULL) {
        fprintf(out, "%s,%s\n", hpc_header, pkt_header);
    }

    size_t matched = 0;
    for (size_t i = 0; i < n_pkts; i++) {
        size_t j = find_closest(hpc, n_hpc, pkts[i].ts);
        if (fabs(hpc[j].ts - pkts[i].ts) <= max_delta) {
            fprintf(out, "%s,%s\n", hpc[j].line, pkts[i].line);
            matched++;
        }
    }

    fclose(out);

    printf("Loaded %zu HPC rows and %zu packet rows.\n", n_hpc, n_pkts);
    printf("Matched %zu rows (within %.3f s) -> %s\n", matched, max_delta, OUTPUT_FILE);

    if (matched == 0) {
        fprintf(stderr,
                "Warning: 0 timestamps matched!\n"
                "  HPC range:  [%.6f, %.6f]\n"
                "  PCAP range: [%.6f, %.6f]\n",
                hpc[0].ts, hpc[n_hpc - 1].ts,
                pkts[0].ts, pkts[n_pkts - 1].ts);
    }

    free_csv(hpc_header, hpc, n_hpc);
    free_csv(pkt_header, pkts, n_pkts);
    return 0;
}
