#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMMAND_FILE "windows_commands.txt"
#define RUNTIME_FILE "perfPI_runtime.ps1"

#define MAX_SCRIPT_SIZE (1024 * 1024)

static char *read_file(const char *filename, size_t *out_size)
{
    FILE *file = fopen(filename, "rb");

    if (file == NULL) {
        perror("Could not open command file");
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        fprintf(stderr, "Could not seek command file.\n");
        return NULL;
    }

    long size = ftell(file);

    if (size < 0 || size > MAX_SCRIPT_SIZE) {
        fclose(file);
        fprintf(stderr, "Command file is too large or invalid.\n");
        return NULL;
    }

    rewind(file);

    char *buffer = malloc((size_t)size + 1);

    if (buffer == NULL) {
        fclose(file);
        fprintf(stderr, "Out of memory.\n");
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, (size_t)size, file);
    fclose(file);

    if (bytes_read != (size_t)size) {
        free(buffer);
        fprintf(stderr, "Could not read command file completely.\n");
        return NULL;
    }

    buffer[bytes_read] = '\0';

    if (out_size != NULL) {
        *out_size = bytes_read;
    }

    return buffer;
}

static int replace_all(
    char *buffer,
    size_t buffer_capacity,
    const char *needle,
    const char *replacement
)
{
    size_t needle_len = strlen(needle);
    size_t replacement_len = strlen(replacement);

    if (needle_len == 0) {
        return 1;
    }

    char *position = buffer;

    while ((position = strstr(position, needle)) != NULL) {

        size_t current_len = strlen(buffer);

        if (replacement_len > needle_len) {

            size_t growth = replacement_len - needle_len;

            if (current_len + growth + 1 > buffer_capacity) {
                fprintf(stderr,
                        "Expanded PowerShell script is too large.\n");
                return 0;
            }
        }

        if (replacement_len != needle_len) {

            memmove(
                position + replacement_len,
                position + needle_len,
                current_len
                    - (size_t)(position - buffer)
                    - needle_len
                    + 1
            );
        }

        memcpy(position, replacement, replacement_len);

        position += replacement_len;
    }

    return 1;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(
            stderr,
            "Usage: %s <PID> <duration_seconds>\n",
            argv[0]
        );

        return 1;
    }

    char *endptr = NULL;

    long pid = strtol(argv[1], &endptr, 10);

    if (*argv[1] == '\0' || *endptr != '\0' || pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }

    long duration = strtol(argv[2], &endptr, 10);

    if (*argv[2] == '\0' || *endptr != '\0' || duration <= 0) {
        fprintf(stderr, "Invalid duration: %s\n", argv[2]);
        return 1;
    }

    size_t source_size = 0;

    char *script = read_file(COMMAND_FILE, &source_size);

    if (script == NULL) {
        return 1;
    }

    size_t capacity = source_size + 4096;

    char *expanded = realloc(script, capacity);

    if (expanded == NULL) {
        free(script);
        fprintf(stderr, "Out of memory.\n");
        return 1;
    }

    script = expanded;

    char pid_string[32];
    char duration_string[32];

    snprintf(pid_string, sizeof(pid_string), "%ld", pid);
    snprintf(duration_string, sizeof(duration_string), "%ld", duration);

    if (!replace_all(
            script,
            capacity,
            "{{PID}}",
            pid_string)) {

        free(script);
        return 1;
    }

    if (!replace_all(
            script,
            capacity,
            "{{DURATION}}",
            duration_string)) {

        free(script);
        return 1;
    }

    FILE *runtime = fopen(RUNTIME_FILE, "wb");

    if (runtime == NULL) {
        perror("Could not create temporary PowerShell script");
        free(script);
        return 1;
    }

    size_t script_length = strlen(script);

    if (fwrite(script, 1, script_length, runtime) != script_length) {
        fclose(runtime);
        free(script);
        fprintf(stderr,
                "Could not write temporary PowerShell script.\n");
        return 1;
    }

    fclose(runtime);
    free(script);

    printf("Starting Windows telemetry collection...\n\n");

    int result = system(
        "powershell.exe "
        "-NoLogo "
        "-NoProfile "
        "-NonInteractive "
        "-ExecutionPolicy Bypass "
        "-File \"" RUNTIME_FILE "\""
    );

    remove(RUNTIME_FILE);

    if (result != 0) {

        fprintf(
            stderr,
            "\nWindows telemetry collection failed.\n"
            "PowerShell returned code: %d\n",
            result
        );

        return 1;
    }

    printf(
        "\nWindows telemetry collection finished successfully.\n"
    );

    return 0;
}
