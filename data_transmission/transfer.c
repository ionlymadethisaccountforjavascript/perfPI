#include "transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 8192
#define BACKLOG 5

int serve_file(const char *filename, int port)
{
    FILE *file = fopen(filename, "rb");

    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    /*
     * Create TCP listening socket.
     */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        perror("socket");
        fclose(file);
        return -1;
    }

    /*
     * Allow immediate reuse of the port after restarting.
     */
    int reuse = 1;

    if (setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            sizeof(reuse)) < 0) {
        perror("setsockopt");
        close(server_fd);
        fclose(file);
        return -1;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    /*
     * Bind to all Pi network interfaces.
     */
    if (bind(
            server_fd,
            (struct sockaddr *)&server_addr,
            sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        fclose(file);
        return -1;
    }

    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen");
        close(server_fd);
        fclose(file);
        return -1;
    }

    printf("Waiting for WSL connection on port %d...\n", port);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(
        server_fd,
        (struct sockaddr *)&client_addr,
        &client_len
    );

    if (client_fd < 0) {
        perror("accept");
        close(server_fd);
        fclose(file);
        return -1;
    }

    char client_ip[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        &client_addr.sin_addr,
        client_ip,
        sizeof(client_ip)
    );

    printf("WSL connected from %s\n", client_ip);
    printf("Sending %s...\n", filename);

    /*
     * Send the file in chunks.
     */
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    long long total_sent = 0;

    while ((bytes_read = fread(
                buffer,
                1,
                sizeof(buffer),
                file
            )) > 0) {

        size_t offset = 0;

        while (offset < bytes_read) {
            ssize_t bytes_sent = send(
                client_fd,
                buffer + offset,
                bytes_read - offset,
                0
            );

            if (bytes_sent < 0) {
                perror("send");
                close(client_fd);
                close(server_fd);
                fclose(file);
                return -1;
            }

            offset += bytes_sent;
            total_sent += bytes_sent;
        }
    }

    if (ferror(file)) {
        perror("fread");
        close(client_fd);
        close(server_fd);
        fclose(file);
        return -1;
    }

    /*
     * Signal that the file is finished.
     */
    shutdown(client_fd, SHUT_WR);

    printf("Sent %lld bytes successfully.\n", total_sent);

    close(client_fd);
    close(server_fd);
    fclose(file);

    return 0;
}
