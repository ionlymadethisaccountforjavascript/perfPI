#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFFER_SIZE 4096

int send_file(const char *filename,
              const char *server_ip,
              int port)
{
    FILE *fp = fopen(filename, "rb");

    if (fp == NULL)
    {
        perror("fopen");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0)
    {
        perror("socket");
        fclose(fp);
        return -1;
    }

    struct sockaddr_in server;

    memset(&server, 0, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server.sin_addr) <= 0)
    {
        perror("inet_pton");
        fclose(fp);
        close(sock);
        return -1;
    }

    if (connect(sock,
                (struct sockaddr *)&server,
                sizeof(server)) < 0)
    {
        perror("connect");
        fclose(fp);
        close(sock);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes;

    while ((bytes = fread(buffer, 1, BUFFER_SIZE, fp)) > 0)
    {
        ssize_t sent = send(sock, buffer, bytes, 0);

        if (sent < 0)
        {
            perror("send");
            fclose(fp);
            close(sock);
            return -1;
        }
    }

    fclose(fp);
    close(sock);

    printf("Transfer complete.\n");

    return 0;
}
