#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 8192
#define DEFAULT_PI_IP "192.168.1.15"
#define DEFAULT_PORT  5000
#define PCAP_OUT      "received.pcap"

int main(int argc, char *argv[])
{
    const char *pi_ip = DEFAULT_PI_IP;
    int port = DEFAULT_PORT;

    if (argc >= 2) {
        pi_ip = argv[1];
    }

    if (argc >= 3) {
        char *endptr = NULL;
        long parsed_port = strtol(argv[2], &endptr, 10);
        if (*argv[2] == '\0' || *endptr != '\0' || parsed_port <= 0 || parsed_port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", argv[2]);
            return 1;
        }
        port = (int)parsed_port;
    }

    if (argc > 3) {
        fprintf(stderr, "Usage: %s [pi_ip] [port]\n", argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in pi_addr;
    memset(&pi_addr, 0, sizeof(pi_addr));
    pi_addr.sin_family = AF_INET;
    pi_addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, pi_ip, &pi_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid Pi IP address: %s\n", pi_ip);
        close(sockfd);
        return 1;
    }

    printf("Connecting to Pi at %s:%d...\n", pi_ip, port);

    if (connect(sockfd, (struct sockaddr *)&pi_addr, sizeof(pi_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    printf("Connected. Receiving PCAP file...\n");

    FILE *file = fopen(PCAP_OUT, "wb");
    if (file == NULL) {
        perror("fopen");
        close(sockfd);
        return 1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    long long total_received = 0;

    for (;;) {
        bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            fclose(file);
            close(sockfd);
            return 1;
        }
        if (bytes_received == 0) {
            break;
        }

        size_t bytes_written = fwrite(buffer, 1, (size_t)bytes_received, file);
        if (bytes_written != (size_t)bytes_received) {
            perror("fwrite");
            fclose(file);
            close(sockfd);
            return 1;
        }

        total_received += bytes_received;
    }

    fclose(file);
    close(sockfd);

    printf("Received %lld bytes.\n", total_received);

    if (total_received == 0) {
        fprintf(stderr, "Error: received 0 bytes from Pi; skipping ./process.\n");
        return 1;
    }

    printf("Saved PCAP as %s\n", PCAP_OUT);

    int status = system("./process");
    if (status != 0) {
        fprintf(stderr, "Error: ./process failed.\n");
        return 1;
    }

    return 0;
}
