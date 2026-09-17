#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#define BUFFER_SIZE 8192

int main(void)
{
    const char *pi_ip = "192.168.1.15";
    int port = 5000;

    /* Initialize WinSock */
    WSADATA wsaData;

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return 1;
    }

    /* Create socket */
    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in pi_addr;
    memset(&pi_addr, 0, sizeof(pi_addr));

    pi_addr.sin_family = AF_INET;
    pi_addr.sin_port = htons((u_short)port);

    if (inet_pton(AF_INET, pi_ip, &pi_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid Pi IP address: %s\n", pi_ip);
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    printf("Connecting to Pi at %s:%d...\n", pi_ip, port);

    if (connect(sockfd,
                (struct sockaddr *)&pi_addr,
                sizeof(pi_addr)) == SOCKET_ERROR) {

        fprintf(stderr, "connect failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    printf("Connected. Receiving PCAP file...\n");

    FILE *file = fopen("received.pcap", "wb");

    if (file == NULL) {
        perror("fopen");
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    char buffer[BUFFER_SIZE];
    int bytes_received;
    long long total_received = 0;

    while ((bytes_received = recv(sockfd,
                                  buffer,
                                  sizeof(buffer),
                                  0)) > 0) {

        size_t bytes_written = fwrite(
            buffer,
            1,
            (size_t)bytes_received,
            file
        );

        if (bytes_written != (size_t)bytes_received) {
            perror("fwrite");
            fclose(file);
            closesocket(sockfd);
            WSACleanup();
            return 1;
        }

        total_received += bytes_received;
    }

    if (bytes_received == SOCKET_ERROR) {
        fprintf(stderr, "recv failed: %d\n", WSAGetLastError());
        fclose(file);
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    fclose(file);
    closesocket(sockfd);
    WSACleanup();

    printf("Received %lld bytes.\n", total_received);
    printf("Saved PCAP as received.pcap\n");

    return 0;
}
