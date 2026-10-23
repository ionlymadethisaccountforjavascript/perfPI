#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define PCAP_FILE   "received.pcap"
#define OUTPUT_FILE "packet_data.csv"
#define TEMP_FILE   "packet_data.csv.tmp"
#define TSHARK      "tshark"

int main(void)
{
    struct stat st;

    /* Check that the PCAP exists */
    if (stat(PCAP_FILE, &st) != 0) {
        fprintf(stderr, "Error: %s not found.\n", PCAP_FILE);
        return 1;
    }

    printf("Found %s (%lld bytes)\n",
           PCAP_FILE,
           (long long)st.st_size);

    printf("Processing PCAP with TShark...\n");

    /*
     * Wireshark 4.x uses lowercase "_ws.col.protocol", while older
     * Wireshark 3.x uses "_ws.col.Protocol". Probe once so both work.
     */
    const char *proto_field = "_ws.col.protocol";
    if (system(TSHARK " -r " PCAP_FILE " -c 1 -T fields -e _ws.col.protocol >/dev/null 2>&1") != 0) {
        proto_field = "_ws.col.Protocol";
    }

    char command[1024];
    int written = snprintf(
        command,
        sizeof(command),
        TSHARK " "
        "-r " PCAP_FILE " "
        "-T fields "
        "-E header=y "
        "-E separator=, "
        "-E quote=d "
        "-e frame.time_epoch "
        "-e frame.time_delta "
        "-e frame.len "
        "-e ip.src "
        "-e ip.dst "
        "-e ipv6.src "
        "-e ipv6.dst "
        "-e %s "
        "-e tcp.srcport "
        "-e tcp.dstport "
        "-e udp.srcport "
        "-e udp.dstport "
        "-e tcp.flags "
        "-e tcp.flags.syn "
        "-e tcp.flags.fin "
        "-e tcp.flags.push "
        "> " TEMP_FILE,
        proto_field
    );

    if (written < 0 || (size_t)written >= sizeof(command)) {
        fprintf(stderr, "Error: command buffer overflow.\n");
        return 1;
    }

    int status = system(command);

    if (status != 0) {
        remove(TEMP_FILE);
        fprintf(stderr, "Error: TShark failed (ensure 'tshark' is installed).\n");
        return 1;
    }

    if (rename(TEMP_FILE, OUTPUT_FILE) != 0) {
        perror("rename");
        remove(TEMP_FILE);
        return 1;
    }

    printf("TShark processing complete.\n");
    printf("Packet data saved to %s\n", OUTPUT_FILE);

    return 0;
}
