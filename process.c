#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define PCAP_FILE   "received.pcap"
#define OUTPUT_FILE "packet_data.csv"

/*
 * Windows short path for:
 * C:\Program Files\Wireshark\tshark.exe
 *
 * This avoids the space in "Program Files".
 */
#define TSHARK "C:\\Progra~1\\Wireshark\\tshark.exe"

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
     * Extract packet-level information.
     *
     * We deliberately do not use a display filter here.
     * TShark will process the entire PCAP and leave irrelevant
     * fields blank when they do not apply to a packet.
     */
    const char *command =
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
        "-e _ws.col.Protocol "
        "-e tcp.srcport "
        "-e tcp.dstport "
        "-e udp.srcport "
        "-e udp.dstport "
        "-e tcp.flags "
        "-e tcp.flags.syn "
        "-e tcp.flags.fin "
        "-e tcp.flags.push "
        "> " OUTPUT_FILE;

    int status = system(command);

    if (status != 0) {
        fprintf(stderr, "Error: TShark failed.\n");
        return 1;
    }

    printf("TShark processing complete.\n");
    printf("Packet data saved to %s\n", OUTPUT_FILE);

    return 0;
}
