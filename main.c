#include <stdio.h>
#include <stdlib.h>

#include "data_transmission/capture.h"
#include "data_transmission/transfer.h"

//test test test test
int main(void)
{
    capture_packets("capture.pcap", 60);

    serve_file("capture.pcap", 5000);

    return 0;
}
