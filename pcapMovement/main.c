#include <stdio.h>
#include <stdlib.h>
#include "data_transmission/capture.h"
#include "data_transmission/transfer.h"
//test test test test
int main(){
  capture_packets("capture.pcap", 60);
  send_file("capture.pcap",
             "192.168.1.4",
              5000);
  return 0;
};

