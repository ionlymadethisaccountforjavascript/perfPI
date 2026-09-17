#include <stdio.h>
#include <stdlib.h>

//capture packet command
int capture_packets(const char *filename, int duration)
{
	char command[512];
	//command
	snprintf(command, 
		sizeof(command),
		"sudo timeout %d tcpdump -i eth0 -w %s",
		duration,
		filename);
	printf("executing",command);
	
	int status = system(command);
	if(status==-1){
    fprintf(stderr,"Failed to capture");
    return -1;
  };
	printf("\nCapture complete hehehehe\n");
	return 0;

};

