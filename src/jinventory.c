/*
 *  "jinventory.c" 
 *
 *  (c) COPYRIGHT 2018 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/* need this for the cpu affinity stuff */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libudev.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <json-c/json.h>
/* #include "pfsinv_common.h" */
#include "config.h"
#include <getopt.h>
#include <libjinventory/libjinventory.h>

static int show_drive_info(void);
static int show_cpu_info(void);
static int show_all_info(void);
static int show_net_info(void);
static int show_fpga_info(void);

static int verbose_flag;

void usage( void )
{
	printf(" Usage: jinventory <device>\n"
	       "   device: storage, net, cpu, fpga, all\n"
	       "       If no option is given the output will be the same as \"all\"\n");
	printf(" This command will print ou a JSON string of the udev informatiom found in sysfs\n"
	       "    of one or all of the devices shown above.\n" );
}

int main (int argc, char **argv)
{
	char device[32] = "all";
	char c;
	int getopt_error=0;
#if 0
	while (1){
		static struct option long_options[] =
			{
				/* These options set a flag. */
				{"version", no_argument,       0,'V'},
				/* These options don’t set a flag.
				   We distinguish them by their indices. */
				{0, 0, 0, 0}};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "V",
				 long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c){
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0)
				break;
			printf ("option %s", long_options[option_index].name);
			if (optarg)
				printf (" with arg %s", optarg);
			printf ("\n");
			break;
		case 'V':
			printf ("Version: %s\n",VERSION);
			return 0;
		case '?':
		default:
			/* getopt_long already printed an error message. */
			getopt_error=1;
			break;
		}
	}/* while 1 */

	if ( getopt_error ){
		printf(" Fatal Error Parsing Arguments.\n");
		return 1;
	}
#endif

	if (argc > 1)
		strncpy(device, argv[1], 32);

	if (strcmp (device, "net") == 0 ){
		show_net_info();
	}
	else if (strcmp (device, "cpu") == 0 ){
		show_cpu_info();
	}
	else if (strcmp (device, "storage") == 0 ) {
		show_drive_info();
	}
	else if (strcmp (device, "scsi_host") == 0 ) {
		jinventory_scsi_hosts_show_json();
	}
	else if (strcmp (device, "fpga") == 0 ) {
		show_fpga_info();
	}
	else if (strcmp (device, "all") == 0 ){
		show_all_info();
	}
	else if (strcmp (device, "?") == 0 ){
		usage();
		return 0;
	}
	else {
		printf(" Error: invalid device %s\n", device);
		usage();
		return 1;
	}
	return 0;
}

static int show_drive_info(void)
{
	jinventory_drives_show_json();
	return 0;
}

static int show_fpga_info(void)
{
	jinventory_fpga_show_json();
	return 0;
}

static int show_cpu_info(void)
{
	jinventory_cpus_show_json();
	return 0;
}

static int show_net_info(void)
{
	jinventory_nets_show_json();
	return 0;
}

static int show_all_info(void)
{
	char *invstr = NULL;

	invstr = jinventory_inventory_get_json_str();

	if ( invstr != NULL ){
		printf("%s",invstr);
		free(invstr);
	}

	return 0;
}



