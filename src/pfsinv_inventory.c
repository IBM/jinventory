/*
 *  "pfsinv_inventory.c" 
 *
 *  (c) COPYRIGHT 2016 IBM Corp.
 *
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
#include "pfsinv_common.h"
#include <json-c/json.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/ethtool.h>

#define VERBOSE_DEBUG 1

#if defined VERBOSE_DEBUG
static int test_device_parents(struct udev *udev, const char *syspath);
static void print_device(struct udev_device *device);
static int test_device(struct udev *udev, const char *syspath);
static void print_properties(struct udev_device *device);
static void print_sysattr(struct udev_device *device);
#endif

static json_object *pfsinv_drives_get_json_object( void );
static json_object *pfsinv_cpus_get_json_object( void );
static json_object *pfsinv_nets_get_json_object( void );
static int pfsinv_get_eth_drvinfo( int sock, char *if_name, struct ethtool_drvinfo *drvinfo);
static int pfsinv_netstat_info( unsigned int flags, char **json_str, char *iface, void **jobj );
static int pfsinv_net_interfaces( unsigned int flags, char **json_str, void **jobj );

static int is_ascii(const signed char *c, size_t len);
static int verbose_debug = 0;

#define PFSD_INV_FLAG_VERBOSE  (1<<0)

static void init_inv_list ( struct inv_dir_list **head);
static struct inv_dir_list  *add_inv_list ( struct inv_dir_list *node, struct inv_dir_info *info);
static void print_inv_list(struct inv_dir_list *head);
static void free_inv_list(struct inv_dir_list *head);


struct inv_dir_list *find_subdirs( const char *path, struct inv_dir_list *dl_ptr )
{
	char  cfpath[256];
	char  basepath[256];
	char  dirname[256];
	DIR *dirp;
	struct dirent *dp;

	memset((void *)cfpath,0,256);
	memset((void *)basepath,0,256);
	sprintf(cfpath,"%s", path);
	sprintf(basepath,"%s", path);
	struct inv_dir_info *dlinfo= NULL;

	if ( 0 )
		printf("cfpath = %s\n", cfpath);

	dirp = opendir(cfpath);
	while (dirp) {
		if ((dp=readdir(dirp)) != NULL) {
			if ((strcmp(".",dp->d_name)==0) || (strcmp("..",dp->d_name)==0))
				continue;
			if (dp->d_type == DT_DIR ){
				memset((void *)dirname,0,256);
				sprintf(dirname,"%s/%s",basepath, dp->d_name);
				/*printf("%s is a directory\n", dirname);*/
				dlinfo= (struct inv_dir_info *)malloc(sizeof(struct inv_dir_info));
				dlinfo->name = malloc(strlen(dirname)+1);
				memset((void *)dlinfo->name,0,strlen(dirname)+1);
				strncpy(dlinfo->name, dirname, strlen(dirname));
				/*printf("%s\n", dlinfo->name);*/
				dl_ptr = add_inv_list( dl_ptr,dlinfo);
				dl_ptr = find_subdirs( dirname, dl_ptr );
			}
		}
		else {
			break;
		}
	}
	closedir(dirp);
	return dl_ptr;
}


/* Storage */
int pfsinv_num_drives( void )
{
	char *json_str = NULL;
	int num_drives = 0;

	/* Don't ask me why but doing it like this causes a segfault of the variety...
	   unhandled signal 11 at 0000000000000018 nip 0000000000000018 lr 000000001000513c code 30001
	   num_drives = pfsinv_drive_info(0,(char **)NULL,(void **)NULL); 
	   The CPU one does the exact same thing.
	*/

	num_drives = pfsinv_drive_info(0,&json_str,(void **)NULL); 

	if (json_str)
		free(json_str);

	return num_drives;
}

int pfsinv_drives_show_json( void )
{
	char *json_str = NULL;
	int num_drives = 0;
	num_drives = pfsinv_drive_info(PFSD_INV_FLAG_VERBOSE, (char **)NULL,(void **)NULL); 
	/* num_drives = pfsinv_drive_info(PFSD_INV_FLAG_VERBOSE, &json_str,(void **)NULL);  */
	if (json_str)
		free(json_str);
	return num_drives;
}

char *pfsinv_drives_get_json_str( void )
{
	char *json_str = NULL;
	pfsinv_drive_info(0, &json_str,(void **)NULL); 
	return json_str;
}


/* CPU */
int pfsinv_num_cpus( void )
{
	char *json_str = NULL;
	int num_cpus = 0;
	num_cpus = pfsinv_cpu_info(0,&json_str,(void **)NULL); 
	if (json_str)
		free(json_str);
	return num_cpus;
}

int pfsinv_cpus_show_json( void )
{
	char *json_str = NULL;
	int num_cpus = 0;
	num_cpus = pfsinv_cpu_info(PFSD_INV_FLAG_VERBOSE, (char **)NULL, (void **)NULL); 
	/* num_cpus = pfsinv_cpu_info(PFSD_INV_FLAG_VERBOSE, &json_str, (void **)NULL);  */
	if (json_str)
		free(json_str);
	return num_cpus;
}

char *pfsinv_cpus_get_json_str( void )
{
	char *json_str = NULL;
	pfsinv_cpu_info(0, &json_str, (void **)NULL);
	return json_str;
}

/* NET */
int pfsinv_num_nets( void )
{
	char *json_str = NULL;
	int num_nets = 0;
	num_nets = pfsinv_net_info(0,&json_str,(void **)NULL); 
	if (json_str)
		free(json_str);
	return num_nets;
}

int pfsinv_nets_show_json( void )
{
	char *json_str = NULL;
	int num_nets = 0;
	num_nets = pfsinv_net_info(PFSD_INV_FLAG_VERBOSE, (char **)NULL, (void **)NULL); 
	/*	num_nets = pfsinv_net_info(PFSD_INV_FLAG_VERBOSE, &json_str, (void **)NULL);  */

	if (json_str)
		free(json_str);
	return num_nets;
}

char *pfsinv_nets_get_json_str( void )
{
	char *json_str = NULL;
	pfsinv_net_info(0, &json_str, (void **)NULL);
	return json_str;
}

char *pfsinv_netstat_get_json_str( char *iface )
{
	char *json_str = NULL;
	pfsinv_netstat_info(0, &json_str, iface, (void **)NULL);
	return json_str;
}

char *pfsinv_net_interfaces_get_json_str(void)
{
	char *json_str = NULL;
	pfsinv_net_interfaces(0, &json_str, (void **)NULL);
	return json_str;
}



/* Combine everything into one big honking JSON string */
char *pfsinv_inventory_get_json_str( void )
{
	char *json_str = NULL;
	json_object *jobj;
	json_object *inventory_object;
	char dstr[256];
	const char *jstr = NULL;

	inventory_object = json_object_new_object();

	strcpy(dstr,"storage");
	jobj = pfsinv_drives_get_json_object();
	json_object_object_add(inventory_object, dstr, jobj);

	strcpy(dstr,"cpu");
	jobj = pfsinv_cpus_get_json_object();
	json_object_object_add(inventory_object, dstr, jobj);

	strcpy(dstr,"network");
	jobj = pfsinv_nets_get_json_object();
	json_object_object_add(inventory_object, dstr, jobj);

#if defined ENABLE_SCSI_HOST
	strcpy(dstr,"scsi_host");
	jobj = (json_object *)pfsinv_scsi_hosts_get_json_object();
	json_object_object_add(inventory_object, dstr, jobj);
#endif

	jstr = json_object_to_json_string(inventory_object);
	json_str = malloc(strlen(jstr)+32);
	strcpy(json_str, jstr);
	
	/* free the object */
	json_object_put(inventory_object);

	return json_str;
}

/*
 * **********************************************************************
 *
 * Function: int pfsinv_drive_info()
 *
 * Description:
 *
 * inputs: 
 * 	 unsigned int flags
 * 	 char **json_str
 *
 * returns:
 *
 * side effects:
 *
 * *********************************************************************
 */

int pfsinv_drive_info( unsigned int flags, char **json_str, void **jobj )
{
	int num_drives;
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry, *list_entry;
	struct udev_device *dev;
	json_object *drive_object;
	json_object *info_object;
	json_object *drive_list_object;
	char dstr[64];
	int verbose = flags & PFSD_INV_FLAG_VERBOSE;
	const char *jstr = NULL;
	char last_path[256];

	memset((void *)last_path,0,256);

	/* Create the udev object */
	udev = udev_new();
	if (!udev) {
		printf("Can't create udev\n");
		return(0);
	}
	
	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "block");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	num_drives = 0;

	drive_list_object = json_object_new_object();

	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path;
		const char *property;
		const char *value;
		const char *id_bus;
		char  cfpath[256];
		char  sg_generic_str[256];
		DIR *dirp;
		struct dirent *dp;

		/* Get the filename of the /sys entry for the device
		   and create a udev_device object (dev) representing it */
		path = udev_list_entry_get_name(dev_list_entry);
		if (verbose_debug)
			printf("path = %s\n", path);
		dev = udev_device_new_from_syspath(udev, path);
		/* usb_device_get_devnode() returns the path to the device node
		   itself in /dev. */

#if 0
		/* 
		   The scsi reference doesn't work for sata or nvme 
		*/

		dev = udev_device_get_parent_with_subsystem_devtype(
		       dev,
		       "scsi",
		       "scsi_device");
		if (!dev) {
			if ( verbose_debug ){
				printf("\tUnable to find parent device.\n");
			}
			continue;
		}

#endif

#if defined VERBOSE_DEBUG
		if ( verbose_debug )
			test_device(udev, path);
#endif
		dev = udev_device_new_from_syspath(udev, path);
		id_bus = udev_device_get_property_value(dev, "DEVTYPE");
		
		if (id_bus != NULL){
			if(strcmp(id_bus, "disk") == 0){

				/* To get around partitioned drives we'll just make sure
				   we haven't added the path already. This works by assuming
				   the drives will show up in order i.e. sda, sda1, sda2.
				   It should equal one of these two. Do SAS_PATH first since whatever is
				   running RHEL 7.2 has both but the phy number is only in SAS_PATH.
				*/
				property = udev_device_get_property_value(dev, "DEVPATH");

				if ( property == NULL ){
					property = udev_device_get_property_value(dev, "ID_PATH");
				}
				if ( property == NULL )
					continue;  /* should never hit this */
				if( strcmp(last_path, property) == 0 )
					continue;

#if !defined (DISK_SHOW_VIRTUAL_INTERFACES)
				/* check if we show virtual interfaces */
				if (strstr(property, "virtual") != NULL)
					continue;
#endif

				if ( verbose_debug )
					printf(" *** last_path=%s, property=%s\n", last_path, property);

				strncpy(last_path, property, 256);
				info_object = json_object_new_object();
				json_object_object_add(info_object, "path", json_object_new_string(property));
				if ( verbose_debug )
					printf("property: path=%s\n", property); 


				udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev)) {
					property = udev_list_entry_get_name(list_entry);
					value =    udev_list_entry_get_value(list_entry);
					if ( verbose_debug )
						printf("property: %s=%s\n", property, value); 
					if ( value != NULL )
						json_object_object_add(info_object, property, json_object_new_string(value));
				}

				udev_list_entry_foreach(list_entry, udev_device_get_sysattr_list_entry(dev)) {
					property = udev_list_entry_get_name(list_entry);
					value = udev_device_get_sysattr_value(dev, property);
					if ( verbose_debug )
						printf("sysattr: %s=%s\n", property, value); 
					if ( value != NULL )
						json_object_object_add(info_object, property, json_object_new_string(value));
				}

				/* SCSI generic name is buried */
				sprintf(cfpath,"%s/device/scsi_generic", path);

				if ( verbose_debug )
					printf("cfpath = %s\n", cfpath);
				dirp = opendir(cfpath);
				while (dirp) {
					if ((dp=readdir(dirp)) != NULL) {
						if ((strcmp(".",dp->d_name)==0) || (strcmp("..",dp->d_name)==0))
							continue;
						sprintf(sg_generic_str,"%s", dp->d_name);
						json_object_object_add(info_object, "scsi_generic", json_object_new_string(dp->d_name));
					}
					else {
						break;
					}
				}
				closedir(dirp);

				drive_object = json_object_new_object();
				json_object_object_add(drive_object,"info", info_object);

				sprintf(dstr,"drive%02d", num_drives);

				json_object_object_add(drive_list_object, dstr, drive_object);

				num_drives++;
			}
		}

		udev_device_unref(dev);
	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	if ( verbose ){
		if ( verbose_debug )
			printf (" ** Number of drives found = %d\n", num_drives);
		printf("%s\n", json_object_to_json_string(drive_list_object));
	}

	if (json_str != NULL) {
		jstr = json_object_to_json_string(drive_list_object);
		*json_str = malloc(strlen(jstr)+32);
		strcpy(*json_str, jstr);
	}

	if ( jobj != NULL )
		*jobj = drive_list_object;
	else
		json_object_put(drive_list_object);

	return num_drives;
}


/*
 * **********************************************************************
 *
 * Function:  int pfsinv_cpu_info()
 *
 * Description:
 *
 * inputs:
 * 	 unsigned int flags
 * 	 char **json_str
 *
 * returns:
 *
 * side effects:
 *
 * *********************************************************************
 */

int pfsinv_cpu_info( unsigned int flags, char **json_str, void **jobj )
{
	int num_cpus;
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry, *list_entry;
	struct udev_device *dev;
	json_object *cpu_object;
	json_object *info_object;
	json_object *cpu_list_object;
	char dstr[64];
	int verbose = flags & PFSD_INV_FLAG_VERBOSE;
	const char *jstr = NULL;

	/* Create the udev object */
	udev = udev_new();
	if (!udev) {
		printf("Can't create udev\n");
		return(0);
	}
	
	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "cpu");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	num_cpus = 0;

	cpu_list_object = json_object_new_object();

	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path;
		const char *property;
		const char *value;
		char  cfpath[256];
		char  tmppath[256];
		DIR *dirp;
		struct dirent *dp;
		char *subdirs[] = {"cpufreq", "cpuidle", "thermal_throttle","topology",
				   "microcode", "hotplug", "power", NULL};
		int sdidx;

		struct inv_dir_list  *dl_head = NULL;
		struct inv_dir_list  *dl_node = NULL;
		struct inv_dir_list  *dl_next = NULL;

		memset((void *)cfpath,0,256);

		/* Get the filename of the /sys entry for the device
		   and create a udev_device object (dev) representing it */
		path = udev_list_entry_get_name(dev_list_entry);
		if ( verbose_debug )
			printf("path = %s\n", path);
		dev = udev_device_new_from_syspath(udev, path);

		/* new info object */
		info_object = json_object_new_object();

		/* Build the inventory directory list for this device */
		init_inv_list ( &dl_head);
		dl_head = find_subdirs(path, dl_head);
#if 0
		for (dl_node = dl_head; dl_node; dl_node = dl_node->next){
			printf ("%s\n", dl_node->info->name);
		}
		print_inv_list(dl_head);
#endif

		/* 
                 * This will get everything at this level
		 */
		udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev)) {
			property = udev_list_entry_get_name(list_entry);
			value =    udev_list_entry_get_value(list_entry);
			if ( verbose_debug )
				printf("property: %s=%s\n", property, value); 
			if ( value != NULL )
				json_object_object_add(info_object, property, json_object_new_string(value));
		}

		udev_list_entry_foreach(list_entry, udev_device_get_sysattr_list_entry(dev)) {
			property = udev_list_entry_get_name(list_entry);
			value = udev_device_get_sysattr_value(dev, udev_list_entry_get_name(list_entry));
			if ( verbose_debug )
				printf("sysattr:  %s=%s\n", property, value);
			if ( value != NULL )
				json_object_object_add(info_object, property, json_object_new_string(value));
		}

		/*
		 * This bit of code will get the values that are in subdirectories
		 */
		path = udev_list_entry_get_name(dev_list_entry);

		for (dl_node = dl_head; dl_node; dl_node = dl_node->next){
			sprintf(cfpath,"%s", dl_node->info->name);
			if ( verbose_debug )
				printf("cfpath = %s\n", cfpath);
			dirp = opendir(cfpath);
			while (dirp) {
				if ((dp=readdir(dirp)) != NULL) {
					if ((strcmp(".",dp->d_name)==0) || (strcmp("..",dp->d_name)==0))
						continue;
					if (dp->d_type == DT_DIR )
						continue;
					char *cptr;
					memset(tmppath,0,256);
					sprintf(tmppath,"%s/%s", cfpath,dp->d_name);
					/* strip off the path */
					cptr = (char *)tmppath+strlen(path);
					value = udev_device_get_sysattr_value(dev,cptr);
					if ( verbose_debug )
						printf("%s=%s\n", cptr, value);
					if ( value != NULL ){
						json_object_object_add(info_object, cptr, json_object_new_string(value));
					}
					else {
						value = udev_device_get_property_value(dev,cptr);
						if ( value != NULL )
							json_object_object_add(info_object, cptr, json_object_new_string(value));
					}
				}
				else {
					break;
				}
			}
			closedir(dirp);
		}
		
		/* Free up the inventory directory list */
		free_inv_list(dl_head);

		cpu_object = json_object_new_object();
		json_object_object_add(cpu_object,"info", info_object);

		sprintf(dstr,"thread%02d", num_cpus);

		if ( verbose_debug )
			printf(" --  Adding %s\n", dstr);

		json_object_object_add(cpu_list_object, dstr, cpu_object);

		udev_device_unref(dev);

		num_cpus++;

	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	if ( verbose ){
		if ( verbose_debug )
			printf (" ** Number of cpus found = %d\n", num_cpus);
		printf("%s\n", json_object_to_json_string(cpu_list_object));
	}

	if (json_str != NULL) {
		jstr = json_object_to_json_string(cpu_list_object);
		*json_str = malloc(strlen(jstr)+32);
		strcpy(*json_str, jstr);
	}

	if ( jobj != NULL )
		*jobj = cpu_list_object;
	else
		json_object_put(cpu_list_object);

	return num_cpus;

}

/*
 * **********************************************************************
 *
 * Function:  int pfsinv_net_info()
 *
 * Description:
 *
 * inputs:
 * 	 unsigned int flags
 * 	 char **json_str
 * 	 void **jobj
 *
 * returns:
 *
 * side effects:
 * /sys/devices/pci0001:00/0001:00:00.0/0001:01:00.0/net/enP1p1s0# 
 *
 * *********************************************************************
 */

int pfsinv_net_info( unsigned int flags, char **json_str, void **jobj )
{
	int num_nets;
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry, *list_entry;
	struct udev_device *dev;
	json_object *net_object;
	json_object *info_object;
	json_object *net_list_object;
	json_object *statistics_object;
	json_object *bonding_object;
	char dstr[64];
	int verbose = flags & PFSD_INV_FLAG_VERBOSE;
	const char *jstr = NULL;
	int sock;

	/* Create the udev object */
	udev = udev_new();
	if (!udev) {
		printf("Can't create udev\n");
		return(0);
	}

	/* open a socket for ethtool */
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0) {
		perror("socket");
		printf("Opening socket failed");
		return 0;
	}
	
	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "net");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	num_nets = 0;

	net_list_object = json_object_new_object();


	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path;
		const char *property;
		const char *value;
		char  cfpath[256];
		DIR *dirp;
		struct dirent *dp;
		char netname[256];
		struct ethtool_drvinfo drvinfo;


		memset((void *)netname,0,256);
		memset((void *)cfpath,0,256);

		/* Get the filename of the /sys entry for the device
		   and create a udev_device object (dev) representing it */
		path = udev_list_entry_get_name(dev_list_entry);
		if ( verbose_debug )
			printf("path = %s\n", path);

#if !defined (NET_SHOW_VIRTUAL_INTERFACES)
		/* first check We're not counting lo or any virtual interfaces */
		/* bonds and lo are virtual ports */
		if (strstr(path, "virtual") != NULL)
			continue;
#endif
		dev = udev_device_new_from_syspath(udev, path);

		value = udev_device_get_property_value(dev, "INTERFACE");

		if ( value == NULL )
			continue;

		strcpy(netname, value);

		if ( verbose_debug )
			printf("netname = %s\n", netname);


		/* new info object */
		info_object = json_object_new_object();

		/* We cannot use udev to get the firmware and driver versions (that I know of)
		   but we can use ethtool !!
		   Virtual networks do not have firmware revisions yo.
		*/
		if ((sock >= 0) && (strstr(path, "virtual") == NULL)) {
			if ( pfsinv_get_eth_drvinfo( sock, netname, &drvinfo) > 0){
				fprintf(stderr, "Failure: reading driver information");
			}
			else {
				json_object_object_add(info_object, "driver", json_object_new_string(drvinfo.driver));
				json_object_object_add(info_object, "version", json_object_new_string(drvinfo.version));
				json_object_object_add(info_object, "firmware-version", json_object_new_string(drvinfo.fw_version));
				json_object_object_add(info_object, "bus-info", json_object_new_string(drvinfo.bus_info));
				if (verbose_debug)
					printf(	"driver: %.*s\n"
						"version: %.*s\n"
						"firmware-version: %.*s\n"
						"bus-info: %.*s\n",
						(int)sizeof(drvinfo.driver), drvinfo.driver,
						(int)sizeof(drvinfo.version), drvinfo.version,
						(int)sizeof(drvinfo.fw_version), drvinfo.fw_version,
						(int)sizeof(drvinfo.bus_info), drvinfo.bus_info );
			}
		}

		udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev)) {
			property = udev_list_entry_get_name(list_entry);
			value =    udev_list_entry_get_value(list_entry);
			if ( verbose_debug )
				printf("property: %s=%s\n", property, value); 
			if ( value != NULL )
				if (is_ascii((const char *)value, strlen(value)))
						   json_object_object_add(info_object, property, json_object_new_string(value));
		}

		udev_list_entry_foreach(list_entry, udev_device_get_sysattr_list_entry(dev)) {
			property = udev_list_entry_get_name(list_entry);
			value = udev_device_get_sysattr_value(dev, udev_list_entry_get_name(list_entry));
			if ( verbose_debug )
				printf("sysattr:  %s=%s\n", property, value);
			if ( value != NULL )
				if (is_ascii((const char *)value, strlen(value)))
					json_object_object_add(info_object, property, json_object_new_string(value));
		}

		/*
		 * I cannot figure out how to use the library to get attributes that are in
		 * subdirectories. For "cpufreq" we'll use readdir to list the directory and 
		 * read the attributes (which are files in the cpufreq direcectory).
		 */
		path = udev_list_entry_get_name(dev_list_entry);
		sprintf(cfpath,"%s/statistics", path);

		if ( verbose_debug )
			printf("cfpath = %s\n", cfpath);
		dirp = opendir(cfpath);

		statistics_object = json_object_new_object();

		while (dirp) {
			if ((dp=readdir(dirp)) != NULL) {
				if ((strcmp(".",dp->d_name)==0) || (strcmp("..",dp->d_name)==0))
					continue;
				sprintf(cfpath,"statistics/%s", dp->d_name);
				if ( verbose_debug )
					printf("cfpath = %s\n", cfpath);

				value = udev_device_get_sysattr_value(dev,cfpath);
				if ( verbose_debug )
					printf("%s=%s\n", cfpath, value);
				if ( value != NULL )
					json_object_object_add(statistics_object, dp->d_name, json_object_new_string(value));
			}
			else {
				break;
			}
		}

		json_object_object_add(info_object,"statistics", statistics_object);
		closedir(dirp);

			
		/*
		 * Bonding
		 */
		sprintf(cfpath,"%s/bonding", path);

		if ( verbose_debug )
			printf("cfpath = %s\n", cfpath);

		dirp = opendir(cfpath);

		/* printf("cfpath = %s, dirp=0x%x\n", cfpath, dirp); */
		if (dirp) {
			bonding_object = json_object_new_object();

			while (dirp) {
				if ((dp=readdir(dirp)) != NULL) {
					if ((strcmp(".",dp->d_name)==0) || (strcmp("..",dp->d_name)==0))
						continue;
					sprintf(cfpath,"bonding/%s", dp->d_name);
					value = udev_device_get_sysattr_value(dev,cfpath);
					if ( verbose_debug )
						printf("%s=%s\n", cfpath, value);
					if ( value != NULL )
						json_object_object_add(bonding_object, dp->d_name, json_object_new_string(value));
				}
				else {
					break;
				}
			}

			json_object_object_add(info_object,"bonding", bonding_object);
			closedir(dirp);
		}

		net_object = json_object_new_object();
		json_object_object_add(net_object,"info", info_object);

		sprintf(dstr,"net%02d", num_nets);

		if ( verbose_debug )

			printf(" --  Adding %s\n", dstr);

		json_object_object_add(net_list_object, dstr, net_object);

		udev_device_unref(dev);

		num_nets++;

	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	if ( verbose ){
		if ( verbose_debug )
			printf (" ** Number of nets found = %d\n", num_nets);
		printf("%s\n", json_object_to_json_string(net_list_object));
	}

	if (json_str != NULL) {
		jstr = json_object_to_json_string(net_list_object);
		*json_str = malloc(strlen(jstr)+32);
		strcpy(*json_str, jstr);
	}

	if ( jobj != NULL )
		*jobj = net_list_object;
	else
		json_object_put(net_list_object);

	if (sock >= 0)
		close(sock);

	return num_nets;

}

/*
 * **********************************************************************
 *
 * Function:  int pfsinv_netstat_info()
 *
 * Description:
 *
 * inputs:
 * 	 unsigned int flags
 * 	 char **json_str
 *       char *iface 
 * 	 void **jobj
 *
 * returns:
 *
 * side effects:
 * /sys/devices/pci0001:00/0001:00:00.0/0001:01:00.0/net/enP1p1s0# 
 *
 * *********************************************************************
 */

static int pfsinv_netstat_info( unsigned int flags, char **json_str, char *iface, void **jobj )
{
	int num_nets;
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry;
	struct udev_device *dev;
	json_object *info_object;
	json_object *net_list_object;
	json_object *statistics_object;
	int verbose = flags & PFSD_INV_FLAG_VERBOSE;
	const char *jstr = NULL;
	int sock;

	/* Create the udev object */
	udev = udev_new();
	if (!udev) {
		printf("Can't create udev\n");
		return(0);
	}

	/* open a socket for ethtool */
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0) {
		perror("socket");
		printf("Opening socket failed");
		return 0;
	}
	
	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "net");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	num_nets = 0;

	net_list_object = json_object_new_object();


	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path;
		const char *value;
		char  cfpath[256];
		DIR *dirp;
		struct dirent *dp;
		char netname[256];


		memset((void *)netname,0,256);
		memset((void *)cfpath,0,256);

		/* Get the filename of the /sys entry for the device
		   and create a udev_device object (dev) representing it */
		path = udev_list_entry_get_name(dev_list_entry);
		if ( verbose_debug )
			printf("path = %s\n", path);

#if !defined (NET_SHOW_VIRTUAL_INTERFACES)
		/* first check We're not counting lo or any virtual interfaces */
		/* bonds and lo are virtual ports */
		if (strstr(path, "virtual") != NULL)
			continue;
#endif
		dev = udev_device_new_from_syspath(udev, path);

		value = udev_device_get_property_value(dev, "INTERFACE");

		if ( value == NULL || strcmp(value, iface))
			continue;

		strcpy(netname, value);

		if ( verbose_debug )
			printf("netname = %s\n", netname);


		/* new info object */
		info_object = json_object_new_object();

		/* We cannot use udev to get the firmware and driver versions (that I know of)
		   but we can use ethtool !!
		*/

		/*
		 * I cannot figure out how to use the library to get attributes that are in
		 * subdirectories. For "cpufreq" we'll use readdir to list the directory and 
		 * read the attributes (which are files in the cpufreq direcectory).
		 */
		path = udev_list_entry_get_name(dev_list_entry);
		sprintf(cfpath,"%s/statistics", path);

		if ( verbose_debug )
			printf("cfpath = %s\n", cfpath);
		dirp = opendir(cfpath);

		statistics_object = json_object_new_object();

		while (dirp) {
			if ((dp=readdir(dirp)) != NULL) {
				if ((strcmp(".",dp->d_name)==0) || (strcmp("..",dp->d_name)==0))
					continue;
				sprintf(cfpath,"statistics/%s", dp->d_name);
				value = udev_device_get_sysattr_value(dev,cfpath);
				if ( verbose_debug )
					printf("%s=%s\n", cfpath, value);
				if ( value != NULL )
					json_object_object_add(statistics_object, dp->d_name, json_object_new_string(value));
			}
			else {
				break;
			}
		}
		closedir(dirp);

		json_object_object_add(info_object,"statistics", statistics_object);

#if 0
		net_object = json_object_new_object();
		json_object_object_add(net_object,"info", info_object);
		json_object_object_add(net_list_object, iface, net_object);
#else
		json_object_object_add(net_list_object, iface, info_object);
#endif

		udev_device_unref(dev);

		num_nets++;
		
		/* we found it so get out */
		break;

	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	if ( verbose ){
		if ( verbose_debug )
			printf (" ** Number of nets found = %d\n", num_nets);
		printf("%s\n", json_object_to_json_string(net_list_object));
	}

	if (json_str != NULL) {
		jstr = json_object_to_json_string(net_list_object);
		*json_str = malloc(strlen(jstr)+32);
		strcpy(*json_str, jstr);
	}

	if ( jobj != NULL )
		*jobj = net_list_object;
	else
		json_object_put(net_list_object);

	if (sock >= 0)
		close(sock);

	return num_nets;

}

/*
 * **********************************************************************
 *
 * Function:  int pfsinv_net_interfaces()
 *
 * Description:
 *
 * inputs:
 * 	 unsigned int flags
 * 	 char **json_str
 * 	 void **jobj
 *
 * returns:
 *
 * side effects:
 * /sys/devices/pci0001:00/0001:00:00.0/0001:01:00.0/net/enP1p1s0# 
 *
 * *********************************************************************
 */

static int pfsinv_net_interfaces( unsigned int flags, char **json_str, void **jobj )
{
	int num_nets;
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry;
	struct udev_device *dev;
	json_object *info_object;
	json_object *net_list_object;
	char dstr[64];
	int verbose = flags & PFSD_INV_FLAG_VERBOSE;
	const char *jstr = NULL;
	int sock;

	/* Create the udev object */
	udev = udev_new();
	if (!udev) {
		printf("Can't create udev\n");
		return(0);
	}

	/* open a socket for ethtool */
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0) {
		perror("socket");
		printf("Opening socket failed");
		return 0;
	}
	
	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "net");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	num_nets = 0;

	net_list_object = json_object_new_object();

	/* new info object */
	info_object = json_object_new_object();

	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path;
		const char *value;
		char  cfpath[256];
		char netname[256];

		memset((void *)netname,0,256);
		memset((void *)cfpath,0,256);

		/* Get the filename of the /sys entry for the device
		   and create a udev_device object (dev) representing it */
		path = udev_list_entry_get_name(dev_list_entry);
		if ( verbose_debug )
			printf("path = %s\n", path);

#if !defined (NET_SHOW_VIRTUAL_INTERFACES)
		/* first check We're not counting lo or any virtual interfaces */
		/* bonds and lo are virtual ports */
		if (strstr(path, "virtual") != NULL)
			continue;
#endif
		dev = udev_device_new_from_syspath(udev, path);

		value = udev_device_get_property_value(dev, "INTERFACE");

		if ( value == NULL)
			continue;

		strcpy(netname, value);

		if ( verbose_debug )
			printf("netname = %s\n", netname);

		sprintf(dstr,"net%02d", num_nets);

		json_object_object_add(info_object, dstr, json_object_new_string(value));

		udev_device_unref(dev);

		num_nets++;

	}

	json_object_object_add(net_list_object, "interfaces", info_object);

	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	if ( verbose ){
		if ( verbose_debug )
			printf (" ** Number of nets found = %d\n", num_nets);
		printf("%s\n", json_object_to_json_string(net_list_object));
	}

	if (json_str != NULL) {
		jstr = json_object_to_json_string(net_list_object);
		*json_str = malloc(strlen(jstr)+32);
		strcpy(*json_str, jstr);
	}

	if ( jobj != NULL )
		*jobj = net_list_object;
	else
		json_object_put(net_list_object);

	if (sock >= 0)
		close(sock);

	return num_nets;

}

/*
 Static functions
*/

static int pfsinv_get_eth_drvinfo( int sock, char *if_name, struct ethtool_drvinfo *drvinfo)
{
    struct ifreq ifr;
    /* struct ethtool_cmd edata; */
    int rc;

    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

#if 0
    ifr.ifr_data = &edata;
    edata.cmd = ETHTOOL_GDRVINFO;
#else
    ifr.ifr_data = drvinfo;
    drvinfo->cmd = ETHTOOL_GDRVINFO;
#endif

    rc = ioctl(sock, SIOCETHTOOL, &ifr);
    if (rc < 0) {
	    perror("ioctl");
	    return 1;
    }

    return 0;
}


static json_object *pfsinv_drives_get_json_object( void )
{
	char *json_str = NULL;
	json_object *jobj;
	pfsinv_drive_info(0, &json_str, (void **)&jobj);
	return jobj;
}

static json_object *pfsinv_cpus_get_json_object( void )
{
	char *json_str = NULL;
	json_object *jobj;
	pfsinv_cpu_info(0, &json_str, (void **)&jobj);
	return jobj;
}

static json_object *pfsinv_nets_get_json_object( void )
{
	char *json_str = NULL;
	json_object *jobj;
	pfsinv_net_info(0, &json_str, (void **)&jobj);
	return jobj;
}


static int is_ascii(const signed char *c, size_t len)
{
  size_t i;
	for (i = 0; i < len; i++) {
		if(c[i] < 0) return 0;
	}
	return 1;
}

static void init_inv_list ( struct inv_dir_list **head)
{
	*head=NULL;
}

static struct inv_dir_list  *add_inv_list ( struct inv_dir_list *node, struct inv_dir_info *info)
{
	struct inv_dir_list *tmpnode = (struct inv_dir_list *)malloc(sizeof(struct inv_dir_list));
	tmpnode->info = info;
	tmpnode->next = node;
	node = tmpnode;
	return node;
}


static void print_inv_list(struct inv_dir_list *head)
{
	struct inv_dir_list *temp;
	for (temp = head; temp; temp = temp->next)
		printf(" ******** %s\n", temp->info->name);
}

static void free_inv_list(struct inv_dir_list *head)
{
	struct inv_dir_list *temp, *tf;
	for (temp = head; temp; ){
		free(temp->info->name);
		free(temp->info);
		tf = temp;
		temp = temp->next;
		free(tf);
	}
}


#if defined VERBOSE_DEBUG
static void print_device(struct udev_device *device)
{
        const char *str;
        dev_t devnum;
        int count;
        struct udev_list_entry *list_entry;

        printf("*** device: %p ***\n", device);
        str = udev_device_get_action(device);
        if (str != NULL)
                printf("action:    '%s'\n", str);

        str = udev_device_get_syspath(device);
        printf("syspath:   '%s'\n", str);

        str = udev_device_get_sysname(device);
        printf("sysname:   '%s'\n", str);

        str = udev_device_get_sysnum(device);
        if (str != NULL)
                printf("sysnum:    '%s'\n", str);

        str = udev_device_get_devpath(device);
        printf("devpath:   '%s'\n", str);

        str = udev_device_get_subsystem(device);
        if (str != NULL)
                printf("subsystem: '%s'\n", str);

        str = udev_device_get_devtype(device);
        if (str != NULL)
                printf("devtype:   '%s'\n", str);

        str = udev_device_get_driver(device);
        if (str != NULL)
                printf("driver:    '%s'\n", str);

        str = udev_device_get_devnode(device);
        if (str != NULL)
                printf("devname:   '%s'\n", str);

        devnum = udev_device_get_devnum(device);
        if (major(devnum) > 0)
                printf("devnum:    %u:%u\n", major(devnum), minor(devnum));

        count = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device)) {
                printf("link:      '%s'\n", udev_list_entry_get_name(list_entry));
                count++;
        }
        if (count > 0)
                printf("found %i links\n", count);

        count = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_sysattr_list_entry(device)) {
                printf("sysattr:  '%s=%s'\n",
                       udev_list_entry_get_name(list_entry),
                       udev_list_entry_get_value(list_entry));
                count++;
        }
        if (count > 0)
                printf("found %i sysattr\n", count);

        count = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device)) {
                printf("properties:  '%s=%s'\n",
                       udev_list_entry_get_name(list_entry),
                       udev_list_entry_get_value(list_entry));
                count++;
        }
        if (count > 0)
                printf("found %i properties\n", count);

        str = udev_device_get_property_value(device, "MAJOR");
        if (str != NULL)
                printf("MAJOR: '%s'\n", str);

        str = udev_device_get_sysattr_value(device, "dev");
        if (str != NULL)
                printf("attr{dev}: '%s'\n", str);

        printf("\n");
}

static void print_properties(struct udev_device *device)
{
        const char *str;
        int count;
        struct udev_list_entry *list_entry;

        printf("*** print properties for device: %p ***\n", device);

        count = 0;
        udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(device)) {
                printf("property:  '%s=%s'\n",
                       udev_list_entry_get_name(list_entry),
                       udev_list_entry_get_value(list_entry));
                count++;
        }
        if (count > 0)
                printf("found %i properties\n", count);

        str = udev_device_get_property_value(device, "ID_VENDOR");
        if (str != NULL)
                printf("ID_VENDOR: '%s'\n", str);

        str = udev_device_get_sysattr_value(device, "dev");
        if (str != NULL)
                printf("attr{dev}: '%s'\n", str);

        printf("\n");
}

static void print_sysattr(struct udev_device *device)
{
        const char *str_name;
        const char *str_value;
        int count;
        struct udev_list_entry *list_entry;

        printf("*** print sysattr for device: %p ***\n", device);

        count = 0;

	udev_list_entry_foreach(list_entry, udev_device_get_sysattr_list_entry(device)) {
		str_name = udev_list_entry_get_name(list_entry);
		str_value = udev_device_get_sysattr_value(device, udev_list_entry_get_name(list_entry));
                printf("sysattr:  '%s=%s'\n", str_name, str_value);
                count++;
        }
        if (count > 0)
                printf("found %i sysattrs\n", count);

        printf("\n");
}

static int test_device(struct udev *udev, const char *syspath)
{
        struct udev_device *device;

        printf("looking at device: %s\n", syspath);
        device = udev_device_new_from_syspath(udev, syspath);
        if (device == NULL) {
                printf("no device found\n");
                return -1;
        }
        print_device(device);
        udev_device_unref(device);
        return 0;
}

static int test_device_parents(struct udev *udev, const char *syspath)
{
        struct udev_device *device;
        struct udev_device *device_parent;

        printf("looking at device: %s\n", syspath);
        device = udev_device_new_from_syspath(udev, syspath);
        if (device == NULL)
                return -1;

        printf("looking at parents\n");
        device_parent = device;
        do {
                print_device(device_parent);
                device_parent = udev_device_get_parent(device_parent);
        } while (device_parent != NULL);
#if 0
        printf("looking at parents again\n");
        device_parent = device;
        do {
                print_device(device_parent);
                device_parent = udev_device_get_parent(device_parent);
        } while (device_parent != NULL);
        udev_device_unref(device);
#endif

        return 0;
}

#endif
