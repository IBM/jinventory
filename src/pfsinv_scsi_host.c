/*
 *  "pfsinv_scsi_host.c" 
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

static int verbose_debug = 0;

#define PFSD_INV_FLAG_VERBOSE  (1<<0)

int pfsinv_num_scsi_hosts( void )
{
	char *json_str = NULL;
	int num_scsi_hosts = 0;
	num_scsi_hosts = pfsinv_scsi_host_info(0,&json_str,(void **)NULL); 
	if (json_str)
		free(json_str);
	return num_scsi_hosts;
}

int pfsinv_scsi_hosts_show_json( void )
{
	char *json_str = NULL;
	int num_scsi_hosts = 0;
	num_scsi_hosts = pfsinv_scsi_host_info(PFSD_INV_FLAG_VERBOSE, (char **)NULL, (void **)NULL); 
	/*	num_scsi_hosts = pfsinv_scsi_host_info(PFSD_INV_FLAG_VERBOSE, &json_str, (void **)NULL);  */

	if (json_str)
		free(json_str);
	return num_scsi_hosts;
}

char *pfsinv_scsi_hosts_get_json_str( void )
{
	char *json_str = NULL;
	pfsinv_scsi_host_info(0, &json_str, (void **)NULL);
	return json_str;
}

void *pfsinv_scsi_hosts_get_json_object( void )
{
	char *json_str = NULL;
	json_object *jobj;
	pfsinv_scsi_host_info(0, &json_str, (void **)&jobj);
	return (void *)jobj;
}

/*
 * **********************************************************************
 *
 * Function:  int pfsinv_scsi_host_info()
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
int pfsinv_scsi_host_info( unsigned int flags, char **json_str, void **jobj )
{
	int num_scsi_hosts;
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry, *list_entry;
	struct udev_device *dev;
	json_object *scsi_host_object;
	json_object *info_object;
	json_object *scsi_host_list_object;
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
	udev_enumerate_add_match_subsystem(enumerate, "scsi_host");
	/* filter out the USB devices */
	udev_enumerate_add_nomatch_sysattr(enumerate, "proc_name","usb-storage");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	num_scsi_hosts = 0;

	scsi_host_list_object = json_object_new_object();

	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path;
		const char *property;
		const char *value;
		char  cfpath[256];

		memset((void *)cfpath,0,256);

		/* Get the filename of the /sys entry for the device
		   and create a udev_device object (dev) representing it */
		path = udev_list_entry_get_name(dev_list_entry);
		if ( verbose_debug )
			printf("path = %s\n", path);
		dev = udev_device_new_from_syspath(udev, path);

		/* new info object */
		info_object = json_object_new_object();

		 
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


		scsi_host_object = json_object_new_object();
		json_object_object_add(scsi_host_object,"info", info_object);

		sprintf(dstr,"scsi_host%02d", num_scsi_hosts);

		if ( verbose_debug )
			printf(" --  Adding %s\n", dstr);

		json_object_object_add(scsi_host_list_object, dstr, scsi_host_object);

		udev_device_unref(dev);

		num_scsi_hosts++;

	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	if ( verbose ){
		if ( verbose_debug )
			printf (" ** Number of scsi_hosts found = %d\n", num_scsi_hosts);
		printf("%s\n", json_object_to_json_string(scsi_host_list_object));
	}

	if (json_str != NULL) {
		jstr = json_object_to_json_string(scsi_host_list_object);
		*json_str = malloc(strlen(jstr)+32);
		strcpy(*json_str, jstr);
	}

	if ( jobj != NULL )
		*jobj = scsi_host_list_object;
	else
		json_object_put(scsi_host_list_object);

	return num_scsi_hosts;

}
