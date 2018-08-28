/*
 *  "pfsd-common.h" 
 *
 *  (c) COPYRIGHT 2016 IBM Corp.
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

#if !defined (__PFSINV_COMMON_H__)
#define __PFSINV_COMMON_H__

/*
 * Comment out to not show virtual interfaces. Be aware that bond interfaces
 * are considered virtual.
 */
#define NET_SHOW_VIRTUAL_INTERFACES

struct pfsinv_dpdr_info {
	struct dp_ioc_attr *dpi;
	int fd;
};
	
struct pfsinv_info {
	unsigned long long data;
	int num_drives;
	struct pfsinv_dpdr_info  *dpdri;
};


/* pfsinv_inventory.c */
int pfsinv_drive_info( unsigned int flags, char **json_str, void **jobj );
int pfsinv_num_drives( void );
int pfsinv_drives_show_json( void );
char *pfsinv_drives_get_json_str( void );

int pfsinv_cpu_info( unsigned int flags, char **json_str, void **jobj );
int pfsinv_num_cpus( void );
int pfsinv_cpus_show_json( void );
char *pfsinv_cpus_get_json_str( void );

int pfsinv_net_info( unsigned int flags, char **json_str, void **jobj );
int pfsinv_num_nets( void );
int pfsinv_nets_show_json( void );
char *pfsinv_nets_get_json_str( void );

int pfsinv_num_sas_phys( void );
int pfsinv_sas_phys_show_json( void );
char *pfsinv_sas_phys_get_json_str( void );
int pfsinv_sas_phy_info( unsigned int flags, char **json_str, void **jobj );

int pfsinv_num_scsi_hosts( void );
int pfsinv_scsi_hosts_show_json( void );
char *pfsinv_scsi_hosts_get_json_str( void );
int pfsinv_scsi_host_info( unsigned int flags, char **json_str, void **jobj );
void *pfsinv_scsi_hosts_get_json_object( void );

char *pfsinv_inventory_get_json_str( void );
char *pfsinv_netstat_get_json_str( char *iface );
char *pfsinv_net_interfaces_get_json_str(void);

#endif /* __PFSINV_COMMON_H__ */
