/************************************************************************
 *                                                                      *
 * Netcwmp/Opencwmp Project                                             *
 * A software client for enabling TR-069 in embedded devices (CPE).     *
 *                                                                      *
 * Copyright (C) 2013-2014  netcwmp.netcwmp group                            *
 *                                                                      *
 * This program is free software; you can redistribute it and/or        *
 * modify it under the terms of the GNU General Public License          *
 * as published by the Free Software Foundation; either version 2       *
 * of the License, or (at your option) any later version.               *
 *                                                                      *
 * This program is distributed in the hope that it will be useful,      *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 * GNU General Public License for more details.                         *
 *                                                                      *
 * You should have received a copy of the GNU Lesser General Public     *
 * License along with this library; if not, write to the                *
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,          *
 * Boston, MA  02111-1307 USA                                           *
 *                                                                      *
 * Copyright 2013-2014  Mr.x(Mr.x) <netcwmp@gmail.com>          *
 *                                                                      *
 ***********************************************************************/

#include "cwmpd.h"
#include <unistd.h>
#include <signal.h>

#define CWMP_VALUE_UNSET -1

int              cwmp_argc;
char           **cwmp_argv;

void cwmp_daemon()
{
    //daemon(0, 1);
}

void cwmp_getopt(int argc, char **argv)
{
    
}

static int cwmp_save_argv( int argc, char *const *argv)
{
    cwmp_argv = (char **) argv;
    cwmp_argc = argc;

    return 0;
}

int cwmp_set_var(cwmp_t * cwmp)
{
    FUNCTION_TRACE();

    cwmp_event_init(cwmp);

    return CWMP_OK;
}

#ifdef USE_CWMP_OPENSSL
void cwmp_init_ssl(cwmp_t * cwmp)
{
    char * cafile = cwmp_conf_pool_get(cwmp->pool, "cwmp:ca_file");
    char * capasswd = cwmp_conf_pool_get(cwmp->pool, "cwmp:ca_password");   
    cwmp->ssl_ctx = openssl_initialize_ctx(cafile, capasswd);
}
#endif

int read_file_data(const char *fileName, char *buffer, int buf_size)
{
	int n;
	FILE *fp;

	if(buffer==NULL || buf_size<=0)
		return 0;

	buffer[0]='\0';

	fp = fopen((char *)fileName, "rb");
	if(fp == NULL)
		return 0;
	else{
		n = fread(buffer, 1, buf_size-1, fp);
		fclose(fp);
	}

	buffer[n]='\0';

	return n;
}

int get_cwmp_log_level(void)
{
	int n;
	char buf[64];

	n = read_file_data("/tmp/cwmp_log_level", buf, sizeof(buf)-1);
	if(n <= 0)
		return CWMP_LOG_NOTICE;

	return atoi(buf);
}

int main(int argc, char **argv)
{
    cwmp_pid_t pid;
    cwmp_t *cwmp = NULL;
    pool_t *pool = NULL;

#ifdef WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    pid = getpid();
    signal(SIGPIPE, SIG_IGN);

	printf("cwmpd built at %s %s\r\n", __DATE__, __TIME__);

	//cwmp_log_init("/var/log/cwmpd.log", CWMP_LOG_DEBUG);
	//cwmp_log_init(NULL, get_cwmp_log_level());
    cwmp_log_init(NULL, CWMP_LOG_DEBUG);
	
    pool = pool_create(POOL_DEFAULT_SIZE);
    cwmp = pool_palloc(pool, sizeof(cwmp_t));
	cwmp_bzero(cwmp, sizeof(cwmp_t));
	cwmp->new_request = CWMP_TRUE;
	cwmp->pool = pool;
    cwmp->task_priority = task_queue_create(cwmp->pool);
    cwmp->task_time = task_queue_create(cwmp->pool);

    cwmp_conf_open("cwmp.conf");
    cwmp_conf_init(cwmp);
    
    if(!cwmp_conf_get_int("cwmp:enable"))
        exit(-1);    

    cwmp_getopt(argc, argv);
    cwmp_daemon();
    cwmp_set_var(cwmp);

#ifdef USE_CWMP_OPENSSL
    cwmp_init_ssl(cwmp);
#endif

    cwmp_log_debug("data_model: device.xml");
    cwmp_model_load(cwmp, "device.xml");

	if(access(TR069_UPDATE_REBOOT_FLAG, F_OK) < 0 &&
		access(TR069_REBOOT_FLAG, F_OK) < 0){
		cwmp_log_debug("Not tr069_update_then_reboot and tr069_reboot");
		
	    if (access(TR069_BOOTSTRAP_FLAG, F_OK) < 0)
	    {
	    	cwmp_log_debug("TR069 INFORM_BOOTSTRAP.");
	        clear_and_cwmp_event_set_value(cwmp, INFORM_BOOTSTRAP, 1, NULL, 0, 0, 0);
	    }
	    else
	    {
	    	cwmp_log_debug("TR069 INFORM_BOOT.");
	        clear_and_cwmp_event_set_value(cwmp, INFORM_BOOT, 1, NULL, 0, 0, 0);
	    }
    }
    else {
	    cwmp_log_debug("Is tr069_update_then_reboot or tr069_reboot");
    	if (access(TR069_REBOOT_FLAG, F_OK) >= 0) {
    		remove(TR069_REBOOT_FLAG);
    	}
    }
	
    cwmp_process_start_master(cwmp);

    return 0;
}



