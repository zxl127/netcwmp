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

#include "cwmp_module.h"
#include <cwmp/cfg.h>



void cwmp_conf_init(cwmp_t * cwmp)
{
    pool_t * pool;
    FUNCTION_TRACE();

    pool = cwmp->pool;
    cwmp->httpd_port =  cwmp_conf_get_int("cwmpd:httpd_port");

    cwmp->acs_auth  =   cwmp_conf_get_int("cwmp:acs_auth");
    cwmp->cpe_auth  =   cwmp_conf_get_int("cwmp:cpe_auth");

    if(cwmp->acs_auth)
    {
        cwmp->acs_user = cwmp_conf_pool_get(pool, "cwmp:acs_username");
        cwmp->acs_pwd = cwmp_conf_pool_get(pool, "cwmp:acs_password");
    }

	if(cwmp->cpe_auth)
	{
	    cwmp->cpe_user = cwmp_conf_pool_get(pool, "cwmp:cpe_username");
    	cwmp->cpe_pwd = cwmp_conf_pool_get(pool, "cwmp:cpe_password");
	}

    cwmp->acs_url   =   cwmp_conf_pool_get(pool, "cwmp:acs_url");

    cwmp->cpe_mf    =   cwmp_conf_pool_get(pool, "cwmp:cpe_manufacture"); 

    cwmp->cpe_oui   =   cwmp_conf_pool_get(pool, "cwmp:cpe_oui"); 

    cwmp->cpe_sn    =   cwmp_conf_pool_get(pool, "cwmp:cpe_sn");

    cwmp->cpe_name  =   cwmp_conf_pool_get(pool, "cwmp:cpe_name");

    cwmp->cpe_pc    =   cwmp_conf_pool_get(pool, "cwmp:cpe_pc");

    cwmp->cpe_httpd_ip  =   cwmp_conf_pool_get(pool, "cwmpd:httpd_ip"); 

    cwmp_log_debug("url:%s\nmf:%s\noui:%s\nsn:%s\nname:%s\npc:%s\nhttpd ip=%s port:%d\n",
                    cwmp->acs_url, cwmp->cpe_mf, cwmp->cpe_oui, 
                    cwmp->cpe_sn, cwmp->cpe_name, cwmp->cpe_pc,
					cwmp->cpe_httpd_ip,
                    cwmp->httpd_port);


    cwmp->event_filename = cwmp_conf_pool_get(pool, "cwmp:event_filename");
	cwmp_log_debug("event_filename=%s", cwmp->event_filename);
}

