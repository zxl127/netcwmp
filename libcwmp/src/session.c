/************************************************************************
 * Id: session.c                                                        *
 *                                                                      *
 * TR069 Project:  A TR069 library in C                                 *
 * Copyright (C) 2013-2014 netcwmp group                                *
 *                                                                      *
 *                                                                      *
 * Email: netcwmp ( & ) gmail dot com                                *
 *                                                                      *
 ***********************************************************************/


#include "cwmp/session.h"
#include "cwmp/cfg.h"
#include "cwmp/log.h"
#include "cwmp/cwmp.h"
#include "cwmp_private.h"



static cwmp_uint32_t g_cwmp_session_sequence = 0;
static char g_cwmp_session_sequence_buffer[64];

static char * rpc_methods[] =
{
    "GetRPCMethods",
    "SetParameterValues",
    "GetParameterValues",
    "GetParameterNames",
   "SetParameterAttributes",
   "GetParameterAttributes",
    "AddObject",
    "DeleteObject",
    "Download",
    "Upload",
    "Reboot",
    "FactoryReset",
    "Inform"
};

char * cwmp_data_get_parameter_value(cwmp_t * cwmp, parameter_node_t * root, const char * name, pool_t * pool)
{
    parameter_node_t * node;
    char * value = NULL;
    int rc;


    node = cwmp_get_parameter_node(root, name);
    if (!node)
        return NULL;


     rc = cwmp_get_parameter_node_value(cwmp, node, name, &value, pool);
     if(rc == 0)
     {
	return value;
     }

     else
     {
	return node->value;
     }

}

int cwmp_data_set_parameter_value(cwmp_t * cwmp, parameter_node_t * root, const char * name, const char * value, int value_length, pool_t * pool)
{
    parameter_node_t * node;

    node = cwmp_get_parameter_node(root, name);
    if (!node)
        return CWMP_ERROR;
    return cwmp_set_parameter_node_value(cwmp, node, name, value, value_length);

}







char * cwmp_session_get_sequence(pool_t * pool)
 {
    g_cwmp_session_sequence++;
    TRsnprintf(g_cwmp_session_sequence_buffer, 63, "%d", g_cwmp_session_sequence);
    return g_cwmp_session_sequence_buffer;
}

int cwmp_session_get_localip(char *hostip)
{
#ifdef WIN32
    /*    struct sockaddr addr;
    	SOCKET fd;
    	char local_ip_addr[20] = {0};
    	int len = sizeof(addr);
        ZeroMemory( &addr, sizeof(addr) );


    	if(!hostip)
                return -1;

    	if((fd=socket(AF_INET,SOCK_DGRAM,0))>=0)
        {
    		if( getsockname( fd, &addr, &len ) )
    		{
    			len = WSAGetLastError();
    		}

    		TRsnprintf(local_ip_addr, 20, "%s", inet_ntoa( ((struct sockaddr_in*)&addr)->sin_addr ));
    		TRstrcpy(hostip, local_ip_addr);
    	}
    */

    char hostname[256];

    struct hostent* pHostent;

    struct sockaddr_in sa;

    struct hostent he;
    int i;

    int res = gethostname(hostname, sizeof(hostname));
    if (res != 0)
    {
        cwmp_log_error("Error: %u\n", WSAGetLastError());
        return -1;
    }
    cwmp_log_debug("hostname=%s\n", hostname);
    ////////////////
    // ������������ȡ������Ϣ.
    //


    pHostent = gethostbyname(hostname);


    if (pHostent==NULL)
    {
        cwmp_log_error("Error: %u\n", WSAGetLastError());
        return -1;
    }
    //////////////////
    // ���򷵻ص�hostent��Ϣ.
    //

    he = *pHostent;


    cwmp_log_debug("name=%s\naliases=%s\naddrtype=%d\nlength=%d\n",
                   he.h_name, he.h_aliases, he.h_addrtype, he.h_length);


    for (i=0; he.h_addr_list[i]; i++)
    {
        memcpy ( &sa.sin_addr.s_addr, he.h_addr_list[i],he.h_length);
        // ����������IP��ַ.
        cwmp_log_debug("Address: %s\n", inet_ntoa(sa.sin_addr)); // ��ʾ��ַ��
        TRsnprintf(hostip, 20, "%s", inet_ntoa(sa.sin_addr));
        break;
    }






#else
    register int fd,intrface,retn=0;
    struct ifreq buf[32];
    struct ifconf ifc;
    char domain_host[100] = {0};
    char local_ip_addr[20] = {0};
    char local_mac[20] = {0};
    //Get Domain Name --------------------------------------------------
    if (!hostip)
        return -1;
    if (getdomainname(&domain_host[0], 100) != 0)
    {
        return -1;
    }
    //------------------------------------------------------------------
    //Get IP Address & Mac Address ----------------------------------------
    if ((fd=socket(AF_INET,SOCK_DGRAM,0))>=0)
    {
        ifc.ifc_len=sizeof buf;
        ifc.ifc_buf=(caddr_t)buf;
        if (!ioctl(fd,SIOCGIFCONF,(char*)&ifc))
        {
            intrface=ifc.ifc_len/sizeof(struct ifreq);
            while (intrface-->0)
            {
                if (!(ioctl(fd,SIOCGIFFLAGS,(char*)&buf[intrface])))
                {
                    if (buf[intrface].ifr_flags&IFF_PROMISC)
                    {
                        retn++;
                    }
                }
                //Get IP Address
                if (!(ioctl(fd,SIOCGIFADDR,(char*)&buf[intrface])))
                {
                    sprintf(local_ip_addr, "%s", inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr));
                }
                //Get Hardware Address
#if 0
                if (!(ioctl(fd,SIOCGIFHWADDR,(char*)&buf[intrface])))
                {


		    sprintf(local_mac,"%02x:%02x:%02x:%02x:%02x:%02x",
                            (unsigned char)buf[intrface].ifr_hwaddr.sa_data[0],
                            (unsigned char)buf[intrface].ifr_hwaddr.sa_data[1],
                            (unsigned char)buf[intrface].ifr_hwaddr.sa_data[2],
                            (unsigned char)buf[intrface].ifr_hwaddr.sa_data[3],
                            (unsigned char)buf[intrface].ifr_hwaddr.sa_data[4],
                            (unsigned char)buf[intrface].ifr_hwaddr.sa_data[5]);

                    break;
                }
#endif
            }//While
        }
    }
    if ( fd > 0 )
    {
        close(fd);
    }

    strcpy(hostip, local_ip_addr);
#endif

    return CWMP_OK;
}

cwmp_session_t * cwmp_session_create(cwmp_t * cwmp)
{


    pool_t * pool = pool_create(POOL_MIN_SIZE);
    cwmp_session_t * session = pool_pcalloc(pool, sizeof(cwmp_session_t));
    session->env = pool_pcalloc(pool, sizeof(env_t));
    session->env->cwmp = cwmp;
    session->cwmp = cwmp;
    cwmp_chunk_create( &session->writers, pool);
    cwmp_chunk_create(&session->readers, pool);

    session->pool = pool;
    session->status = 0;
    session->newdata = 0;
    session->timeout = 0;
    session->envpool = NULL;
    session->connpool = NULL;

    session->root = cwmp->root;
    session->retry_count = 0;

    return session;
}

void cwmp_session_free(cwmp_session_t * session)
{
    pool_t * pool = session->pool;

    if (session->envpool)
    {
        pool_destroy(session->envpool);
        session->envpool = NULL;
    }
    if (session->connpool)
    {
        pool_destroy(session->connpool);
        session->connpool = NULL;
    }
    pool_destroy(pool);

}

int cwmp_session_close(cwmp_session_t * session)
{
    pool_destroy(session->envpool);
    pool_destroy(session->connpool);
    session->envpool = NULL;
    session->connpool = NULL;
    return 0;
}

int cwmp_session_open(cwmp_session_t * session)
{

    pool_t *envpool = pool_create(POOL_MIN_SIZE);

    session->connpool = pool_create(POOL_MIN_SIZE);
    if (!session->connpool)
    {
        cwmp_log_error("session init: create connection pool null.");
        return CWMP_ERROR;
    }
    session->envpool = envpool;
    session->env->pool = envpool;


    //pool_cleanup_add(envpool, cwmp_chunk_clear, session->writers);
    //pool_cleanup_add(envpool, cwmp_chunk_clear, session->readers);

    return CWMP_OK;
}

static size_t cwmp_session_write_callback(char *data, size_t size, size_t nmemb, void * calldata)
{
    cwmp_session_t * session = (cwmp_session_t *)calldata;

    cwmp_chunk_write_string(session->readers, data, size * nmemb, session->envpool);

    return size * nmemb;
}

int cwmp_session_connect(cwmp_session_t * session, const char * url)
{

    http_dest_t *  dest;
    int rv;

    http_dest_create(&dest, url, session->connpool);
    session->dest = dest;
    cwmp_log_debug("session connect: dest url is %s, acs url is %s", dest->url, url);
    rv = cwmp_session_create_connection(session);
    if(rv != CWMP_OK)
    {
        return rv;
    }
    cwmp_session_set_headers(session, 0);

    return CWMP_OK;
}

int cwmp_session_set_auth(cwmp_session_t * session, const char * user, const char * pwd)
{
    char buffer[256] = {0};
    TRsnprintf(buffer, 255, "%s:%s", user==NULL?"":user, pwd==NULL?"":pwd);

    session->dest->auth_type = HTTP_DIGEST_AUTH;
    session->dest->auth.active = CWMP_FALSE;
    TRstrncpy(session->dest->user, user, URL_USER_LEN);
    TRstrncpy(session->dest->password, pwd, URL_PWD_LEN);

    return CWMP_OK;
}


int cwmp_session_set_headers(cwmp_session_t * session, int postempty)
{

    return 0;
}


int cwmp_session_create_connection(cwmp_session_t * session)
{

    cwmp_t * cwmp = session->cwmp;
    http_socket_t * sock;
    int use_ssl = 0;
    http_dest_t *  dest = session->dest;
    if(dest)
    {
        if(strncmp(dest->scheme, "https", 5) == 0)
        {
            use_ssl = 1;
        }
    }
    cwmp_log_info("session connect using ssl?(%s)\n", use_ssl==1?"yes":"no");



        int rc = http_socket_create(&sock, AF_INET, SOCK_STREAM, 0, session->connpool);
        if (rc != CWMP_OK)
        {
            cwmp_log_error("session connect: create socket error.");
            return rc;
        }



		cwmp_log_debug("dest host: %s, dest port: %d", session->dest->host, session->dest->port);

       	http_socket_set_sendtimeout(sock, 60);

        rc = http_socket_connect(sock, AF_INET, session->dest->host, session->dest->port);
        if(rc != CWMP_OK)
        {
            cwmp_log_alert("connect to ACS faild. Host is %s:%d.", session->dest->host, session->dest->port);
            return rc;
        }


        if(use_ssl)
        {
#ifdef USE_CWMP_OPENSSL
            SSL *ssl = openssl_connect(cwmp->ssl_ctx, sock->sockdes);
            if(ssl)
            {
               sock->ssl = ssl;
               sock->use_ssl = 1;
            }
#endif

            //check_cert(ssl,host);
        }


        http_socket_set_writefunction(sock, cwmp_session_write_callback, session);

		cwmp_log_debug("session->timeout: %d", session->timeout);
        /*if(session->timeout > 0)
        {
            http_socket_set_recvtimeout(sock, session->timeout);
        }*/
        http_socket_set_recvtimeout(sock, 60);

    session->sock = sock;

    return CWMP_OK;

}

header_t * cwmp_session_create_header(cwmp_session_t * session, pool_t * pool)
{

    header_t * header;
    FUNCTION_TRACE();

    header = pool_palloc(pool, sizeof(header_t));
    header->hold_requests = 0;
    header->id = cwmp_session_get_sequence(pool);
    header->no_more_requests = 0;

    strncpy(session->id, header->id, 128);

    return header;
}

device_id_t * cwmp_session_create_inform_device(cwmp_session_t * session, pool_t * pool)
{
    device_id_t * device;

    FUNCTION_TRACE();


    device = pool_palloc(pool, sizeof(device_id_t));

    device->manufactorer = session->cwmp->cpe_mf;  
    device->oui          = session->cwmp->cpe_oui; 
    device->product_class = session->cwmp->cpe_pc; 
    device->serial_number = session->cwmp->cpe_sn; 
    device->name = session->cwmp->cpe_name;

    return device;
}

void add_parameter_to_list(cwmp_session_t * session, parameter_list_t * pl, char *name, char *value)
{
    parameter_t * parameter;
	parameter = cwmp_create_parameter(session->env,  name, value, 0, TYPE_STRING);
	cwmp_add_parameter_to_list(session->env,  pl, parameter);
}

void add_parameter(pool_t * pool, cwmp_session_t * session, parameter_list_t * pl, char *name, char *value)
{
    value   = cwmp_data_get_parameter_value(session->cwmp, session->root, name, pool);
    add_parameter_to_list(session, pl, name, value);
}

void cwmp_create_inform_param_list(cwmp_session_t *session, parameter_list_t *pl, char * path_name, parameter_node_t *  param_node)
{
    int rc;
    cwmp_buffer_t buffer;
    char *value;
    char *name = buffer.string;
    parameter_node_t * param_child;
    cwmp_t *cwmp = session->cwmp;
    pool_t *pool = cwmp->pool;

    if (!param_node)
        return NULL;
 
    for (param_child = param_node->child; param_child; param_child = param_child->next_sibling)
    {
        if(TRstrcmp(param_child->name, "{i}") == 0)
            continue;
        cwmp_buffer_init(&buffer);
        if (param_child->type == TYPE_OBJECT)
        {
            cwmp_buffer_write_format_string(&buffer,"%s%s.", path_name, param_child->name);
        }
        else
        {
            cwmp_buffer_write_format_string(&buffer,"%s%s", path_name, param_child->name);
            if(param_child->attr.nc == 1)
            {
                if(param_child->get)
                {
                    rc = (*param_child->get)(cwmp, name, &value, pool);
                    if(rc == FAULT_CODE_OK)
                    {
                        if(param_child->value == NULL || strcmp(value, param_child->value))
                        {
                            param_child->value = PSTRDUP(value);
                            add_parameter_to_list(session, pl, name, value);
                            cwmp_event_set_value(cwmp, INFORM_VALUECHANGE, 1, NULL, 0, 0, 0);
                        }
                    }
                }
            }
            else if(param_child->inform)
            {
                if(param_child->get)
                {
                    rc = (*param_child->get)(cwmp, name, &value, pool);
                    if(rc == FAULT_CODE_OK)
                    {
                        add_parameter_to_list(session, pl, name, value);
                    }
                }
            }
        }
 
        cwmp_create_inform_param_list(session, pl, cwmp_buffer_string(&buffer), param_child);
    }
}

parameter_list_t * cwmp_session_create_inform_parameters(cwmp_session_t * session, pool_t * pool)
{
    parameter_list_t * pl;

    FUNCTION_TRACE();
    pl = cwmp_create_parameter_list(session->env);
    cwmp_create_inform_param_list(session, pl, "", session->cwmp->root->parent);

    return pl;
}


event_list_t * cwmp_session_create_inform_events(cwmp_session_t * session, pool_t * pool)
{
    event_list_t * el;
    event_code_t * ev;
    int i=0;

    FUNCTION_TRACE();

    el = cwmp_create_event_list(session->env, INFORM_MAX);

    if (el->count == 0)
    {
        ev = cwmp_create_event_code(session->env);
        ev->event = 1;
        ev->code = CWMP_INFORM_EVENT_CODE_1;
        el->events[el->count++] = ev;
    }

    return el;
}



datatime_t *cwmp_session_create_inform_datetimes(cwmp_session_t * session, pool_t * pool)
{
    struct tm t;
    time_t tn;
    datatime_t *now;

    //FUNCTION_TRACE();
    tn = time(NULL);
#ifdef WIN32
    cwmp_log_debug("inform datatime");
    //localtime_s(&t, &tn);
    memset(&t, 0, sizeof(struct tm));
#else
    t = *localtime(&tn);
#endif

    now = pool_palloc(pool, sizeof(datatime_t));
    now->year = t.tm_year + 1900;
    now->month = t.tm_mon + 1;
    now->day = t.tm_mday;
    now->hour = t.tm_hour;
    now->min = t.tm_min;
    now->sec = t.tm_sec;

    return now;
}

//取得active event以及count
int cwmp_session_get_active_event(cwmp_session_t * session,  event_list_t **pevent_list)
{
    int i=0;
    event_list_t * el;
    event_code_t * ev;
    cwmp_t *cwmp = session->cwmp;

    FUNCTION_TRACE();
    el = cwmp_create_event_list(session->env, INFORM_MAX);
    event_code_t ** pec = cwmp->el->events;
   
    int elsize = cwmp->el->count;
    for(i=0; i<elsize; i++)
    {      
        
        if(pec[i]  && pec[i]->ref > 0)
        {
         
            event_code_t * ec = pec[i];
            ev = cwmp_create_event_code(session->env);
            ev->event = ec->event;
            ev->code = ec->code;
    
            if (pec[i]->event == INFORM_MREBOOT || pec[i]->event == INFORM_BOOTSTRAP)
            {
                strcpy(ev->command_key , ec->command_key);
            }
        
  
            el->events[el->count++] = ev;
            ev = NULL;

        }
    }
    
    if (el->count == 0)
    {
        ev = cwmp_create_event_code(session->env);
        ev->event = INFORM_BOOT;
        ev->code = CWMP_INFORM_EVENT_CODE_1;
        el->events[el->count++] = ev;
    }

    *pevent_list = el;

    return CWMP_OK;
}

xmldoc_t *  cwmp_session_create_inform_message(cwmp_session_t * session, pool_t * pool)
{

    header_t * header;
    device_id_t * device;
    event_list_t * el;
    datatime_t *now;
    parameter_list_t * pl;
    event_list_t  *evtlist = NULL;
    cwmp_t *cwmp = session->cwmp;

    FUNCTION_TRACE();
    header = cwmp_session_create_header(session, pool);
    device  = cwmp_session_create_inform_device(session, pool);
    pl      	= cwmp_session_create_inform_parameters(session, pool);
    now     = cwmp_session_create_inform_datetimes(session, pool);

    cwmp_session_get_active_event(session,  & evtlist);
    if(evtlist != NULL)
    {
        cwmp_log_debug("session stutus: cwmp_event_clear_active\n");
        cwmp_event_clear_active(cwmp);
    }

    return  cwmp_create_inform_message(session->env, header, device, evtlist, now, 1, session->retry_count, pl);
}

xmldoc_t *  cwmp_session_create_transfercomplete_message(cwmp_session_t * session, event_code_t * evcode,  pool_t * pool)
{

    header_t * header;
    device_id_t * device;
    event_list_t * el;
    datatime_t *now;
    parameter_list_t * pl;






    FUNCTION_TRACE();


    header = cwmp_session_create_header(session, pool);


    return  cwmp_create_transfercomplete_message(session->env, header, evcode);
}


xmldoc_t *  cwmp_session_create_getrpcmethods_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }
    return cwmp_create_getrpcmethods_response_message(session->env, header, rpc_methods, sizeof(rpc_methods)/sizeof(rpc_methods[0]));
}

xmldoc_t *  cwmp_session_create_getparameternames_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * path;
    unsigned int next_level;
    unsigned int next_subset;
    parameter_node_t * node;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_getparameternames_message(session->env, doc, &path, &next_level, &fault);

	char root_path[64] = ".";
    if (path == NULL || strlen(path) == 0)
	{
		path = root_path;
        next_subset = CWMP_YES;
	} 
	else if (path[strlen(path)-1] == '.')
    {
        next_subset = CWMP_YES;
    }
    else
    {
        next_subset = CWMP_NO;
    }

    node = cwmp_get_parameter_path_node(session->root, path);
	if (!strcmp(path, ".")) {
		strcpy(path, "");
	}

    return cwmp_create_getparameternames_response_message(session->env, header, path, node, next_subset, next_level);
}


xmldoc_t *  cwmp_session_create_getparametervalues_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    parameter_list_t * pl;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }
    
    rv = cwmp_parse_getparametervalues_message(session->env, doc, session->root, &pl, &fault);

    return cwmp_create_getparametervalues_response_message(session->env, header, pl);
}

xmldoc_t *  cwmp_session_create_setparametervalues_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    parameter_list_t * pl;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_setparametervalues_message(session->env, doc, session->root, &pl, &fault);

    if(rv != CWMP_OK)
    {
        return cwmp_create_faultcode_setparametervalues_response_message(session->env, header, pl, &fault);
    }


    return cwmp_create_setparametervalues_response_message(session->env, header, 0);
}


xmldoc_t *  cwmp_session_create_setparameterattributes_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    parameter_list_t * pl;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_setparameterattributes_message(session->env, doc, session->root, &pl, &fault);

    if(rv != CWMP_OK)
    {
        return cwmp_create_faultcode_setparameterattributes_response_message(session->env, header, pl, &fault);
    }


    return cwmp_create_setparameterattributes_response_message(session->env, header, 0);
}

xmldoc_t *  cwmp_session_create_getparameterattributes_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;

    xmlnode_t *obj_node;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    obj_node = cwmp_xml_get_child_with_name(cwmp_get_rpc_method_node(doc), "ParameterNames");
	if(obj_node == NULL){
		cwmp_log_error("no ParameterNames node \n");
		cwmp_set_faultcode(fault, FAULT_CODE_9005);
		return cwmp_create_faultcode_response_message(session->env, header, &fault);
	}

    return cwmp_create_getparameterattr_response_message(session->env, header, session->root, obj_node);
}

int receive_file(const char *fromurl, const char * pUsername, const char * pPassword)
{
    int ret;
    char *fileName;
    char tofile[256];
    char buff[512];

    if(!fromurl)
        return -1;

    fileName = GetBasename(fromurl);
    if(!fileName)
        return -1;
    sprintf(tofile, "/tmp/%s", fileName);

    if(access(tofile, F_OK) == 0)
    {
        sprintf(buff, "rm %s", tofile);
        system(buff);
    }

    if (pUsername == NULL || strlen(pUsername) == 0)
    {
        sprintf(buff, "wget -t 2 %s -O %s", fromurl, tofile);
    }
    else
    {
        if(!TRstrncasecmp("ftp://", fromurl, 6))
        {
            sprintf(buff, "wget -t 2 ftp://%s:%s@%s -O %s",
                pUsername,
                pPassword == NULL? "" : pPassword,
                fromurl + 6,
                tofile);
        }
        else
        {
            sprintf(buff, "wget -t 2 --http-user=%s --http-password=%s %s -O %s", pUsername, 
                pPassword == NULL? "" : pPassword, fromurl, tofile);
        }
    }
    // cwmp_log_debug("Download firmware: %s", buff);
    ret = system(buff);
    if((-1 != ret) && (WIFEXITED(ret)) && (!(WEXITSTATUS(ret))))
        return 0;
    else
    {
        // cwmp_log_debug("Download firmware: using origin http download", buff);
        ret = http_receive_file(fromurl, tofile);
        if(ret == 0 || ret == 200) // HTTP/1.1 200
            return 0;
        else
            return -1;
    }
}

int cwmp_download_file(download_arg_t * dlarg)
{
    int faultcode = 0;
    char * fromurl = dlarg->url;

    FUNCTION_TRACE();
    
    cwmp_log_info("cwmp_agent_download_file url[%s] usr[%s] pwd[%s] type[%s] fsize[%d]\r\n",
    			dlarg->url, 
    			dlarg->username, 
    			dlarg->password, 
    			dlarg->filetype, 
    			dlarg->filesize);

    if(receive_file(dlarg->url, dlarg->username, dlarg->password) < 0)
        faultcode = 9001;
    else
        faultcode = CWMP_OK;

    return faultcode;

}

int required_download(download_arg_t * dlarg) {
	
    char * fromurl = dlarg->url;
    char tofile[256], flagfile[256];
	char *fileName = GetBasename(fromurl);
	sprintf(tofile, "/tmp/%s", fileName);
	
	sprintf(flagfile, "/usr/upgrade_flag_%s", fileName);
	if (cmd_file_exist(flagfile)) {
		return CWMP_ERROR;
	}

	char *deviceType = "CPE";
	
	cwmp_log_debug("File: %s, DeviceType: %s", tofile, deviceType);
	if (strstr(tofile, deviceType) == NULL) {
		return CWMP_ERROR;
	}

	return CWMP_OK;
}

xmldoc_t *  cwmp_session_create_download_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * key;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    download_arg_t * dlarg;

    rv = cwmp_parse_download_message(session->env, doc, &dlarg, &fault);

    //add download arg to taskqueue
    //begin download process
	
	int status = 0;
	time_t starttime = time(NULL);
    if(rv == CWMP_OK)
    {
		download_arg_t * newdlarg = cwmp_clone_download_arg(dlarg);
		if(newdlarg != NULL /*&& required_download(newdlarg) == CWMP_OK*/)
		{
			cwmp_t * cwmp = session->cwmp;

			queue_push(cwmp->queue, newdlarg, TASK_DOWNLOAD_TAG);

			cwmp_log_debug("push new download task to queue! url: %s ", newdlarg->url);

			//begin download file
		    if (cwmp_download_file(newdlarg) == CWMP_OK)
		    {
			    status = 1;
		    }
		}

    }
    time_t endtime = time(NULL);

    return cwmp_create_download_response_message(session->env, header, status, &starttime, &endtime);
}

xmldoc_t *  cwmp_session_create_upload_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * key;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    upload_arg_t * uparg;

    rv = cwmp_parse_upload_message(session->env, doc, &uparg, &fault);

	time_t starttime = time(NULL);
    if(rv == CWMP_OK)
    {
		upload_arg_t * newularg = cwmp_clone_upload_arg(uparg);
		if(newularg)
		{
			cwmp_t * cwmp = session->cwmp;
			queue_push(cwmp->queue, newularg, TASK_UPLOAD_TAG);
			cwmp_log_debug("push new upload task to queue! url: %s ", newularg->url);
		}
    }
	time_t endtime = time(NULL);

    int status = 0;
    return cwmp_create_upload_response_message(session->env, header, status, &starttime, &endtime);

}



xmldoc_t *  cwmp_session_create_addobject_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    int instances, status;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }
    rv = cwmp_parse_addobject_message(session->env, doc, session->root, &instances, &status,  &fault);
    if(rv != CWMP_OK)
    {
	return cwmp_create_faultcode_response_message(session->env, header, &fault);
    }

    return cwmp_create_addobject_response_message(session->env, header, instances, status);
}


xmldoc_t *  cwmp_session_create_deleteobject_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv, status;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_deleteobject_message(session->env, doc, session->root, &status, &fault);

    if(rv != CWMP_OK)
    {
	return cwmp_create_faultcode_response_message(session->env, header, &fault);
    }


    return cwmp_create_deleteobject_response_message(session->env, header, status);
}



xmldoc_t *  cwmp_session_create_reboot_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * key;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    rv = cwmp_parse_reboot_message(session->env, doc, &key, &fault);

    cwmp_t * cwmp = session->cwmp;
    queue_push(cwmp->queue, NULL, TASK_REBOOT_TAG);

    return cwmp_create_reboot_response_message(session->env, header);
}


xmldoc_t *  cwmp_session_create_factoryreset_response_message(cwmp_session_t * session, xmldoc_t * doc, pool_t * pool)
{
    header_t * header;
    int rv;
    char * key;
    fault_code_t fault;
    FUNCTION_TRACE();
    rv = cwmp_parse_header_node(cwmp_get_header_node(doc), &header, pool);
    if (rv != CWMP_OK)
    {
        cwmp_log_error("no header node \n");
    }

    cwmp_t * cwmp = session->cwmp;
    queue_push(cwmp->queue, NULL, TASK_FACTORYRESET_TAG);

    return cwmp_create_factoryreset_response_message(session->env, header);
}



int cwmp_session_send_request(cwmp_session_t * session)
{
    //    size_t length = cwmp_chunk_length(session->writers);
    //    http_request_t * request;
    //    http_request_create(&request, session->env->pool);
    //    request->dest = session->dest;
    //
    //    http_post(session->sock, request, session->writers, session->env->pool);


    int rv;
    http_request_t * request;
    FUNCTION_TRACE();

    cwmp_log_debug("session dest url: %s\r\n", session->dest->url);
	cwmp_log_debug("session dest uri: %s\r\n", session->dest->uri);
	cwmp_log_debug("session dest auth.uri: %s\r\n", session->dest->auth.uri);

    http_request_create(&request, session->envpool);
    request->dest = session->dest;

    if(session->dest->auth_type == HTTP_DIGEST_AUTH)
    {
        if(!session->dest->auth.active)
        {
            //post empty
			cwmp_log_debug("post empty");
            http_post(session->sock, request, NULL, session->envpool);
            rv = cwmp_session_recv_response(session);
        }
    }

    rv = http_post(session->sock, request, session->writers, session->envpool);
    //cwmp_session_recv_response(session);

    if (rv <= 0)
    {
        return CWMP_ERROR;
    }
    else
    {
        return CWMP_OK;
    }




}

int cwmp_session_recv_response(cwmp_session_t * session)
{
    int respcode;
    http_response_t * response;
    char * auth;
    char * cookie;
	char * connection;
    char buffer[256];
    //select session->sock
    //if have new data, then read it

    http_response_create(&response, session->envpool);
    response->readers = session->readers;
    respcode= http_read_response(session->sock, response, session->envpool);

    session->last_code = response->status;

    if(respcode != HTTP_200 && respcode != 204)
    {
        cwmp_log_error("http read response failed. return code is %d, %d", respcode, response->status);

        if(response->status == 401 ||response->status == 407)
        {
            auth = http_get_variable(response->parser, "WWW-Authenticate");
            if(auth)
            {
                session->dest->auth.active = CWMP_FALSE;

                http_parse_digest_auth(auth, &session->dest->auth);
            }
        }

    }
    else
    {
		cwmp_log_error("http read response success. return code is %d, %d", respcode, response->status);
        session->dest->auth.active = CWMP_TRUE;
    }

    if(session->last_method == CWMP_INFORM_METHOD)
    {
        cookie = http_get_variable(response->parser, "Set-Cookie");
        if(cookie)
        {
            http_parse_cookie(cookie, session->dest->cookie);
			
			// liyao trim Cookie Path 2016-03-19
			char *p = session->dest->cookie;
			while (*p != '\0') {
				if (*p == ';') {
					*p = '\0';
					break;
				}
				p++;
			}
			cmd_echo(session->dest->cookie, TR069_COOKIE_FILE);
        } else {
        	if (cmd_file_exist(TR069_COOKIE_FILE)) {
				cmd_cat(TR069_COOKIE_FILE, buffer, sizeof(buffer));
				trim_end_line(buffer, strlen(buffer));
				strcpy(session->dest->cookie, buffer);
			}
        }
    }

    connection = http_get_variable(response->parser, "Connection");
	if (connection != NULL && strcmp(connection, "close") == 0) {
		session->close = CWMP_YES;
		cwmp_log_debug("Connection is close");
	} else {
		session->close = CWMP_NO;
		cwmp_log_debug("Connection is alive");
	}

    if(respcode == HTTP_200 || respcode == 204)
    {
		return CWMP_OK;
    }
    else
    {
		return CWMP_ERROR;
    }


}
