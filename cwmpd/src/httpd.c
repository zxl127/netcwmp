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

#include <cwmp/http.h>
#include <cwmp/event.h>
#include "cwmp_httpd.h"


#define MAX_CLIENT_NUMS 8


static char * AuthRealm = "cwmpd";
static char * AuthQop = "auth";
static char   AuthOpaque[33] = {0};
static int	  AuthNonce = 0;

const char * RESPONSE_200 = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\r\nOK";
const char * RESPONSE_400 = "HTTP/1.1 400 Bad request\r\nServer: CWMP-Agent\r\nConnection: close\r\nContent-Length: 5\r\n\r\nError";
const char * RESPONSE_401 = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest qop=\"%s\", nonce=\"%s\", opaque=\"%s\", realm=\"%s\"\r\nServer: TR069Agent\r\nContent-Length: 0\r\n\r\n";

struct http_session_fd_t
{
    //int fd;
    time_t time;
    http_socket_t * sock;
};


struct http_session_fd_t sessionfd[MAX_CLIENT_NUMS];


void setnonblocking(int fd)
{
#ifdef WIN32
#else
    int opts;
    opts=fcntl(fd, F_GETFL);
    if (opts < 0)
    {
        cwmp_log_error("setnonblocking fcntl GETFL failed: fd(%d)\n", fd);
        return;
    }
    opts = opts | O_NONBLOCK;
    if (fcntl(fd, F_SETFL, opts) < 0)
    {
        cwmp_log_error("setnonblocking fcntl SETFL failed: fd(%d)\n", fd);
        return;
    }
    return;
#endif
}



int httpd_response_unauthorization(http_socket_t * sock)
{

    char buffer[256];
    char nonce[33];
    FUNCTION_TRACE();
    AuthNonce ++;
    TRsnprintf(buffer, 256,  "%d", AuthNonce);
    MD5(nonce, buffer, NULL);

    nonce[32] = 0;

    TRsnprintf(buffer, 256, RESPONSE_401, AuthQop, nonce, AuthOpaque, AuthRealm);


    return	http_socket_write(sock, buffer, TRstrlen(buffer));
}

int httpd_response_ok(http_socket_t * sock)
{
    FUNCTION_TRACE();
    return	http_socket_write(sock, RESPONSE_200, TRstrlen(RESPONSE_200));
}

int httpd_response_unkonw_error(http_socket_t * sock)
{
    FUNCTION_TRACE();
    return	http_socket_write(sock, RESPONSE_400, TRstrlen(RESPONSE_400));
}

extern void set_connection_request_true(void);
extern void cwmp_agent_create_session(cwmp_t *cwmp);

void task_server_run(utask_queue_t *q, utask_t *t)
{
    int rc = 1;
    pid_t pid;
    char * auth;
    cwmp_t *cwmp = t->args[0];
    http_socket_t *s = t->args[1];
    http_request_t * request;
    char cpe_user[INI_BUFFERSIZE] = {0};
    char cpe_pwd[INI_BUFFERSIZE] = {0};

    pid = fork();

    if(pid != 0) {
        t->pid = pid;
        http_socket_close(s);
        http_socket_destroy(s);
        return;
    }

    http_request_create(&request, http_socket_get_pool(s));
    rc = http_read_request(s, request, http_socket_get_pool(s));
    if (rc <= 0)
    {
        rc = -1;
        httpd_response_unkonw_error(s);
        goto fail;
    }

    if (request->method != HTTP_GET)
    {
        rc = -1;
        httpd_response_unkonw_error(s);
        goto fail;
    }

    if (cwmp->cpe_auth)
    {
        auth = http_get_variable(request->parser, "Authorization");

        if (!auth)
        {
            rc = -1;
            httpd_response_unauthorization(s);
            goto fail;
        }

        cwmp_conf_get("cwmp:cpe_username", cpe_user);
        cwmp_conf_get("cwmp:cpe_password", cpe_pwd);

        cwmp_log_debug("cpe username: %s, cpe password: %s\n", cpe_user, cpe_pwd);

        if (http_check_digest_auth(AuthRealm, auth, cpe_user, cpe_pwd) != 0)
        {
            rc = -1;
            httpd_response_unauthorization(s);
            goto fail;
        }
    }

    httpd_response_ok(s);

    //get a new request from acs
    cwmp->new_request = CWMP_YES;
    cwmp_log_debug("set cwmp new request to %d\n", cwmp->new_request);

    cwmp_event_set_value(cwmp, INFORM_CONNECTIONREQUEST, 1, NULL, 0, 0, 0);
    set_connection_request_true();
fail:
    http_socket_close(s);
    http_socket_destroy(s);
    if(rc > 0)
        cwmp_agent_create_session(cwmp);
    pool_clear(cwmp->pool);
    exit(EXIT_SUCCESS);
}

void task_server_complete(utask_queue_t *q, utask_t *t)
{
    cwmp_t *cwmp = t->args[0];

    free(t->args);
    pool_pfree(cwmp->pool, t);
    printf("new client request complete\n");
}

void new_server_request(ufd_t *f)
{
    int ret;
    utask_t *task_server;
    http_socket_t *new_sock;
    cwmp_t *cwmp = f->args[0];

    for(;;)
    {
        ret = http_socket_accept(f->args[1], &new_sock);
        if(ret < 0)
            break;
        task_server = pool_palloc(cwmp->pool, sizeof(utask_t));
        utask_set_handler(task_server, task_server_run, utask_kill, task_server_complete);
        utask_set_timer(task_server, 0, 20000);
        utask_register(task_server, mk_args(2, cwmp, new_sock));
    }
}

void init_httpd_server(cwmp_t *cwmp)
{
    int rc;
    http_socket_t *listen_sock;
    ufd_t *ufd;

    rc = http_socket_server(&listen_sock, cwmp->httpd_port, 5, -1, cwmp->pool);
    if(rc != CWMP_OK)
    {
        cwmp_log_error("build httpd server faild. port: %d, %s\n", cwmp->httpd_port, strerror(errno));
        exit(-1);
    }

    ufd = pool_palloc(cwmp->pool, sizeof(ufd_t));
    ufd->fd = http_socket_get_fd(listen_sock);
    ufd->handler = new_server_request;
    ufd->args = mk_args(2, cwmp, listen_sock);
    ufd_add(ufd, EVENT_READ | EVENT_NONBLOCK | EVENT_EDGE_TRIGGER);
}

