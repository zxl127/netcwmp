#include "cwmp/log.h"
#include "cwmp/cwmp.h"
#include "cwmp/task_list.h"

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
        ret = http_receive_file(fromurl, tofile);
        if(ret == 0 || ret == 200) // HTTP/1.1 200
            return 0;
        else
            return -1;
    }
}

int cwmp_agent_upload_file(upload_arg_t * ularg)
{
    int faultcode = 0;
    FUNCTION_TRACE();
    char * fromfile;

    cwmp_log_info("ularg->filetype: %s", ularg->filetype);

    if(strcmp(ularg->filetype, "1 Vendor Configuration File") == 0)
    {
        fromfile = "/tmp/configuration";
    }
    else if(strcmp(ularg->filetype, "2 Vendor Log File") == 0)
    {
        fromfile = "/tmp/log_file";
    }
    else
    {
        fromfile = "";
    }
    cwmp_log_info("Upload: %s", fromfile);

    faultcode = http_send_file(fromfile, ularg->url);

    if(faultcode != CWMP_OK)
    {
        faultcode = 9001;
    }

    return faultcode;
}

void cwmp_task_inform(void *arg1, void *arg2)
{
    FUNCTION_TRACE();
    int interval = 0;
    cwmp_t *cwmp = (cwmp_t *)arg1;

    interval = cwmp_conf_get_int("cwmp:interval");
    cwmp_event_set_value(cwmp, INFORM_PERIODIC, 1, NULL, 0, 0, 0);
    cwmp->new_request = CWMP_YES;

//    task_register(cwmp, cwmp_task_inform, NULL, interval, TASK_TYPE_TIME);
}

void cwmp_task_download_file(void *arg1, void *arg2)
{
    FUNCTION_TRACE();
    int faultcode = 0;
    cwmp_t *cwmp = (cwmp_t *)arg1;
    download_arg_t * dlarg;// = (download_arg_t*)task->arg;

    cwmp_log_info("cwmp_agent_download_file url[%s] usr[%s] pwd[%s] type[%s] fsize[%d]\r\n",
                dlarg->url,
                dlarg->username,
                dlarg->password,
                dlarg->filetype,
                dlarg->filesize);

    time_t starttime = time(NULL);
    if(receive_file(dlarg->url, dlarg->username, dlarg->password) < 0)
        faultcode = 9001;
    else
        faultcode = CWMP_OK;
    time_t endtime = time(NULL);

    cwmp_event_set_value(cwmp, INFORM_TRANSFERCOMPLETE, 1,dlarg->cmdkey, faultcode, starttime, endtime);
    cwmp_event_clear_active(cwmp);

    FREE(dlarg);

//    task_unregister(cwmp, task, TASK_TYPE_PRIORITY);
}

void cwmp_task_upload_file(void *arg1, void *arg2)
{
    FUNCTION_TRACE();
    int faultcode = 0;
    cwmp_t *cwmp = (cwmp_t *)arg1;
    upload_arg_t * ularg;// = (upload_arg_t*)task->arg;

    time_t starttime = time(NULL);
    faultcode = cwmp_agent_upload_file(ularg);
    time_t endtime = time(NULL);

    cwmp_event_set_value(cwmp, INFORM_TRANSFERCOMPLETE, 1,ularg->cmdkey, faultcode, starttime, endtime);

    FREE(ularg);

//    task_unregister(cwmp, task, TASK_TYPE_PRIORITY);
}

void cwmp_task_reboot(void *arg1, void *arg2)
{
    FUNCTION_TRACE();
    cwmp_t *cwmp = (cwmp_t *)arg1;

    cwmp_event_set_value(cwmp, INFORM_MREBOOT, 1, NULL, 0, 0, 0);
    cwmp_event_clear_active(cwmp);
//    system("reboot");

//    task_unregister(cwmp, task, TASK_TYPE_PRIORITY);

//    exit(1);
}

void cwmp_task_factoryreset(void *arg1, void *arg2)
{
    FUNCTION_TRACE();
    cwmp_t *cwmp = (cwmp_t *)arg1;

    remove(TR069_BOOTSTRAP_FLAG);
    remove(TR069_REBOOT_FLAG);
    cwmp_event_set_value(cwmp, INFORM_BOOTSTRAP, 1, NULL, 0, 0, 0);
    cwmp_event_clear_active(cwmp);

//    task_unregister(cwmp, task, TASK_TYPE_PRIORITY);

//    exit(1);
}
