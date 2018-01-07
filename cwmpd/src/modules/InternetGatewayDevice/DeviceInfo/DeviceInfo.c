#include "cwmp/cwmp.h"
char param[1024];

int cpe_get_igd_di_manufacturer(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = cwmp->cpe_mf;

    return FAULT_CODE_OK;
}

int cpe_get_igd_di_manufactureroui(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = cwmp->cpe_oui;

    return FAULT_CODE_OK;
}

int cpe_get_igd_di_ModelName(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{	

    return FAULT_CODE_OK;
}

int cpe_get_igd_di_ModelNumber(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{

    return FAULT_CODE_OK;
}

int cpe_get_igd_di_Description(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    return FAULT_CODE_OK;
}

int cpe_get_igd_di_productclass(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = cwmp->cpe_pc;

    return FAULT_CODE_OK;
}

int cpe_get_igd_di_serialnumber(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = cwmp->cpe_sn;

    return FAULT_CODE_OK;
}

int cpe_get_igd_di_specversion(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    strcpy(param, "V1.0");
    *value = param;

    return FAULT_CODE_OK;
}

int cpe_get_igd_di_hardwareversion(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    strcpy(param, "V1.0");
    *value = param;
    
    return FAULT_CODE_OK;
}

int cpe_get_igd_di_softwareversion(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	strcpy(param, "Ver1.0.0");
	*value = param;
	
    return FAULT_CODE_OK;
}

int cpe_get_igd_di_provisioningcode(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    return FAULT_CODE_OK;
}

int cpe_get_igd_di_uptime(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    return FAULT_CODE_OK;
}

int cpe_set_attr_UpTime(cwmp_t * cwmp, const char * name, int notiChange, int noti, 
                        parameter_list_t *accList, int accListChange)
{
	return cwmp_set_parameter_attributes(cwmp, name, notiChange, noti);
}

int cpe_get_igd_di_AdditionalHardwareVersion(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{

    return FAULT_CODE_OK;
}

int cpe_get_igd_di_AdditionalSoftwareVersion(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{

    return FAULT_CODE_OK;
}

int cpe_get_igd_ms_period_intval(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = cwmp_conf_pool_get(pool, "cwmp:interval");

    return FAULT_CODE_OK;
}

int cpe_set_igd_ms_period_intval(cwmp_t *cwmp, const char *name, const char *value, int length)
{
    cwmp_conf_set("cwmp:interval", value);

    return FAULT_CODE_OK;
}

int cpe_get_ConnectionRequestURL(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    sprintf(param, "http://%s:%d", cwmp->cpe_httpd_ip, cwmp->httpd_port);
    *value = param;

    return FAULT_CODE_OK;
}

int cpe_get_igd_ms_connectionrequestusername(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = cwmp->acs_user;

    return FAULT_CODE_OK;
}

int cpe_set_igd_ms_connectionrequestusername(cwmp_t *cwmp, const char *name, const char *value, int length)
{
    cwmp_conf_set("cwmp:acs_username", value);

    return FAULT_CODE_OK;
}

int cpe_get_igd_ms_connectionrequestpassword(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    *value = cwmp->acs_pwd;

    return FAULT_CODE_OK;
}

int cpe_set_igd_ms_connectionrequestpassword(cwmp_t *cwmp, const char *name, const char *value, int length)
{
    cwmp_conf_set("cwmp:acs_password", value);

    return FAULT_CODE_OK;
}

int  cpe_refresh_igd_wandevice(cwmp_t * cwmp, parameter_node_t * param_node)
{
    cwmp_refresh_i_parameter(cwmp, param_node, 1);
    cwmp_model_refresh_object(cwmp, param_node, 0);

    return FAULT_CODE_OK;
}

int  cpe_refresh_igd_wanconnectiondevice(cwmp_t * cwmp, parameter_node_t * param_node)
{
    cwmp_refresh_i_parameter(cwmp, param_node, 1);
    cwmp_model_refresh_object(cwmp, param_node, 0);

    return FAULT_CODE_OK;
}

int  cpe_refresh_igd_wanipconnection(cwmp_t * cwmp, parameter_node_t * param_node)
{
    cwmp_refresh_i_parameter(cwmp, param_node, 1);
    cwmp_model_refresh_object(cwmp, param_node, 0);

    return FAULT_CODE_OK;
}

int cpe_get_igd_wan_ip_ExternalIPAddress(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
    sprintf(param, "%s", cwmp->cpe_httpd_ip);
    *value = param;

    return FAULT_CODE_OK;
}

int cpe_get_igd_wan_ip_MACAddress(cwmp_t * cwmp, const char * name, char ** value, pool_t * pool)
{
	strcpy(param, "11:22:33:44:55:66");
	*value = param;

    return FAULT_CODE_OK;
}


