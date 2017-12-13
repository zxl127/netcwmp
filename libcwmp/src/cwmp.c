/************************************************************************
 * Id: cwmp.c                                                           *
 *                                                                      *
 * TR069 Project:  A TR069 library in C                                 *
 * Copyright (C) 2013-2014 netcwmp group                         *
 *                                                                      *
 *                                                                      *
 * Email: netcwmp ( & ) gmail dot com                                *
 *                                                                      *
 ***********************************************************************/

#include "cwmp/cwmp.h"
#include "cwmp/buffer.h"
#include "cwmp/log.h"
#include "cwmp/event.h"
#include "cwmp_private.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include "sys/stat.h"


#define CWMP_BUF_SIZE 128
#define CWMP_RENEW_SIZE CWMP_NAME_MAX

#ifdef WIN32


//#define ESA(x, y) do { (x) = (y); if( (x) == NULL) { return NULL; } } while (0)
#define ESA(x, y)   (x) = (y); if( (x) == NULL)  return NULL
#define ESN(x, y)   if((x) != (y))  return NULL
#define ESQ(x, y)   if((x) == (y))  return NULL

//not eq
#define ESNE(x,y,z)  if((y) != (z)) return (x)
//eq
#define ESE(x,y,z)  if((y) == (z)) return (x)

#else

//#define ESA(x, y) do { (x) = (y); if( (x) == NULL) { return NULL; } } while (0)
#define ESA(x, y)  do { (x) = (y); if( (x) == NULL) { printf("ASSERT: \"%s\" is NULL. file: %s , func: %s , line: %d\n", #x, __FILE__, __func__, __LINE__); return NULL; } } while(0)
#define ESN(x, y)  do { if((x) != (y))  { printf("ASSERT: \"%s\" != \"%s\"  file: %s , func: %s , line: %d\n", #x, #y, __FILE__, __func__, __LINE__); return NULL; } } while (0)
#define ESQ(x, y)    do { if((x) != (y)) return NULL ; } while(0)
//true
#define ESNE(x,y,z) do { if((y) != (z))  { printf("ASSERT: \"%s\" != \"%s\"  file: %s , func: %s , line: %d\n", #y, #z, __FILE__, __func__, __LINE__); return (x); } } while (0)
//eq
#define ESE(x,y,z)  do { if((y) == (z))  { printf("ASSERT: \"%s\" == \"%s\"  file: %s , func: %s , line: %d\n", #y, #z, __FILE__, __func__, __LINE__); return (x); } } while (0)

#endif


static char SOAP_ENV[CWMP_NAME_MAX] = {0};
static char SOAP_ENC[CWMP_NAME_MAX] = {0};

static char SOAP_ENV_HEADER[CWMP_NAME_MAX] = {0};
static char SOAP_ENV_BODY[CWMP_NAME_MAX] = {0};
static char SOAP_ENV_ENVELOPE[CWMP_NAME_MAX] = {0};
static char SOAP_ENV_FAULT[CWMP_NAME_MAX]={0};
static char SOAP_ENC_ARRAYTYPE[CWMP_NAME_MAX] = {0};


//static parameter_node_t* gs_root_parameter_node = NULL;


#define CWMP_TYPE(x) cwmp_get_type_string(x)





static char * cwmp_get_format_string(const char * fmt, ...)
{
    va_list ap;

    static char g_cwmp_format_string[1024] = {0};
    va_start(ap, fmt);
#ifdef WIN32
    _vsnprintf(g_cwmp_format_string, 1023, fmt, ap);
#else
    vsnprintf(g_cwmp_format_string, 1023, fmt, ap);
#endif

    va_end(ap);
    return g_cwmp_format_string;
}


char * cwmp_get_type_string(int type)
{
    switch (type)
    {
    case TYPE_OBJECT:
        return "object";
    case TYPE_STRING:
        return "xsd:string";
    case TYPE_INT:
        return "xsd:int";
    case TYPE_UNSIGNEDINT:
        return "xsd:unsignedInt";
    case TYPE_STRING32:
        return "xsd:string[32]";
    case TYPE_STRING64:
        return "xsd:string[64]";
    case TYPE_STRING128:
        return "xsd:string[128]";
    case TYPE_STRING256:
        return "xsd:string[256]";
    case TYPE_STRING1024:
        return "xsd:string[1024]";
    case TYPE_BOOLEAN:
        return "xsd:bool";
    case TYPE_DATETIME:
        return "xsd:DateTime";
    default:
        return "";
    }


}



int cwmp_get_type_value(char * type)
{
//    	TYPE_OBJECT=0,	//obj
//	TYPE_INT,	//int
//	TYPE_UNSIGNEDINT, //uint
//	TYPE_STRING,  	//s
//	TYPE_STRING16,	//s16
//	TYPE_STRING32,	//s32
//	TYPE_STRING64,	//s64
//	TYPE_STRING128,	//s128
//	TYPE_STRING256,	//s256
//	TYPE_STRING1024, //s1024
//	TYPE_DATETIME,	//dt
//	TYPE_BOOLEAN,	//bool
//	TYPE_BASE64,	//base

    if(type == NULL)
    {
        return TYPE_UNKNOWN;
    }

    if(! TRstrcasecmp(type, "int"))
    {
        return TYPE_INT;
    }
    else if(! TRstrcasecmp(type, "uint"))
    {
        return TYPE_UNSIGNEDINT;
    }
    else if(! TRstrcasecmp(type, "s"))
    {
        return TYPE_STRING;
    }
    else if(! TRstrcasecmp(type, "s16"))
    {
        return TYPE_STRING16;
    }
    else if(! TRstrcasecmp(type, "s32"))
    {
        return TYPE_STRING32;
    }
    else if(! TRstrcasecmp(type, "s64"))
    {
        return TYPE_STRING64;
    }
    else if(! TRstrcasecmp(type, "s128"))
    {
        return TYPE_STRING64;
    }
    else if(! TRstrcasecmp(type, "s256"))
    {
        return TYPE_STRING64;
    }
    else if(! TRstrcasecmp(type, "s1024"))
    {
        return TYPE_STRING64;
    }
    else if(! TRstrcasecmp(type, "dt"))
    {
        return TYPE_STRING64;
    }
    else if(! TRstrcasecmp(type, "bool"))
    {
        return TYPE_STRING64;
    }
     else if(! TRstrcasecmp(type, "base"))
    {
        return TYPE_BASE64;
    }
    else if(! TRstrcasecmp(type, "obj"))
    {
        return TYPE_OBJECT;
    }

    return TYPE_STRING;

}




char * cwmp_get_fault_string(int code)
{
    char * fault_string;
    switch(code)
    {
        case 9000:
            return  FAULT_STR_9000;

        case 9001:
            return  FAULT_STR_9001;

        case 9002:
            return  FAULT_STR_9002;

        case 9003:
            return  FAULT_STR_9003;

        case 9004:
            return  FAULT_STR_9004;

        case 9005:
            return  FAULT_STR_9005;

        case 9006:
            return  FAULT_STR_9006;

        case 9007:
            return  FAULT_STR_9007;

        case 9008:
            return  FAULT_STR_9008;

        case 9009:
            return  FAULT_STR_9009;

        case 9010:
            return  FAULT_STR_9010;

        case 9011:
            return  FAULT_STR_9011;

        case 9012:
            return  FAULT_STR_9012;

        case 9013:
            return  FAULT_STR_9013;

        case 9014:
            return  FAULT_STR_9014;

        case 9015:
            return  FAULT_STR_9015;

        case 9016:
            return  FAULT_STR_9016;

        case 9017:
            return  FAULT_STR_9017;

        case 9018:
            return  FAULT_STR_9018;

        case 9019:
            return  FAULT_STR_9019;
        default:
            return "";

    }

}


void get_gmtime(time_t *t, struct tm *gm)
{
	struct tm *p;
		
	p=localtime(t);
	memcpy(gm,p,sizeof(struct tm));
}

char *parse_time(time_t *t)
{
	static char buff[64];
	struct tm gm;

	if(t == NULL) return NULL;

	get_gmtime(t, &gm);
    // UTC time: 0001-01-01T00:00:00Z 
	sprintf(buff,
		"%04d-%02d-%02dT%02d:%02d:%02dZ",
		gm.tm_year+1900,
		gm.tm_mon+1,
		gm.tm_mday,
		gm.tm_hour,
		gm.tm_min,
		gm.tm_sec);

	return buff;
}

char *trim_end_line(char *value, int n) {
	register int i;

	for (i = n; i >= 0; i--) {
		if (value[i] == '\0') {
			continue;
		}

		if (value[i] == '\n' || value[i] == '\r') {
			value[i] = '\0';
		} else {
			break;
		}
	}

	return value;
}


xmldoc_t * cwmp_xml_parse_buffer(pool_t * pool, char * buffer)
{
    return XmlParseBuffer(pool, buffer);

}

const char * cwmp_xml_get_node_name(xmlnode_t * node)
{
    xmlnode_t * child;
    child = XmlNodeGetFirstChild(node);
    return XmlNodeGetNodeName(child);

}


char * cwmp_xml_get_node_value(xmlnode_t * node)
{
    return XmlNodeGetNodeValue(XmlNodeGetFirstChild(node));

}

char * cwmp_xml_get_node_attribute(xmlnode_t * node, const char * name)
{
    return XmlElementGetAttribute((XmlElement*)node, name);

}


xmlnode_t * cwmp_xml_get_child_with_name(void * nodeptr, const char * nodeName)
{
    xmlnode_t * children;
    xmlnode_t * node = (xmlnode_t *)nodeptr;
    if (node == NULL)
    {
        cwmp_log_error("Invalid parameter 'param' (null)");
        return NULL;
    }

    children = XmlNodeGetFirstChild(node);
    while (children != NULL)
    {
        if (children->nodeType != XML_ELEMENT_NODE)
        {
            children = XmlNodeGetNextSibling(children);
        }
        else
        {
            if (! TRstrcasecmp(children->nodeName, nodeName))
            {
                //cwmp_log_debug("cwmp_xml_get_child_with_name found node(%p)\n", children);
                break;
            }
            else
                children = XmlNodeGetNextSibling(children);
        }
    }

    return children;
}

xmlnode_t * cwmp_xml_create_child_node(env_t * env ,  xmlnode_t * parentNode, const char * ns, const char * nodeName, const char * nodeValue)
{
    XmlElement * newNode;
    pool_t * pool = env->pool;

    assert(parentNode != NULL);
    newNode = ( XmlElement *  ) PMALLOC( sizeof( XmlElement ) );
    if ( newNode == NULL )
    {
        cwmp_log_error("cwmp_xml_create_child_node XMALLOC is error: newNode\n" );
        return NULL;
    }
    else
    {
        XmlElementInit( newNode );
        XmlElementSetTagName(pool , newNode, nodeName);
        XmlNodeSetNodeName(pool ,  (xmlnode_t *)newNode, nodeName );
        XmlNodeSetNodeValue(pool , (xmlnode_t *)newNode, nodeValue );


        XmlNodeAppendChild(parentNode, (xmlnode_t *)newNode);

    }

    return (xmlnode_t *)newNode;
}


int cwmp_xml_set_node_attribute(env_t * env,  xmlnode_t * node, const char * name, const char * value)
{
    int rv = XmlElementSetAttribute(env->pool, (XmlElement *)node, name, value);
    if (rv == XML_OK)
        return CWMP_OK;
    else
        return CWMP_ERROR;
}







void cwmp_xml_copy_to_chunk_with_escape(cwmp_chunk_t * cb,   IN char *p , pool_t * pool)
{
    int i;
    size_t plen;

    if ( p == NULL )
        return;

    plen = TRstrlen( p );

    for ( i = 0; i < plen; i++ )
    {
        switch ( p[i] )
        {
        case '<':
            cwmp_chunk_write_string(cb, "&lt;", 4, pool);
            break;

        case '>':
            cwmp_chunk_write_string(cb, "&gt;", 4, pool);
            break;

        case '&':
            cwmp_chunk_write_string(cb, "&amp;", 5, pool);
            break;

        case '\'':
            cwmp_chunk_write_string(cb, "&apos;", 6, pool);
            break;

        case '\"':
            cwmp_chunk_write_string(cb, "&quot;", 6, pool);
            break;

        default:
            cwmp_chunk_write_string(cb, &p[i], 1, pool);

            break;
        }
    }
}


int cwmp_xml_dom_tree_print_to_chunk(xmlnode_t * node, cwmp_chunk_t * cb, pool_t * pool )
{
    char *nodeName = NULL;
    char *nodeValue = NULL;
    xmlnode_t *  child = NULL;
    xmlnode_t *  sibling = NULL;

    if ( node != NULL )
    {
        nodeName = ( char * )XmlNodeGetNodeName( node )? ( char * )XmlNodeGetNodeName( node ):"";
        nodeValue = XmlNodeGetNodeValue( node );
        cwmp_log_debug("dom tree xmlnode type is %d\n", XmlNodeGetNodeType( node ));
        switch ( XmlNodeGetNodeType( node ) )
        {

        case XML_TEXT_NODE:
            cwmp_xml_copy_to_chunk_with_escape(cb, nodeValue, pool);

            break;

        case XML_CDATA_SECTION_NODE:
            cwmp_chunk_write_string(cb, nodeValue, TRstrlen(nodeValue), pool);
            break;


        case XML_PROCESSING_INSTRUCTION_NODE:
            cwmp_chunk_write_string(cb, "<?", 2, pool);
            cwmp_chunk_write_string(cb, nodeName, TRstrlen(nodeName), pool);
            cwmp_chunk_write_string(cb, " ", 1, pool);
            cwmp_chunk_write_string(cb, nodeValue, TRstrlen(nodeValue), pool);
            cwmp_chunk_write_string(cb, "?>\n", 3, pool);

            break;

        case XML_DOCUMENT_NODE:
            cwmp_xml_dom_tree_print_to_chunk(XmlNodeGetFirstChild( node ), cb, pool);

            break;

        case XML_ATTRIBUTE_NODE:
            cwmp_log_debug	("dom tree attribute: %s,%s\n", nodeName, nodeValue);
            cwmp_chunk_write_string(cb, nodeName, TRstrlen(nodeName), pool);
            cwmp_chunk_write_string(cb, "=\"", 2, pool);
            cwmp_chunk_write_string(cb, nodeValue, TRstrlen(nodeValue), pool);
            cwmp_chunk_write_string(cb, "\"", 1, pool);

            if ( node->nextSibling != NULL )
            {
                cwmp_chunk_write_string(cb, " ", 1, pool);
                cwmp_xml_dom_tree_print_to_chunk(node->nextSibling, cb, pool);
            }
            break;

        case XML_ELEMENT_NODE:
            cwmp_chunk_write_string(cb, "<", 1, pool);
            cwmp_chunk_write_string(cb, nodeName, TRstrlen(nodeName), pool);

            if ( node->firstAttr != NULL )
            {
                cwmp_chunk_write_string(cb, " ", 1, pool);
                cwmp_xml_dom_tree_print_to_chunk(node->firstAttr, cb, pool);

            }

            child = XmlNodeGetFirstChild( node );
            if ( ( child != NULL )
                    && ( XmlNodeGetNodeType( child ) == XML_ELEMENT_NODE ) )
            {
                cwmp_chunk_write_string(cb, ">\n", 2, pool);

                cwmp_xml_dom_tree_print_to_chunk(node, cb, pool);
                //  output the children

            }
            else
            {
                cwmp_chunk_write_string(cb, ">", 1, pool);

                if (nodeValue)
                {
                    cwmp_chunk_write_string(cb, nodeValue, TRstrlen(nodeValue), pool);

                }
            }

            cwmp_chunk_write_string(cb, "</", 2, pool);
            // Done with children.  Output the end tag.
            cwmp_chunk_write_string(cb, nodeName, TRstrlen(nodeName), pool);

            sibling = XmlNodeGetNextSibling( node );
            if ( sibling != NULL
                    && XmlNodeGetNodeType( sibling ) == XML_TEXT_NODE )
            {
                cwmp_chunk_write_string(cb, ">", 1, pool);

            }
            else
            {
                cwmp_chunk_write_string(cb, ">\n", 2, pool);
            }
            cwmp_xml_dom_tree_print_to_chunk(sibling, cb, pool);

            break;

        default:
            break;
        }
    }
    return XML_OK;
}


int cwmp_xml_print_doc_to_chunk(xmldoc_t *   doc, cwmp_chunk_t * cb, pool_t * pool )
{
    xmlnode_t * nodeptr = &doc->node;


    char *nodeName = NULL;
    char *nodeValue = NULL;
    xmlnode_t *  child = NULL;

    if ( nodeptr == NULL)
    {
        return CWMP_OK;
    }

    nodeName = ( char * )XmlNodeGetNodeName( nodeptr )? ( char * )XmlNodeGetNodeName( nodeptr ) :"";
    nodeValue = XmlNodeGetNodeValue( nodeptr );

    switch ( XmlNodeGetNodeType( nodeptr ) )
    {

    case XML_TEXT_NODE:
    case XML_CDATA_SECTION_NODE:
    case XML_PROCESSING_INSTRUCTION_NODE:
    case XML_DOCUMENT_NODE:
        cwmp_xml_dom_tree_print_to_chunk(nodeptr, cb, pool);

        break;

    case XML_ATTRIBUTE_NODE:
        cwmp_log_debug	("attribute: %s,%s\n", nodeName, nodeValue);
        cwmp_chunk_write_string(cb, nodeName, TRstrlen(nodeName), pool);
        cwmp_chunk_write_string(cb, "=\"", 2, pool);
        cwmp_chunk_write_string(cb, nodeValue, TRstrlen(nodeValue), pool);
        cwmp_chunk_write_string(cb, "\"", 1, pool);
        break;

    case XML_ELEMENT_NODE:
        cwmp_chunk_write_string(cb, "<", 1, pool);

        cwmp_chunk_write_string(cb, nodeName, TRstrlen(nodeName), pool);
        if ( nodeptr->firstAttr != NULL )
        {
            cwmp_chunk_write_string(cb, " ", 1, pool);
            cwmp_xml_dom_tree_print_to_chunk(nodeptr->firstAttr, cb, pool);
        }




        child = XmlNodeGetFirstChild( nodeptr );
        if ( ( child != NULL )
                && ( XmlNodeGetNodeType( child ) == XML_ELEMENT_NODE ) )
        {
            cwmp_chunk_write_string(cb, ">\n", 2, pool);

            cwmp_xml_dom_tree_print_to_chunk(XmlNodeGetFirstChild( nodeptr ), cb, pool);
            //  output the children

        }
        else
        {
            cwmp_chunk_write_string(cb, ">", 1, pool);

            if (nodeValue)
            {
                cwmp_chunk_write_string(cb, nodeValue, TRstrlen(nodeValue), pool);

            }
        }



        // Done with children.  Output the end tag.
        cwmp_chunk_write_string(cb, "</", 2, pool);
        cwmp_chunk_write_string(cb, nodeName, TRstrlen(nodeName), pool);
        cwmp_chunk_write_string(cb, ">\n", 2, pool);
        break;

    default:
        break;
    }
    return CWMP_OK;
}


void cwmp_set_envelope_ns(const char * envstr, const char * encstr)
{
    const char * envs;
    const char * encs;
    char buffer[CWMP_NAME_MAX] = {0};
    if (envstr == NULL)
    {
        envs = SOAP_ENV_DEFAULT;
    }
    else
    {
        envs = envstr;
    }

    if (encstr == NULL)
    {
        encs = SOAP_ENC_DEFAULT;
    }
    else
    {
        encs = encstr;
    }

    if(TRstrcasecmp(SOAP_ENV, envs) == 0)
    {
        return;
    }

    cwmp_log_debug("ENV: %s, ENC: %s", envs, encs);
    TRstrncpy(SOAP_ENV,  envs, CWMP_NAME_MAX);
    TRstrncpy(SOAP_ENC,  encs, CWMP_NAME_MAX);


    TRsnprintf(buffer, CWMP_NAME_MAX, "%s:%s", envs, SOAP_XML_HEADER);
    TRstrncpy(SOAP_ENV_HEADER, buffer, CWMP_NAME_MAX);

    TRsnprintf(buffer, CWMP_NAME_MAX, "%s:%s", envs, SOAP_XML_BODY);
    TRstrncpy(SOAP_ENV_BODY, buffer, CWMP_NAME_MAX);

    TRsnprintf(buffer, CWMP_NAME_MAX, "%s:%s", envs, SOAP_XML_FAULT);
    TRstrncpy(SOAP_ENV_FAULT, buffer, CWMP_NAME_MAX);

    TRsnprintf(buffer, CWMP_NAME_MAX, "%s:%s", envs, SOAP_XML_ENVELOPE);
    TRstrncpy(SOAP_ENV_ENVELOPE, buffer, CWMP_NAME_MAX);

    TRsnprintf(buffer, CWMP_NAME_MAX, "%s:%s", encs, SOAP_TYPE_ARRAYTYPE);
    TRstrncpy(SOAP_ENC_ARRAYTYPE, buffer, CWMP_NAME_MAX);

    cwmp_log_debug("%s\n%s\n%s\n%s\n", SOAP_ENV_HEADER, SOAP_ENV_BODY, SOAP_ENV_ENVELOPE, SOAP_ENC_ARRAYTYPE);


}

void cwmp_set_faultcode(fault_code_t * fault, int code)
{
    fault->fault_code = code;
//    fault->fault_string = FAULT_STRING(code);
}


void cwmp_initialize_header(header_t * header)
{
    TRBZERO(header->id, CWMP_NAME_MAX);
    header->hold_requests = -1;
    header->no_more_requests = -1;
}


parameter_node_t * cwmp_initialize_parameter_node(env_t * env ,
        parameter_node_t * root, const char * name,
        int	rw,
        int	type,
        //const char * type,
        const char * value,
        parameter_get_handler_pt get,
        parameter_set_handler_pt set,
        parameter_notify_handler_pt notify)
{
    parameter_node_t * node;
    char * nodename;
    cwmp_log_debug("cwmp_initialize_parameter_node ...\n");
    if (cwmp_create_parameter_node(env ,  &node, name) != 0)
    {
        return NULL;
    }

    nodename = strrchr(name, '.');
    if (nodename)
    {
        node->name = XSTRDUP(nodename + 1);
    }
    else
    {
        node->name = XSTRDUP(name);
    }


    node->rw = rw;
    node->type = type;
    //node->type = type;
    node->value = XSTRDUP(value);
    if (value)
    {
        node->value_length = TRstrlen(value);
    }
    node->get = get;
    node->set = set;
    node->notify = notify;

    return node;
}





int cwmp_add_child_parameter_node(parameter_node_t * parent, parameter_node_t * child)
{
    parameter_node_t * node;
    cwmp_log_debug("cwmp_add_child_parameter_node ...\n");

    for (node = parent->child; node && node->next_sibling; node = node->next_sibling);

    if (node)
    {
        node->next_sibling = child;
    }
    else
    {
        parent->child = child;
    }

    child->prev_sibling = node;
    child->parent = parent;
    return 0;
}

int  cwmp_add_parameter_to_list(env_t * env ,  parameter_list_t * pl, parameter_t * parameter)
{
    if (pl->count >= pl->size-1)
    {
        parameter_t ** pp = XREALLOC(pl->parameters, pl->size * sizeof(parameter_t*), sizeof(parameter_t*) * (pl->size+CWMP_RENEW_SIZE));
        pl->parameters = pp;
        pl->size += CWMP_RENEW_SIZE;
    }
    pl->parameters[pl->count++] = parameter;
    return CWMP_OK;
}






void  cwmp_add_event_to_list(env_t * env ,  event_list_t * eventList, event_code_t * event)
{
    eventList->events[eventList->count++] = event;
}


int cwmp_split_parameter_name_list(char * name, char * namelist[])
{
    int i = 0;
    char * p;
    char * s = name;
    namelist[i++] = name;

    while ((p = strstr(s, ".")))
    {
        (*p) = 0;
        p ++;
        namelist[i++] = p;
    }
    namelist[i] = 0;

    return 0;
}


xmlnode_t * cwmp_get_header_node(xmldoc_t *  doc)
{
    xmlnode_t *  node;
    xmlnode_t *  root;
    ASSERT(doc != NULL);

    if (! (root = XmlNodeGetDocRoot(doc)))
    {
        cwmp_log_error("xml document root is null!");
        return NULL;
    }

    node = cwmp_xml_get_child_with_name(root, SOAP_ENV_HEADER);
    if (node == NULL)
    {
        cwmp_log_debug("xml soap header not found1!");
    }

    if(node == NULL){
    	if(strcmp(SOAP_ENV_HEADER, "SOAP-ENV:Header")==0){
    		node = cwmp_xml_get_child_with_name(root, "soap:Header");
		    if (node == NULL)
		    {
		        cwmp_log_info("xml soap header not found2!");
		    }
		 } 
	}
	
    return node;
}


xmlnode_t * cwmp_get_body_node(xmldoc_t *  doc)
{
    xmlnode_t *  node;
    xmlnode_t *  root;
    ASSERT(doc != NULL);
    if (! (root = XmlNodeGetDocRoot(doc)))
    {
        cwmp_log_error("xml document root is null!");
        return NULL;
    }

    node = cwmp_xml_get_child_with_name(root, SOAP_ENV_BODY);
    if (node == NULL)
    {
        cwmp_log_info("xml soap body not found1!");
    }

    if(node == NULL){
		if(strcmp(SOAP_ENV_BODY, "SOAP-ENV:Body")==0){
    		node = cwmp_xml_get_child_with_name(root, "soap:Body");
		    if (node == NULL)
		    {
		        cwmp_log_info("xml soap body not found2!");
		    }
		 } 
	}
	
    return node;
}


xmlnode_t *  cwmp_get_rpc_method_node(xmldoc_t *  doc)
{
    xmlnode_t * body;
    body = cwmp_get_body_node(doc);
    if (!body)
    {
        return NULL;
    }
    return XmlNodeGetFirstChild(body);
}


xmlnode_t * cwmp_get_rpc_node(xmldoc_t *   doc, const char * method)
{
    xmlnode_t * node;
    node = cwmp_get_rpc_method_node(doc);
    if (!node)
    {
        cwmp_log_error("doc get method is null!");
        return NULL;
    }
    if (TRstrcmp(node->nodeName, method))
    {
        cwmp_log_debug("doc get method(%s) is not %s!", node->nodeName, method);
        return NULL;
    }
    return node;
}

char * cwmp_get_rpc_method_name(xmldoc_t *  doc)
{
    xmlnode_t * node = cwmp_get_rpc_method_node(doc);
    if (!node)
    {
        return NULL;
    }
    return node->nodeName;
}

/*
   xmlnode_t * GetRpcInform(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_INFORM);
   }

   xmlnode_t * GetRpcInformResponse(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_INFORMRESPONSE);
   }

   xmlnode_t * GetRpcGetParameterNames(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_GETPARAMETERNAMES);
   }

   xmlnode_t * GetRpcGetParameterNamesResponse(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_GETPARAMETERNAMESRESPONSE);
   }

   xmlnode_t * GetRpcGetParameterValues(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_GETPARAMETERVALUES);
   }

   xmlnode_t * GetRpcGetParameterValuesResponse(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_GETPARAMETERVALUESRESPONSE);
   }

   xmlnode_t * GetRpcSetParameterValues(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_SETPARAMETERVALUES);
   }

   xmlnode_t * GetRpcSetParameterValuesResponse(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_SETPARAMETERVALUESRESPONSE);
   }

   xmlnode_t * GetRpcGetRPCMethods(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_GETRPCMETHODS);
   }

   xmlnode_t * GetRpcGetRPCMethodsResponse(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_GETRPCMETHODSRESPONSE);
   }

   xmlnode_t * GetRpcDownload(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_DOWNLOAD);
   }

   xmlnode_t * GetRpcDownloadResponse(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_DOWNLOADRESPONSE);
   }

   xmlnode_t * GetRpcUpload(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_UPLOAD);
   }

   xmlnode_t * GetRpcUploadResponse(xmldoc_t *  doc)
   {
   return cwmp_get_rpc_node(doc, CWMP_RPC_UPLOADRESPONSE);
   }

xmlnode_t * GetRpcReboot(xmldoc_t *  doc)
{
	return cwmp_get_rpc_node(doc, CWMP_RPC_REBOOT);
}

xmlnode_t * GetRpcRebootResponse(xmldoc_t *  doc)
{
	return cwmp_get_rpc_node(doc, CWMP_RPC_REBOOTRESPONSE);
}

*/

parameter_node_t * get_node_after_paramname(parameter_node_t * param, char *name)
{
	parameter_node_t * child;
	parameter_node_t * tmp;
	parameter_node_t * next;

	if(!param) 
		return NULL; 
	
	if(TRstrcmp(param->name, name) == 0)	
		return param;
	
	child = param->child;
	if(!child)
		return NULL; 
	
	tmp = get_node_after_paramname(child, name);
	if(tmp != NULL)
		return tmp;

	next = child->next_sibling;
	while(next)
	{
		tmp = get_node_after_paramname(next, name);
		if(tmp != NULL)
			return tmp;
			
		next = next->next_sibling;
	}	
	
	return NULL; 
}


char * cwmp_get_parameter_nodename(const char * name, char * buffer)
{
    char *p = (char *)name;
    char *q = buffer;

    while (*p)
    {
        if (*p == '.')
            break;

        *q++ = *p++;
    }

    if (*p) p++;

    *q = '\0';

    return p;
}




parameter_node_t * cwmp_get_parameter_node(parameter_node_t * root, const char * param_name)
{
    parameter_node_t * node = root;
    char * dot;
    char  name[256];

    if ((!node) || (!param_name)){
    	cwmp_log_info("cwmp_get_parameter_node bad param");
        return NULL;
    }

    dot = (char*)param_name;
    while (*dot)
    {

        dot = cwmp_get_parameter_nodename(dot, name);
        while (node && node->name)
        {
            if (TRstrcmp(node->name, name) == 0)
            {

                break;
            }
            node = node->next_sibling;
        }

        if (!node)
        {
            return NULL;
        }

        if ((dot) && (*dot == 0))
        {
            break;
        }

        node = node->child;
    }
    if (!node)
    {
        cwmp_log_error("Not found param node: %s\n", param_name);
    }
    return node;
}


parameter_node_t * cwmp_get_parameter_path_node(parameter_node_t * parent, const char * param_name)
{
    parameter_node_t * param_node = parent;
    const char * dot;
    char  name[256];
    
    if ((!param_node) || (!param_name))
        return NULL;

    dot = (char *)param_name;
    while (*dot)
    {

        dot = cwmp_get_parameter_nodename(dot, name);

        while (param_node && param_node->name)
        {
	    	if(TRstrcmp(param_node->name, "{i}") == 0)
            {
				param_node = param_node->next_sibling;
				continue;
            }


            if (TRstrcmp(param_node->name, name) == 0)
            {
                //cwmp_log_debug("Found param node: %s\n", name);
                break;
            }
            if (param_node->next_sibling)
            {
                param_node = param_node->next_sibling;
            }
            else
            {
                if (*dot != 0)
                {
                    cwmp_log_error("Error param node path. %s\n", param_name);
                    return NULL;
                }
                else
                {
                    if (param_node->parent)
                    {
                        //cwmp_log_debug("Found param node path: %s.\n", param_node->parent->name);
                    }
                    else
                    {
                        cwmp_log_info("Not found param node parent path: %s.\n", param_name);
                    }
                    return param_node->parent;
                }
            }
        }

        if (!param_node)
        {
            return NULL;
        }

        if ((dot) && (*dot == 0))
        {
            break;
        }
        if (param_node->child)
        {
            param_node = param_node->child;
        }
        else
        {
            break;
        }

    }
    if (param_node)
    {
        cwmp_log_debug("Found param node path: %s.\n", param_node->name);
    }
    else
    {
        cwmp_log_error("Not found param node path: %s.\n", param_name);
    }
    return param_node;

}

int cwmp_get_parameter_node_value(cwmp_t * cwmp, parameter_node_t * node, const char * name, char ** value, pool_t * pool)
{

    if (!node)
    {
        return FAULT_CODE_9000;
    }
    if (node->get)
    {
        return (*node->get)(cwmp, name, value, pool);
    }
    else
    {
        return FAULT_CODE_9000;
    }
}

int cwmp_set_parameter_node_value(cwmp_t * cwmp, parameter_node_t * node, const char * name, const char * value, int value_length)
{

    if (!node)
    {
        return CWMP_ERROR;
    }
    if (node->set)
    {
        return (*node->set)(cwmp, name,  value, value_length, callback_register_task);
    }
    else
    {
        if (node->value)
        {
            FREE(node->value);
        }

	      //it's ok , no memory less
        node->value = TRstrdup(value);
        node->value_length = value_length;
        return CWMP_OK;
    }
}

int cwmp_set_parameter_attributes(cwmp_t *cwmp, const char *name, int notiChange, int noti)
{
    if(!notiChange)
        return FAULT_CODE_OK;

    parameter_node_t *pn = cwmp_get_parameter_node(cwmp->root, name);
    if(pn == NULL)
        return FAULT_CODE_9005;
    switch(noti)
    {
        case 0:
        case 1:
        case 2:
            pn->attr.nc = noti;
            return FAULT_CODE_OK;
        case 3:
        case 4:
        case 5:
        case 6:
            return FAULT_CODE_9003;
        default:
            return FAULT_CODE_9003;
    }
}

int cwmp_parse_header_node(xmlnode_t * node, header_t ** header, pool_t * pool)
{
    xmlnode_t * cwmpIdNode;
    xmlnode_t * cwmpHoldRequestsNode;
    xmlnode_t * cwmpNoMoreRequestsNode;
    char * value;

    *header  = NULL;
    if (node)
    {
        (*header) = pool_pcalloc(pool, sizeof(header_t));
        cwmpIdNode = cwmp_xml_get_child_with_name(node, CWMP_XML_HEADER_ID);
        cwmpHoldRequestsNode = cwmp_xml_get_child_with_name(node, CWMP_XML_HEADER_HOLDREQUESTS);
	cwmpNoMoreRequestsNode = cwmp_xml_get_child_with_name(node, CWMP_XML_HEADER_NOMOREREQUESTS);
        if (cwmpIdNode == NULL || cwmpHoldRequestsNode == NULL || cwmpNoMoreRequestsNode == NULL)
        {
            cwmp_log_debug("TR069Header cwmp:ID=%s, cwmp:HoldRequests=%s, cwmp:NoMoreRequests=%s",
                           cwmpIdNode ? cwmp_xml_get_node_value(cwmpIdNode):"null",
                           cwmpHoldRequestsNode ? cwmp_xml_get_node_value(cwmpHoldRequestsNode):"null",
                           cwmpNoMoreRequestsNode ? cwmp_xml_get_node_value(cwmpNoMoreRequestsNode):"null");
        }
        value = cwmp_xml_get_node_value(cwmpIdNode);
        if ((cwmpIdNode != NULL) || (value != NULL))
        {
            (*header)->id = pool_pcalloc(pool, CWMP_HEAD_MAX+1);
            TRstrncpy((*header)->id, value, CWMP_HEAD_MAX);
        }

        if (cwmpHoldRequestsNode != NULL)
        {
            value = cwmp_xml_get_node_value(cwmpHoldRequestsNode);
            (*header)->hold_requests = TRatoi(value);
        }

        if (cwmpNoMoreRequestsNode != NULL)
        {
            value = cwmp_xml_get_node_value(cwmpNoMoreRequestsNode);
            (*header)->no_more_requests = TRatoi(value);
        }


        return CWMP_OK;
    }

    return CWMP_ERROR;
}




int cwmp_parse_inform_response_message(xmlnode_t * node, unsigned int *max_envelopes)
{
    xmlnode_t * cwmpMaxEnvelopes;
    const char * value;
    if (node)
    {
        cwmpMaxEnvelopes = cwmp_xml_get_child_with_name(node, CWMP_XML_INFORM_MAXENVELOPES);
        if (!cwmpMaxEnvelopes)
        {
            return CWMP_ERROR;
        }
        value = XmlNodeGetNodeValue(cwmpMaxEnvelopes);
        if (!value)
        {
            cwmp_log_error("Invalid InformResponse MaxEnvelopes is null");
            return CWMP_ERROR;
        }
        (*max_envelopes) = TRatoi(value);
        return CWMP_OK;
    }

    return CWMP_ERROR;
}

//cwmp_parse_getrpcmethods_message
xmldoc_t * cwmp_parse_getrpcmethods_message(xmldoc_t *doc)
{
    return NULL;
}


int cwmp_parse_getparameternames_message(env_t * env, xmldoc_t * doc, char ** path_name, unsigned int * next_level, fault_code_t *fault)
{
    xmlnode_t * cwmpParamPath;
    xmlnode_t * cwmpNextLevel;
    const char * nl;
    xmlnode_t * node = cwmp_get_rpc_method_node(doc);

    cwmpParamPath = cwmp_xml_get_child_with_name(node, CWMP_XML_GETPARAMETERNAMES_PARAMETERPATH);
    cwmpNextLevel = cwmp_xml_get_child_with_name(node, CWMP_XML_GETPARAMETERNAMES_NEXTLEVEL);
    if (path_name)
    {
        *path_name = pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmpParamPath));

    }
    nl = cwmp_xml_get_node_value(cwmpNextLevel);
    if (!nl)
    {
        cwmp_log_error("Invalid GetParameterNames NextLevel is null");
        nl = "0";
    }
    if (TRstrcmp(nl,"true") == 0 || TRstrcmp(nl,"1") == 0)
    {
        (*next_level) = 1;
    }
    else
    {
        (*next_level) = 0;
    }
    return CWMP_OK;
}

int cwmp_parse_get_single_parameter_value(env_t * env, pool_t * pool, parameter_node_t * root, parameter_list_t ** ppl, fault_code_t *fault, char *name)
{
    int rc;
	parameter_node_t * pn = cwmp_get_parameter_node(root, name);
	if (!pn)
	{
		//Create Fault code;
		fault->fault_code = FAULT_CODE_9003;
		cwmp_log_error("can not find parameter %s.", name);
		return CWMP_ERROR;
	}
	else
	{
		parameter_t * parameter;// = cwmp_create_parameter(env ,  name, NULL, 0, pn->type);

		if (pn->get)
		{
			//exec get
			char * value = NULL;
			rc = (*pn->get)(env->cwmp, name, &value, pool);
			if(rc != FAULT_CODE_OK)
			{
			   fault->fault_code = rc;
			   return CWMP_ERROR;

			}
			
			parameter = cwmp_create_parameter(env ,  name, value, TRstrlen(value), pn->type);

		}
		else
		{
			parameter = cwmp_create_parameter(env ,  name, pn->value, pn->value_length, pn->type);
		}

		if (!parameter)
		{
			return CWMP_OK;
		}

		if ((*ppl)->count >= (*ppl)->size - 1)
		{
			parameter_t ** pp = XREALLOC((*ppl)->parameters, (*ppl)->size * sizeof(parameter_t*), sizeof(parameter_t*) * ((*ppl)->size + CWMP_RENEW_SIZE));
			if (!pp)
			{
				return CWMP_ERROR;
			}
			(*ppl)->parameters = pp;
			(*ppl)->size += CWMP_RENEW_SIZE;
		}
		
		parameter_t ** pv;
		pv = (*ppl)->parameters;
		*(pv + (*ppl)->count) = parameter;
		(*ppl)->count++;

	}
	
	return CWMP_OK;

}

void cwmp_refresh_special_param(env_t * env, parameter_node_t * pn, char * path_name)
{
    int rc;

    if (!pn)
        return;
    if(strstr(path_name, "Hosts.Host.") || strstr(path_name, "AssociatedDevice"))
    {
        if (pn->refresh)
        {
            pn->refresh(env->cwmp, pn, callback_register_task);
        }
    }
}

void * cwmp_parse_walk_node(env_t * env , pool_t * pool, parameter_node_t * root, parameter_list_t ** ppl, fault_code_t *fault, parameter_node_t *  param_node, const char * path_name, int * count)
{
    char buffer[256];
    parameter_node_t * param_child;

    if (!param_node)
        return NULL;
	
    cwmp_refresh_special_param(env, param_node, path_name);
    for (param_child = param_node->child; param_child!=NULL; param_child = param_child->next_sibling)
    {
        if(TRstrcmp(param_child->name, "{i}") == 0 || 
			TRstrcmp(param_child->name, "IPPingDiagnostics") == 0 ||
			TRstrcmp(param_child->name, "TraceRouteDiagnostics") == 0)
            continue;
		
        memset(buffer, 0, sizeof(buffer));
        if (param_child->type == TYPE_OBJECT)
        {
            sprintf(buffer, "%s%s.", path_name, param_child->name);
            //cwmp_log_debug("walk obj %s", buffer);
        	cwmp_parse_walk_node(env, pool, root, ppl, fault, param_child, buffer, count);
        }
        else
        {
            sprintf(buffer, "%s%s", path_name, param_child->name);
            //cwmp_log_debug("walk param %s", buffer);
			cwmp_parse_get_single_parameter_value(env, pool, root, ppl, fault, buffer);
        }
    }

    return NULL;
}


int cwmp_parse_getparametervalues_message(env_t * env , xmldoc_t * doc, parameter_node_t * root, parameter_list_t ** ppl, fault_code_t *fault)
{
    cwmp_buffer_t buffer;
    xmlnode_t * parameterListNode;
    xmlnode_t * parameterNode;
	parameter_node_t *node;
	
    char name[256];
    int	count = 0;
	int rv = 0;

    parameterListNode = cwmp_xml_get_child_with_name(cwmp_get_rpc_method_node(doc), "ParameterNames");


    if (!parameterListNode || !ppl)
    {
        return CWMP_ERROR;
    }

    *ppl = cwmp_create_parameter_list(env );
    ESE(CWMP_ERROR, NULL, *ppl);

    pool_t * pool = pool_create(POOL_DEFAULT_SIZE);

    parameterNode = XmlNodeGetFirstChild(parameterListNode);
    while (parameterNode)
    {
        char *pt_name = cwmp_xml_get_node_value(parameterNode);
        if(pt_name == NULL)
            strcpy(name, ".");
        else
            strcpy(name, pt_name);
        cwmp_log_debug("Name: %s\n", name);
		if (name[strlen(name)-1] == '.')
		{
			node = cwmp_get_parameter_path_node(root, name);
			if(node!=NULL)
				cwmp_parse_walk_node(env, pool, root, ppl, fault, node, name, &count);
		}
		else
		{
			rv = cwmp_parse_get_single_parameter_value(env, pool, root, ppl, fault, name);
			if (rv == CWMP_ERROR) {
				if(fault->fault_code != FAULT_CODE_OK)
				{
				   return CWMP_ERROR;
				}
				break;
			}
		}

        parameterNode = XmlNodeGetNextSibling(parameterNode);

    }

    return CWMP_OK;
}


//cwmp_parse_setparametervalues_message
int  cwmp_parse_setparametervalues_message(env_t * env , xmldoc_t * doc, parameter_node_t * root, parameter_list_t ** ppl, fault_code_t *fault)
{
    xmlnode_t * parameterListNode;
    xmlnode_t * parameterNode;
    parameter_t ** nextpv;
    int rc = CWMP_OK;

    parameterListNode = cwmp_xml_get_child_with_name(cwmp_get_rpc_method_node(doc), "ParameterList");


    if (!parameterListNode || !ppl)
    {
        return CWMP_ERROR;
    }

    *ppl = cwmp_create_parameter_list(env);
    ESE(CWMP_ERROR, NULL, *ppl);

    nextpv = (*ppl)->parameters;

    parameterNode = XmlNodeGetFirstChild(parameterListNode);

    while (parameterNode)
    {
		xmlnode_t * pnode  = parameterNode;

		parameterNode = XmlNodeGetNextSibling(parameterNode);

        const char * name = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(pnode, "Name"));
        const char * value = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(pnode, "Value"));
		cwmp_log_debug("set parameter value (%s=%s)", name, value);
		parameter_t * parameter = cwmp_create_parameter(env ,  name, value, TRstrlen(value), 0);
		
		if (!parameter)
        {
            //faild
            continue;
        }
        
        parameter_node_t * pn = cwmp_get_parameter_node(root, name);
        if (!pn)
        {
            //Create Fault code;
            parameter->fault_code = FAULT_CODE_9003;
            cwmp_log_error("can not find parameter %s.", name);
            continue;
        }
        else
        {
            parameter->type = pn->type;

            if(pn->set)
            {
				//exec set function
				parameter->fault_code =  (*pn->set)(env->cwmp, name,  value, TRstrlen(value), callback_register_task);
            }
		    else
		    {
				parameter->fault_code = FAULT_CODE_9008;
		    }

		    if(parameter->fault_code != FAULT_CODE_OK)
		    {
				cwmp_set_faultcode(fault, FAULT_CODE_9003);
				rc = CWMP_ERROR;
		    }

	        if ((*ppl)->count >= (*ppl)->size - 1)
	        {
	            parameter_t ** pp = XREALLOC((*ppl)->parameters, (*ppl)->size * sizeof(parameter_t*), sizeof(parameter_t*) * ((*ppl)->size + CWMP_RENEW_SIZE));
	            if (!pp)
	            {
	                continue;
	            }
	            
	            (*ppl)->parameters = pp;
	            (*ppl)->size += CWMP_RENEW_SIZE;
	        }
	        
			(*ppl)->count += 1;
	        *nextpv = parameter;
			nextpv++;

		}
    }

    return rc;
}

int  cwmp_parse_setparameterattributes_message(env_t * env , xmldoc_t * doc, parameter_node_t * root, parameter_list_t ** ppl, fault_code_t *fault)
{
    xmlnode_t * parameterListNode;
    xmlnode_t * parameterNode;
    parameter_t ** nextpv;
    int rc = CWMP_OK;

    parameterListNode = cwmp_xml_get_child_with_name(cwmp_get_rpc_method_node(doc), "ParameterList");


    if (!parameterListNode || !ppl)
    {
        return CWMP_ERROR;
    }

    *ppl = cwmp_create_parameter_list(env);
    ESE(CWMP_ERROR, NULL, *ppl);

    nextpv = (*ppl)->parameters;

    parameterNode = XmlNodeGetFirstChild(parameterListNode);

    while (parameterNode)
    {
		xmlnode_t * pnode  = parameterNode;
		xmlnode_t *pAccessListNode, *pStringNode;

		parameterNode = XmlNodeGetNextSibling(parameterNode);

        const char * name = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(pnode, "Name"));
        const char * notificationChange = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(pnode, "NotificationChange"));
        const char * notification = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(pnode, "Notification"));
        const char * accessListChange = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(pnode, "AccessListChange"));
        char *accListString=NULL;

		pAccessListNode = cwmp_xml_get_child_with_name(pnode, "AccessList");
		if(pAccessListNode != NULL){
			pStringNode = cwmp_xml_get_child_with_name(pAccessListNode, "string");
			if(pStringNode != NULL){
				accListString = cwmp_xml_get_node_value(pStringNode);
			}
        }
        
		cwmp_log_debug("set attr name=%s notiChg=%s noti=%s accChg=%s str=%s", 
						name, notificationChange, notification, accessListChange, accListString);
		
		parameter_t * parameter = cwmp_create_parameter(env ,  name, NULL, 0, 0);
		
		if (!parameter)
        {
            //faild
            continue;
        }
        
        parameter_node_t * pn = cwmp_get_parameter_node(root, name);
        if (!pn)
        {
            //Create Fault code;
            parameter->fault_code = FAULT_CODE_9003;
            cwmp_log_error("can not find parameter %s.", name);
            continue;
        }
        else
        {
            parameter->type = pn->type;

            if(pn->setattr)
            {
				//exec set function
				parameter_list_t *accessList = cwmp_create_parameter_list(env);
    			ESE(CWMP_ERROR, NULL, accessList);

				parameter_t *parameter_list_node = cwmp_create_parameter(env,  "string", accListString, 0, TYPE_STRING);
    			cwmp_add_parameter_to_list(env, accessList, parameter_list_node);
    			
				parameter->fault_code =  (*pn->setattr)(env->cwmp, 
														name,  
														atoi(notificationChange), 
														atoi(notification),
														accessList,
														atoi(accessListChange), 
														callback_register_task);

														
														
            }
		    else
		    {
				parameter->fault_code = FAULT_CODE_9008;
		    }

		    if(parameter->fault_code != FAULT_CODE_OK)
		    {
				cwmp_set_faultcode(fault, FAULT_CODE_9003);
				rc = CWMP_ERROR;
		    }

	        if ((*ppl)->count >= (*ppl)->size - 1)
	        {
	            parameter_t ** pp = XREALLOC((*ppl)->parameters, (*ppl)->size * sizeof(parameter_t*), sizeof(parameter_t*) * ((*ppl)->size + CWMP_RENEW_SIZE));
	            if (!pp)
	            {
	                continue;
	            }
	            
	            (*ppl)->parameters = pp;
	            (*ppl)->size += CWMP_RENEW_SIZE;
	        }
	        
			(*ppl)->count += 1;
	        *nextpv = parameter;
			nextpv++;

		}
    }

    return rc;
}



int cwmp_parse_download_message(env_t * env , xmldoc_t *doc, download_arg_t ** pdlarg, fault_code_t *fault)
{
    xmlnode_t * commandKeyNode;
    xmlnode_t * cwmpNextLevel;
    const char * nl;
    FUNCTION_TRACE();
    xmlnode_t * node = cwmp_get_rpc_method_node(doc);
    download_arg_t * dlarg = pool_pcalloc(env->pool, sizeof(download_arg_t));

   //FIXME
   dlarg->cmdkey = pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "CommandKey")));
   dlarg->filetype= pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "FileType")));
   dlarg->url = pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "URL")));
   dlarg->username= pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "Username")));
   dlarg->password = pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "Password")));
   dlarg->filesize= TRatoi(cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "FileSize")));

   dlarg->targetname= pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "TargetFileName")));
   dlarg->delaysec= TRatoi(cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "DelaySeconds")));
   dlarg->succurl= pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "SuccessURL")));
   dlarg->failurl= pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "FailureURL")));

    *pdlarg = dlarg;

    return CWMP_OK;
}


int cwmp_parse_upload_message(env_t * env , xmldoc_t *doc, upload_arg_t ** pularg, fault_code_t *fault)
{

    xmlnode_t * node = cwmp_get_rpc_method_node(doc);
    upload_arg_t * ularg = pool_pcalloc(env->pool, sizeof(download_arg_t));

   ularg->cmdkey = pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "CommandKey")));
   ularg->filetype= pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "FileType")));
   ularg->url = pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "URL")));
   ularg->username= pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "Username")));
   ularg->password = pool_pstrdup(env->pool, cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "Password")));
   ularg->delaysec= TRatoi(cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "DelaySeconds")));

    *pularg = ularg;

    return CWMP_OK;
}


int cwmp_parse_addobject_message(env_t * env , xmldoc_t *doc, parameter_node_t * root,  int * instances, int* status, fault_code_t *fault)
{

    xmlnode_t * node = cwmp_get_rpc_method_node(doc);
    int fault_code;
    int instance_num;

    char * object_name = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "ObjectName"));
    char * parameter_key = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "ParameterKey"));
	cwmp_log_info("parse_addobject_message name=%s", object_name);
	cwmp_log_info("parse_addobject_message key=%s", parameter_key);

    parameter_node_t * param = cwmp_get_parameter_path_node(root, object_name);
    if(!param)
    {
        cwmp_log_error("can't find AddObject parameter ObjectName %s\n", object_name);
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }
    parameter_node_t * child_param = param->child;
    cwmp_log_info("name=%s type=%d rw=%d childName=%s",
    	param->name, param->type, param->rw, child_param->name);
    if( (param->type != TYPE_OBJECT) || (param->rw  != 1) || (TRstrcmp(child_param->name, "{i}") != 0))
    {
        cwmp_log_error("AddObject parameter ObjectName %s is invalid or not writable\n", object_name);
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }
    if(! param->add)
    {
        cwmp_log_error("could not find %s add object function\n", object_name);
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }

    fault_code = param->add(env->cwmp, param, &instance_num, callback_register_task);

    if(fault_code != FAULT_CODE_OK)
    {
        cwmp_log_error("exec %s add object function failed\n", object_name);
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }

    *instances = instance_num;

    return CWMP_OK;
}

extern void walk_xmlDoc_node_tree(XmlNode * param, int level);
extern void _walk_parameter_node_tree(parameter_node_t * param, int level);;
int cwmp_parse_deleteobject_message(env_t * env , xmldoc_t *doc, parameter_node_t * root, int* status, fault_code_t *fault)
{

    xmlnode_t * node = cwmp_get_rpc_method_node(doc);
    int fault_code;
    int instance_num;

    char * object_name = cwmp_xml_get_node_value(cwmp_xml_get_child_with_name(node, "ObjectName"));


    parameter_node_t * param = cwmp_get_parameter_path_node(root, object_name);
    if(!param)
    {
        cwmp_log_error("can't find DeleteObject parameter ObjectName %s\n", object_name);
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }

    if((param->type == TYPE_OBJECT && object_name[strlen(object_name)-1] != '.') ||  param->type != TYPE_OBJECT)
    {
        cwmp_log_error("DeleteObject parameter ObjectName %s is invalid\n", object_name);
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }

    if(is_digit(param->name) != 0)
    {
        cwmp_log_error("DeleteObject parameter ObjectName %s is not digit\n", object_name);
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }

    parameter_node_t * parent = param->parent;
    if(! parent->del)
    {
        cwmp_log_error("could not find %s delete object function\n", object_name);
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }

    instance_num = TRatoi(param->name);

    fault_code = param->parent->del(env->cwmp, param, instance_num, callback_register_task);

    if(fault_code != FAULT_CODE_OK)
    {
        cwmp_set_faultcode(fault, FAULT_CODE_9005);
        return CWMP_ERROR;
    }


    return CWMP_OK;
}


int cwmp_parse_reboot_message(env_t * env , xmldoc_t *doc, char ** key, fault_code_t *fault)
{
    xmlnode_t * commandKeyNode;




    commandKeyNode = cwmp_xml_get_child_with_name(cwmp_get_rpc_method_node(doc), "CommandKey");

    if (!commandKeyNode)
    {
        return CWMP_ERROR;
    }

    *key = cwmp_xml_get_node_value(commandKeyNode);

    return CWMP_OK;
}

download_arg_t * cwmp_clone_download_arg(download_arg_t * dlarg)
{
	if(!dlarg)
	{
		return NULL;
	}
	download_arg_t * newdl = MALLOC(sizeof(download_arg_t));
	if(!newdl)
	{
		return NULL;
	}
	newdl->cmdkey = TRstrdup(dlarg->cmdkey);
	newdl->filetype = TRstrdup(dlarg->filetype);
	newdl->url = TRstrdup(dlarg->url);
	newdl->username = TRstrdup(dlarg->username);
	newdl->password = TRstrdup(dlarg->password);
	newdl->targetname = TRstrdup(dlarg->targetname);
	newdl->succurl = TRstrdup(dlarg->succurl);
	newdl->failurl = TRstrdup(dlarg->failurl);
	newdl->delaysec = dlarg->delaysec;
	newdl->filesize = dlarg->filesize;

	cwmp_log_debug("download arg: %s, %s, %s, %s, %s, targetname:%s,%s,%s, delaysecond:%d,%d",
		newdl->cmdkey?newdl->cmdkey:"null",
		newdl->filetype?newdl->filetype:"null",
		newdl->url?newdl->url:"null",
		newdl->username?newdl->username:"null",
		newdl->password?newdl->password:"null",
		newdl->targetname?newdl->targetname:"null",
		newdl->succurl?newdl->succurl:"null",
		newdl->failurl?newdl->cmdkey:"null",
		newdl->delaysec, newdl->filesize);



	return newdl;

}

upload_arg_t * cwmp_clone_upload_arg(upload_arg_t * ularg)
{
	if(!ularg)
	{
		return NULL;
	}
	upload_arg_t * newul = MALLOC(sizeof(upload_arg_t));
	if(!newul)
	{
		return NULL;
	}
	newul->cmdkey = TRstrdup(ularg->cmdkey);
	newul->filetype = TRstrdup(ularg->filetype);
	newul->url = TRstrdup(ularg->url);
	newul->username = TRstrdup(ularg->username);
	newul->password = TRstrdup(ularg->password);
	newul->delaysec = ularg->delaysec;


	return newul;

}




parameter_t* cwmp_create_parameter(env_t * env ,  const char * name, const char * value, size_t value_length, int type)
{
    parameter_t * pv = XMALLOC(sizeof(parameter_t));
    if (!pv)
    {
        return NULL;
    }

    pv->name = XSTRDUP(name);

    pv->value = XSTRDUP(value);
    pv->value_length = value_length;

    pv->type = type;
    pv->fault_code = 0;


    return pv;
}

event_list_t * cwmp_create_event_list(env_t * env, int size )
{
    event_list_t * el;
    el = cwmp_event_list_create(env->pool, size);

    return el;
}

event_code_t * cwmp_create_event_code(env_t * env )
{
    event_code_t * ev;
    ev = cwmp_event_code_create(env->pool);
    return ev;
}

parameter_list_t* cwmp_create_parameter_list(env_t * env )
{
    parameter_list_t * pl;
    pl = XMALLOC(sizeof(parameter_list_t));
    if (!pl)
    {
        return NULL;
    }
    TRBZERO(pl, sizeof(parameter_list_t));

    pl->parameters = XMALLOC(sizeof(parameter_t*) * CWMP_RENEW_SIZE);
    pl->count = 0;
    pl->size = CWMP_RENEW_SIZE;

    return pl;
}



xmlnode_t * cwmp_create_current_time_node(env_t * env ,   xmlnode_t * parent, const datatime_t *currentt)
{
    char buffer[CWMP_BUF_SIZE];

    xmlnode_t * currTimeNode;
    FUNCTION_TRACE();
    TRsnprintf(buffer, CWMP_BUF_SIZE, "%02d-%02d-%4dT%02d:%02d:%02dZ",
               currentt->month,
               currentt->day,
               currentt->year,
               currentt->hour,
               currentt->min,
               currentt->sec);

    ESA(currTimeNode, cwmp_xml_create_child_node(env ,  parent, NULL, "CurrentTime", buffer));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  currTimeNode, SOAP_XSI_TYPE, SOAP_XSD_DATETIME));

    return currTimeNode;
}


xmlnode_t * cwmp_create_event_node(env_t * env ,  xmlnode_t * parent, const event_list_t * eventlist)
{
    xmlnode_t * eventNode, *eventStructNode,  * eventCodeNode, * eventCommandKeyNode;

    int count = 0;


    event_code_t ** pe = eventlist->events;

    FUNCTION_TRACE();
    ESA(eventNode, cwmp_xml_create_child_node(env ,  parent, NULL, "Event", NULL));

    while (count < eventlist->count)
    {
        ESA(eventStructNode, cwmp_xml_create_child_node(env ,  eventNode, NULL, "EventStruct", NULL));

        ESA(eventCodeNode, cwmp_xml_create_child_node(env ,  eventStructNode, NULL, "EventCode", pe[count]->code));
        ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  eventCodeNode, SOAP_XSI_TYPE, SOAP_XSD_STRING));

		if (pe[count]->event == INFORM_MREBOOT ) //|| pe[count]->event == INFORM_BOOTSTRAP)
		{
	        ESA(eventCommandKeyNode, cwmp_xml_create_child_node(env ,  eventStructNode, NULL, "CommandKey", pe[count]->command_key));
		}
		else
		{
			ESA(eventCommandKeyNode, cwmp_xml_create_child_node(env ,  eventStructNode, NULL, "CommandKey", NULL));
		}
        ++count ;
    }


    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  eventNode, SOAP_ENC_ARRAYTYPE, cwmp_get_format_string("cwmp:EventStruct[%d]", count)));

    return eventNode;
}


xmlnode_t * cwmp_create_header_node(env_t * env ,   xmlnode_t * root, header_t * header)
{
    xmlnode_t * headerNode;
    xmlnode_t * idNode;
    //xmlnode_t * holdRequestsNode;
    FUNCTION_TRACE();
    ESA(headerNode, cwmp_xml_create_child_node(env ,  root, NULL, SOAP_ENV_HEADER, NULL));
    ESA(idNode, cwmp_xml_create_child_node(env ,  headerNode, NULL, CWMP_XML_HEADER_ID, header->id));
    //ESA(holdRequestsNode, cwmp_xml_create_child_node(env ,  headerNode, NULL, CWMP_XML_HEADER_HOLDREQUESTS, NULL));

    ESN(XML_OK, cwmp_xml_set_node_attribute(env , idNode, cwmp_get_format_string("%s:%s", SOAP_ENV, CWMP_XML_MUSTUNDERSTAND), "1"));
    //ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  holdRequestsNode, XMLNS_APPEND(SOAP_ENV, CWMP_XML_MUSTUNDERSTAND), "1"));

    return headerNode;
}

xmlnode_t * cwmp_create_body_node(env_t * env ,  xmlnode_t * root)
{
    xmlnode_t * bodyNode;
    FUNCTION_TRACE();
    ESA(bodyNode, cwmp_xml_create_child_node(env ,  root, NULL, SOAP_ENV_BODY, NULL));
    return bodyNode;
}

xmlnode_t * cwmp_create_envelope_node(env_t * env ,  xmlnode_t * parent)
{

    xmlnode_t * envelopeNode;
    FUNCTION_TRACE();
    cwmp_log_debug("ENV: %s, ENC: %s\n", SOAP_ENV, SOAP_ENC);
    ESA(envelopeNode, cwmp_xml_create_child_node(env ,  parent, NULL, SOAP_ENV_ENVELOPE, NULL));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  envelopeNode, cwmp_get_format_string("%s:%s", "xmlns", SOAP_ENV), SOAP_ENV_NS));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  envelopeNode, cwmp_get_format_string("%s:%s", "xmlns", SOAP_ENC), SOAP_ENC_NS));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  envelopeNode, cwmp_get_format_string("%s:%s", "xmlns", "xsi"), SOAP_XSI_NS));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  envelopeNode, cwmp_get_format_string("%s:%s", "xmlns", "xsd"), SOAP_XSD_NS));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  envelopeNode, cwmp_get_format_string("%s:%s", "xmlns", "cwmp"), SOAP_CWMP_NS));

    return envelopeNode;
}


xmlnode_t * cwmp_create_device_id_node(env_t * env ,  xmlnode_t * parent, const device_id_t * deviceid)
{
    xmlnode_t * deviceIdNode;
    xmlnode_t * mf;
    xmlnode_t * oui;
    xmlnode_t * pc;
    xmlnode_t * sn;

    FUNCTION_TRACE();

    ESA(deviceIdNode, cwmp_xml_create_child_node(env ,  parent, NULL, "DeviceId", NULL));

    ESA(mf, cwmp_xml_create_child_node(env ,  deviceIdNode, NULL, "Manufacturer", env->cwmp->cpe_mf));

    ESA(oui, cwmp_xml_create_child_node(env ,  deviceIdNode, NULL, "OUI", env->cwmp->cpe_oui));

    ESA(pc, cwmp_xml_create_child_node(env ,  deviceIdNode, NULL, "ProductClass", env->cwmp->cpe_pc));

    ESA(sn, cwmp_xml_create_child_node(env ,  deviceIdNode, NULL, "SerialNumber",  env->cwmp->cpe_sn));


    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  deviceIdNode, SOAP_XSI_TYPE, "cwmp:DeviceIdStruct"));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  mf, SOAP_XSI_TYPE, SOAP_XSD_STRING));
    //ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  mf, SOAP_XSI_NAME, deviceId->name));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  oui, SOAP_XSI_TYPE, SOAP_XSD_STRING));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  pc, SOAP_XSI_TYPE, SOAP_XSD_STRING));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  sn, SOAP_XSI_TYPE, SOAP_XSD_STRING));


    return deviceIdNode;
}




xmlnode_t * cwmp_create_max_envelope_node(env_t * env ,  xmlnode_t * parent, unsigned int max_envelope)
{
    xmlnode_t * maxEnvNode;

    FUNCTION_TRACE();

    ESA(maxEnvNode, cwmp_xml_create_child_node(env ,  parent, NULL, CWMP_XML_INFORM_MAXENVELOPES, cwmp_get_format_string("%d", max_envelope)));

    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  maxEnvNode, SOAP_XSI_TYPE, SOAP_XSD_UNSIGNEDINT));

    return maxEnvNode;
}


xmlnode_t * cwmp_create_retry_count_node(env_t * env ,  xmlnode_t * parent, unsigned int retry_count)
{
    xmlnode_t * retryCountNode;
    FUNCTION_TRACE();

    ESA(retryCountNode, cwmp_xml_create_child_node(env ,  parent, NULL, "RetryCount", cwmp_get_format_string("%d", retry_count)));

    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  retryCountNode, SOAP_XSI_TYPE, SOAP_XSD_UNSIGNEDINT));

    return retryCountNode;
}


int cwmp_create_parameter_node(env_t * env ,  parameter_node_t ** news, const char * name)
{
    parameter_node_t * param_node = XMALLOC(sizeof(parameter_node_t));
    cwmp_log_debug("cwmp_create_parameter_node ...\n");
    if (!param_node)
    {
        return CWMP_ERROR;
    }
    //param_node->full_name = XSTRDUP(name);
    param_node->name = NULL;
    param_node->rw = 0;
    param_node->type = 0;
    //param_node->type = NULL;
    param_node->value = NULL;
    param_node->child = param_node->next_sibling = param_node->prev_sibling = param_node->parent = NULL;

    (*news) = param_node;

    return CWMP_OK;
}


xmlnode_t * cwmp_create_parameter_list_node(env_t * env ,  xmlnode_t * parent, parameter_list_t * pl)
{
    xmlnode_t * parameterValueStructNode;
    parameter_t ** ps;
    parameter_t* pv;
    xmlnode_t * parameterListNode, *nameNode, *valueNode;
    int i = 0;

    FUNCTION_TRACE();

    ESA(parameterListNode, cwmp_xml_create_child_node(env ,  parent, NULL, "ParameterList", NULL));
    ps = pl->parameters;

    while (i < pl->count)
    {
        pv = *ps;
        ESA(parameterValueStructNode, cwmp_xml_create_child_node(env ,  parameterListNode, NULL, "ParameterValueStruct", NULL));

        ESA(nameNode, cwmp_xml_create_child_node(env ,  parameterValueStructNode, NULL, "Name", pv->name));
        ESA(valueNode, cwmp_xml_create_child_node(env ,  parameterValueStructNode, NULL, "Value", pv->value));
        // ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  nameNode, SOAP_XSI_TYPE, SOAP_XSD_STRING));
        ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  valueNode, SOAP_XSI_TYPE, SOAP_XSD_STRING));

        parameterValueStructNode = NULL;
        ps ++;
        i++;
    }


    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  parameterListNode, SOAP_ENC_ARRAYTYPE, cwmp_get_format_string("cwmp:ParameterValueStruct[%d]", pl->count) ));
    cwmp_log_debug("created parameter list: [%d]\n", i);
    return parameterListNode;
}





xmldoc_t* cwmp_create_inform_message(env_t * env ,  header_t * header,
                                     device_id_t * deviceid,
                                     event_list_t *events,
                                     datatime_t * currentt,
                                     unsigned int max_envelope,
                                     unsigned int retry_count,
                                     parameter_list_t * pl)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * informNode;
    xmlnode_t * headerNode;
    xmlnode_t * deviceIdNode, *eventsNode, *maxenvNode, *currtimeNode, *retryCountNode, *paramlistNode;



    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    FUNCTION_TRACE();
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);



    ESA(informNode,     cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_INFORM, NULL));
    ESA(deviceIdNode    , cwmp_create_device_id_node(env ,  informNode, deviceid));
    ESA(eventsNode      , cwmp_create_event_node(env ,  informNode, events));
    ESA(maxenvNode      , cwmp_create_max_envelope_node(env ,  informNode, max_envelope));
    ESA(currtimeNode    , cwmp_create_current_time_node(env ,  informNode, currentt));
    ESA(retryCountNode  , cwmp_create_retry_count_node(env ,  informNode, retry_count));
    ESA(paramlistNode   , cwmp_create_parameter_list_node(env ,  informNode, pl));

    return doc;
}




//cwmp_create_getrpcmethods_response_message
xmldoc_t * cwmp_create_getrpcmethods_response_message(env_t * env ,  header_t * header, char ** methods, unsigned int count)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * methodListNode;
    xmlnode_t * methodNode;

    xmldoc_t * doc;
    char ** method;
    int num = 0;
    if (!methods)
    {
        return NULL;
    }

    doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_GETRPCMETHODSRESPONSE, NULL));
    ESA(methodListNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "MethodList", NULL));

    method = (methods);
    num = 0;
    while ((num < count) && method && (*method))
    {
        ESA(methodNode, cwmp_xml_create_child_node(env ,  methodListNode, NULL, "string", *method));

        method ++;
        num ++;
    }

    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  methodListNode, cwmp_get_format_string("%s:%s", "xmlns", SOAP_ENV), SOAP_ENV_NS ));
    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  methodListNode, SOAP_ENC_ARRAYTYPE, cwmp_get_format_string("xsd:string[%d]", count) ));

    return doc;
}






void * cwmp_create_getparameternames_response_all_parameter_names(env_t * env , xmlnode_t * parent_node, const char * path_name, parameter_node_t *  param_node, int * count)
{
    cwmp_buffer_t buffer;
    xmlnode_t * parameterInfoStructNode;
    xmlnode_t * parameterWritableNode;
    xmlnode_t * parameterNameNode;
    parameter_node_t * param_child;

    if (!param_node)
        return NULL;

    //if(param_node->type != TYPE_OBJECT)
    if(path_name != NULL && *path_name != 0)
    {
        ESA(parameterInfoStructNode, cwmp_xml_create_child_node(env ,  parent_node, NULL, "ParameterInfoStruct", NULL));
        ESA(parameterNameNode, cwmp_xml_create_child_node(env ,  parameterInfoStructNode, NULL, "Name", path_name ));
        ESA(parameterWritableNode, cwmp_xml_create_child_node(env ,  parameterInfoStructNode, NULL, "Writable", param_node->rw==0? "0" : "1"));
        (*count) ++;
    }
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

        }
        cwmp_create_getparameternames_response_all_parameter_names(env, parent_node, cwmp_buffer_string(&buffer), param_child, count);

    }

    return NULL;
}


//cwmp_create_getparameternames_response_message
xmldoc_t* cwmp_create_getparameternames_response_message(env_t * env ,
        header_t * header,
        const char * path_name,
        parameter_node_t * param_node,
        unsigned int next_subset,
        unsigned int next_level)
{
    cwmp_buffer_t buffer;
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * parameterListNode;
    xmlnode_t * parameterInfoStructNode;
    xmlnode_t * parameterWritableNode;
    xmlnode_t * parameterNameNode;

    int	count;

    parameter_node_t * child;


    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (!param_node)
    {
        return NULL;
    }

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_GETPARAMETERNAMESRESPONSE, NULL));
    ESA(parameterListNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "ParameterList", NULL));

    count = 0;
    if (next_subset == CWMP_NO)
    {
        if(path_name != NULL && *path_name != 0)
        {
            ESA(parameterInfoStructNode, cwmp_xml_create_child_node(env ,  parameterListNode, NULL, "ParameterInfoStruct", NULL));
            ESA(parameterNameNode, cwmp_xml_create_child_node(env ,  parameterInfoStructNode, NULL, "Name", path_name));
            ESA(parameterWritableNode, cwmp_xml_create_child_node(env ,  parameterInfoStructNode, NULL, "Writable", param_node->rw==0? "0" : "1"));
            count++;
        }
    }
    else
    {
        if (next_level == CWMP_YES)
        {
            for (child = param_node->child; child; child = child->next_sibling)
            {
		if(TRstrcmp(child->name, "{i}") == 0)
	            continue;

                cwmp_buffer_init(&buffer);
                if (child->type == TYPE_OBJECT)
                {
                    cwmp_buffer_write_format_string(&buffer,"%s%s.", path_name, child->name);
                }
                else
                {
                    cwmp_buffer_write_format_string(&buffer,"%s%s", path_name, child->name);
                }
                ESA(parameterInfoStructNode, cwmp_xml_create_child_node(env ,  parameterListNode, NULL, "ParameterInfoStruct", NULL));
                ESA(parameterNameNode, cwmp_xml_create_child_node(env ,  parameterInfoStructNode, NULL, "Name", cwmp_buffer_string(&buffer)));
                ESA(parameterWritableNode, cwmp_xml_create_child_node(env ,  parameterInfoStructNode, NULL, "Writable", child->rw==0? "0" : "1"));
                count++;

            }
        }
        else
        {
            //all parameters
            cwmp_create_getparameternames_response_all_parameter_names(env, parameterListNode, path_name, param_node, &count);

        }
    }

    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  parameterListNode, SOAP_ENC_ARRAYTYPE, cwmp_get_format_string("cwmp:ParameterInfoStruct[%d]", count) ));

    return doc;
}


//cwmp_create_getparametervalues_response_message
xmldoc_t* cwmp_create_getparametervalues_response_message(env_t * env ,  header_t * header, parameter_list_t * pl)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * parameterListNode;

    xmlnode_t * parameterValueStructNode;
    xmlnode_t * nameStructNode;
    xmlnode_t * valueStructNode;
    int	 count;
    parameter_t ** pv;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_GETPARAMETERVALUESRESPONSE, NULL));
    ESA(parameterListNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "ParameterList", NULL));
    pv = pl->parameters;
    count = 0;
    while (count < pl->count)
    {
        ESA(parameterValueStructNode, cwmp_xml_create_child_node(env ,  parameterListNode, NULL, "ParameterValueStruct", NULL));
        ESA(nameStructNode, cwmp_xml_create_child_node(env ,  parameterValueStructNode, NULL, "Name", (*(pv+count))->name));
        ESA(valueStructNode, cwmp_xml_create_child_node(env ,  parameterValueStructNode, NULL, "Value", (*(pv+count))->value));

        // ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  nameStructNode, SOAP_XSI_TYPE, SOAP_XSD_STRING ));
        ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  valueStructNode, SOAP_XSI_TYPE, CWMP_TYPE( (*(pv+count))->type ) ));
        count++;
    }

    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  parameterListNode, SOAP_ENC_ARRAYTYPE, cwmp_get_format_string("cwmp:ParameterValueStruct[%d]", pl->count) ));

    return doc;
}


void walk_tree(xmlnode_t *node)
{
	xmlnode_t *tmpNode;
	xmlnode_t *prevNode;
	xmlnode_t *childNode;
	xmlnode_t *siblingNode;
	
	if(node == NULL)
		return ;

	cwmp_log_info("%s", (XmlNodeGetNodeValue(node->firstAttr)==NULL)?node->nodeName:XmlNodeGetNodeValue(node->firstAttr));

	childNode = XmlNodeGetFirstChild(node);
	tmpNode = childNode;
	while(tmpNode!=NULL){
		tmpNode = XmlNodeGetNextSibling(tmpNode);
		
	}
	siblingNode = XmlNodeGetNextSibling(node);
	tmpNode = siblingNode;

	if(tmpNode == NULL)
		tmpNode = node->prevSibling;
		
	if(tmpNode != NULL)
		while(tmpNode->prevSibling!=NULL)
			tmpNode = tmpNode->prevSibling;
	
	while(tmpNode!=NULL){
		tmpNode = XmlNodeGetNextSibling(tmpNode);
	}

	walk_tree(childNode);
	walk_tree(siblingNode);
}


void walk_node(xmlnode_t *node)
{
	xmlnode_t *tmpNode;
	
	if(node == NULL)
		return ;

	cwmp_log_info("%s\n", (XmlNodeGetNodeValue(node->firstAttr)==NULL)?node->nodeName:XmlNodeGetNodeValue(node->firstAttr));
	tmpNode = XmlNodeGetFirstChild(node);
	while(tmpNode!=NULL){
		walk_node(tmpNode);
		tmpNode = XmlNodeGetNextSibling(tmpNode);
	}
}

void walk_parameter(parameter_node_t *node)
{
	parameter_node_t *tmp;
	parameter_node_t *child;
	parameter_node_t *childSibling;
	
	if(node == NULL)
		return ;

	cwmp_log_info("%s %x\n", node->name, (unsigned int)node);

	child = node->child;
	if(child != NULL){
		childSibling = child->next_sibling;

		cwmp_log_info("	child=%x child_sibling=%x\n", 
					(unsigned int)child,
					(unsigned int)childSibling);
					
		walk_parameter(child);
		
		while(childSibling != NULL){
			walk_parameter(childSibling);
			childSibling = childSibling->next_sibling;
		}
	}
}

void walk_parameter_tree(parameter_node_t *node)
{
	parameter_node_t *parent;
	parameter_node_t *child;
	parameter_node_t *sibling;
	parameter_node_t *tmp;
	
	if(node == NULL)
		return ;

	parent = node;
	child = node->child;

	if(child == NULL){
		cwmp_log_info("%s", node->name);
		return ;
	}

	while(child != NULL){
		parent = child;
		child = child->child;

	}

	return NULL;
}

char *pop_last_name(char *names_str)
{
	char *p = names_str;

	if(p==NULL)
		return NULL;

	while(*p!='\0')
		p++;

	while(p!=names_str && *p!='.')
		p--;

	p[0]='\0';
	return names_str;
}

// not saft pop and push
char *push_last_name(char *names_str, char *dot)
{
	char *p = names_str;

	if(p==NULL || dot==NULL)
		return NULL;

	if(strlen(names_str)>0){
		strcat(names_str, ".");
		strcat(names_str, dot);
	}
	else
		strcpy(names_str, dot);
	
	return names_str;
}

#define PN_NODE_NAME_STACK_SIZE 1024

static int pack_parameter_attr_node_loop_cnt=0;
static char pack_parameter_attr_node_full_name[PN_NODE_NAME_STACK_SIZE];


void init_pack_parameter_attr_node_loop_num(void)
{
	pack_parameter_attr_node_loop_cnt=0;
	pack_parameter_attr_node_full_name[0]='\0';
}

#define get_pack_parameter_attr_node_loop_num()		pack_parameter_attr_node_loop_cnt
#define set_pack_parameter_attr_node_loop_num(x)	pack_parameter_attr_node_loop_cnt=x

void pack_parameter_attr_node(env_t * env ,  xmlnode_t * parentNode,  parameter_node_t *node)
{
	parameter_node_t *tmp;
	parameter_node_t *child;
	parameter_node_t *childSibling;

	xmlnode_t * parameterAttrStructNode;
	
	xmlnode_t * nameNode;
    xmlnode_t * notificationNode;

    xmlnode_t * accessListNode;
    xmlnode_t * stringNode;

    static char temp[PN_NODE_NAME_STACK_SIZE];
	
	if(node == NULL){
		pop_last_name(pack_parameter_attr_node_full_name);
		return ;
	}
	
	if(strlen(pack_parameter_attr_node_full_name)>0){
		strcpy(temp, pack_parameter_attr_node_full_name);
		strcat(temp, ".");
		strcat(temp, node->name);
	}
	else{
		strcpy(temp, node->name);
	}

    if(strstr(temp, "{i}") == NULL)
    {
        pack_parameter_attr_node_loop_cnt++;
        ESA(parameterAttrStructNode, cwmp_xml_create_child_node(env ,  parentNode, NULL, "ParameterAttributeStruct", NULL));
        ESA(nameNode, cwmp_xml_create_child_node(env ,  parameterAttrStructNode, NULL, "Name", temp));

        sprintf(temp, "%d", node->attr.nc);
        ESA(notificationNode, cwmp_xml_create_child_node(env ,  parameterAttrStructNode, NULL, "Notification", temp));

        ESA(accessListNode, cwmp_xml_create_child_node(env ,  parameterAttrStructNode, NULL, "AccessList", NULL));
        ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  accessListNode, "SOAP-ENC:arrayType", "xsd:string[1]"));
        ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  accessListNode, "xsi:type", "SOAP-ENC:Array"));
        ESA(stringNode, cwmp_xml_create_child_node(env ,  accessListNode, NULL, "string", "Subscriber"));
    }
	
	child = node->child;
	if(child != NULL){

		push_last_name(pack_parameter_attr_node_full_name, node->name);
		
		childSibling = child->next_sibling;
		pack_parameter_attr_node(env, parentNode, child);
		
		while(childSibling != NULL){
			pack_parameter_attr_node(env, parentNode, childSibling);
			childSibling = childSibling->next_sibling;
		}

		pop_last_name(pack_parameter_attr_node_full_name);
	}
	
}



xmldoc_t* cwmp_create_getparameterattr_response_message(env_t * env ,  header_t * header, parameter_node_t * root, xmlnode_t *obj_node)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * parameterListNode;

    xmlnode_t * parameterAttrStructNode;
    xmlnode_t * nameNode;
    xmlnode_t * notificationNode;

    xmlnode_t * accessListNode;
    xmlnode_t * stringNode;

    xmldoc_t * doc;
    fault_code_t fault;
    
    int	 count=0;

    char *obj_name;
    char temp[128];
    char obj_parent_name[256];
    char name_for_empty_string[256];

    parameter_node_t *obj_param;
    int is_dot_path = 0;
    static char full_path[PN_NODE_NAME_STACK_SIZE];

    init_pack_parameter_attr_node_loop_num();
    obj_node = cwmp_xml_get_child_with_name(obj_node, "string");
    if(obj_node == NULL){
        cwmp_log_error("no string node \n");
        cwmp_set_faultcode(&fault, FAULT_CODE_9005);
        return cwmp_create_faultcode_response_message(env, header, &fault);
    }

    doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_GETPARAMETERATTRIBUTESRESPONSE, NULL));
    ESA(parameterListNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "ParameterList", NULL));

    do
    {
        obj_name = cwmp_xml_get_node_value(obj_node);
      
        if(obj_name == NULL)
        {
            sprintf(name_for_empty_string, "%s.", root->name);
            obj_name = name_for_empty_string;
        }

    	if(obj_name != NULL){
    		int len;
    		strcpy(obj_parent_name, obj_name);
    		
    		len = strlen(obj_parent_name);
    		if(obj_parent_name[len-1]=='.'){
    			char *p = obj_parent_name;
    			
    			is_dot_path = 1;

    			obj_parent_name[len-1]='\0';
    			p = obj_parent_name+len-1;
    		}
    		else
    			is_dot_path = 0;
    	}
    	else
    		is_dot_path = 0;

    	obj_param = cwmp_get_parameter_node(root, obj_name);
    	if(obj_param == NULL){
    		cwmp_log_info("get param is null");
    		cwmp_set_faultcode(&fault, FAULT_CODE_9005);
    		return cwmp_create_faultcode_response_message(env, header, &fault);
    	}
    	
    	parameter_node_t * pn = cwmp_get_parameter_node(root, obj_name);
    	if(pn==NULL){
    		cwmp_set_faultcode(&fault, FAULT_CODE_9005);
    		return cwmp_create_faultcode_response_message(env, header, &fault);
    	}

    	if(is_dot_path!=0){
    		strcpy(pack_parameter_attr_node_full_name, pop_last_name(obj_parent_name));
    		pack_parameter_attr_node(env, parameterListNode, pn);
        }
        else{
            pack_parameter_attr_node_loop_cnt++;
        	
    	    ESA(parameterAttrStructNode, cwmp_xml_create_child_node(env ,  parameterListNode, NULL, "ParameterAttributeStruct", NULL));

    	    ESA(nameNode, cwmp_xml_create_child_node(env ,  parameterAttrStructNode, NULL, "Name", obj_name));

    		sprintf(temp, "%d", pn->attr.nc);
    	    ESA(notificationNode, cwmp_xml_create_child_node(env ,  parameterAttrStructNode, NULL, "Notification", temp));
    	    
    	    ESA(accessListNode, cwmp_xml_create_child_node(env ,  parameterAttrStructNode, NULL, "AccessList", NULL));
    	    //ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  accessListNode, "SOAP-ENC:arrayType", cwmp_get_format_string("xsd:string[%d]", pn->attr.acl)));
    		ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  accessListNode, "SOAP-ENC:arrayType", "xsd:string[1]"));
    		ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  accessListNode, "xsi:type", "SOAP-ENC:Array"));

    		ESA(stringNode, cwmp_xml_create_child_node(env ,  accessListNode, NULL, "string", "Subscriber"));
    	}
        obj_node = XmlNodeGetNextSibling(obj_node);
    } while(obj_node);

    ESN(XML_OK, cwmp_xml_set_node_attribute(env ,  
    										parameterListNode, 
    										SOAP_ENC_ARRAYTYPE, 
    										cwmp_get_format_string("cwmp:ParameterAttributeStruct[%d]", get_pack_parameter_attr_node_loop_num())));

    return doc;
}

xmldoc_t * cwmp_create_setparametervalues_response_message(env_t * env ,  header_t * header, unsigned int status)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * statusNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);



    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_SETPARAMETERVALUESRESPONSE, NULL));
    ESA(statusNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "Status", status == 0 ? "0" : "1"));

    return doc;
}


xmldoc_t * cwmp_create_setparameterattributes_response_message(env_t * env ,  header_t * header, unsigned int status)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * statusNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);



    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_SETPARAMETERATTRIBUTESRESPONSE, NULL));
    ESA(statusNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "Status", status == 0 ? "0" : "1"));

    return doc;
}

xmldoc_t * cwmp_create_download_response_message(env_t * env , header_t * header, int status, time_t *begin, time_t *end)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * statusNode;
    xmlnode_t * startTimeNode;
    xmlnode_t * completeTimeNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }
    

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_DOWNLOADRESPONSE, NULL));
    ESA(statusNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "Status", status == 0 ? "0" : "1"));
    ESA(startTimeNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "StartTime", parse_time(begin)));
    ESA(completeTimeNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "CompleteTime", parse_time(end)));



    return doc;
}

xmldoc_t * cwmp_create_upload_response_message(env_t * env , header_t * header, int status, time_t *begin, time_t *end)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * statusNode;
    xmlnode_t * startTimeNode;
    xmlnode_t * completeTimeNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_UPLOADRESPONSE, NULL));
    ESA(statusNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "Status", status == 0 ? "0" : "1"));
    ESA(startTimeNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "StartTime", parse_time(begin)));
    ESA(completeTimeNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "CompleteTime", parse_time(end)));

    return doc;
}





xmldoc_t * cwmp_create_addobject_response_message(env_t * env , header_t * header, int instances, int status)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * statusNode;
    xmlnode_t * startTimeNode;
    xmlnode_t * completeTimeNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_ADDOBJECTRESPONSE, NULL));

    ESA(startTimeNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "InstanceNumber", TRitoa(instances)));
    ESA(statusNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "Status", status == 0 ? "0" : "1"));




    return doc;
}



xmldoc_t * cwmp_create_deleteobject_response_message(env_t * env , header_t * header, int status)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * statusNode;
    xmlnode_t * startTimeNode;
    xmlnode_t * completeTimeNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_DELETEOBJECTRESPONSE, NULL));
    ESA(statusNode, cwmp_xml_create_child_node(env ,  responseNode, NULL, "Status", status == 0 ? "0" : "1"));



    return doc;
}


xmldoc_t * cwmp_create_reboot_response_message(env_t * env ,  header_t * header)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_REBOOTRESPONSE, NULL));

    return doc;
}


xmldoc_t * cwmp_create_factoryreset_response_message(env_t * env ,  header_t * header)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(responseNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_FACTORYRESETRESPONSE, NULL));

    return doc;
}


xmldoc_t* cwmp_create_faultcode_response_message(env_t * env , header_t * header, fault_code_t * fault)
{


    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * faultStructNode;
    xmlnode_t * newNode, *detailNode, *faultNode;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );

    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env , envelopeNode, header);
    }
    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);

    cwmp_log_debug("create fault response , code is %d", fault->fault_code);
    ESA(faultStructNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, SOAP_ENV_FAULT, NULL));

    switch(fault->fault_code)
    {
        case FAULT_CODE_9000:
        case FAULT_CODE_9001:
        case FAULT_CODE_9002:
        case FAULT_CODE_9004:
        case FAULT_CODE_9009:
        case FAULT_CODE_9010:
        case FAULT_CODE_9011:
        case FAULT_CODE_9012:
        case FAULT_CODE_9013:
        case FAULT_CODE_9014:
        case FAULT_CODE_9015:
        case FAULT_CODE_9016:
        case FAULT_CODE_9017:
        case FAULT_CODE_9018:
        case FAULT_CODE_9019:
        {
            ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultcode", "Server"));
            break;
        }
        default:
        {
            ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultcode", "Client"));
            break;
        }
    }

    ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultstring", "Client fault"));

    ESA(detailNode, cwmp_xml_create_child_node(env ,  newNode, NULL, "detail", NULL));
    ESA(faultNode, cwmp_xml_create_child_node(env ,  detailNode, NULL, "cwmp:Fault", NULL));


    ESA(newNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "FaultCode", TRitoa(fault->fault_code)));
    ESA(newNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "FaultString", FAULT_STRING(fault->fault_code)));

    return doc;
}



xmldoc_t* cwmp_create_faultcode_setparametervalues_response_message(env_t * env , header_t * header, parameter_list_t * param_list, fault_code_t * fault)
{

    int i, count;
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * faultStructNode;
    xmlnode_t * newNode, *detailNode, *faultNode;
    parameter_t ** param = param_list->parameters;

    FUNCTION_TRACE();

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );

    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env , envelopeNode, header);
    }
    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);

    cwmp_log_debug("create fault response , code is %d", fault->fault_code);
    ESA(faultStructNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, SOAP_ENV_FAULT, NULL));

    switch(fault->fault_code)
    {
        case FAULT_CODE_9000:
        case FAULT_CODE_9001:
        case FAULT_CODE_9002:
        case FAULT_CODE_9004:
        case FAULT_CODE_9009:
        case FAULT_CODE_9010:
        case FAULT_CODE_9011:
        case FAULT_CODE_9012:
        case FAULT_CODE_9013:
        case FAULT_CODE_9014:
        case FAULT_CODE_9015:
        case FAULT_CODE_9016:
        case FAULT_CODE_9017:
        case FAULT_CODE_9018:
        case FAULT_CODE_9019:
        {
            ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultcode", "Server"));
            break;
        }
        default:
        {
            ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultcode", "Client"));
            break;
        }
    }

    ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultstring", "Client fault"));

    ESA(detailNode, cwmp_xml_create_child_node(env ,  newNode, NULL, "detail", NULL));
    ESA(faultNode, cwmp_xml_create_child_node(env ,  detailNode, NULL, "cwmp:Fault", NULL));


    ESA(newNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "FaultCode", TRitoa(fault->fault_code)));
    ESA(newNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "FaultString", FAULT_STRING(fault->fault_code)));

    cwmp_log_debug("cwmp_create_faultcode_setparametervalues_response_message count %d, %p", param_list->count, *param);
    for(i=0, count = param_list->count; (*param != NULL) && (i<count); i++, param++)
    {
        ESA(faultStructNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "SetParameterValuesFault", NULL));
		ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "ParameterName", (*param)->name));
		ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultCode", TRitoa((*param)->fault_code)));
        ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultString", FAULT_STRING((*param)->fault_code)));
    }


    return doc;
}

xmldoc_t* cwmp_create_faultcode_setparameterattributes_response_message(env_t * env , header_t * header, parameter_list_t * param_list, fault_code_t * fault)
{

    int i, count;
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * faultStructNode;
    xmlnode_t * newNode, *detailNode, *faultNode;
    parameter_t ** param = param_list->parameters;

    FUNCTION_TRACE();

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );

    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env , envelopeNode, header);
    }
    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);

    cwmp_log_debug("create fault response , code is %d", fault->fault_code);
    ESA(faultStructNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, SOAP_ENV_FAULT, NULL));

    switch(fault->fault_code)
    {
        case FAULT_CODE_9000:
        case FAULT_CODE_9001:
        case FAULT_CODE_9002:
        case FAULT_CODE_9004:
        case FAULT_CODE_9009:
        case FAULT_CODE_9010:
        case FAULT_CODE_9011:
        case FAULT_CODE_9012:
        case FAULT_CODE_9013:
        case FAULT_CODE_9014:
        case FAULT_CODE_9015:
        case FAULT_CODE_9016:
        case FAULT_CODE_9017:
        case FAULT_CODE_9018:
        case FAULT_CODE_9019:
        {
            ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultcode", "Server"));
            break;
        }
        default:
        {
            ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultcode", "Client"));
            break;
        }
    }

    ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultstring", "Client fault"));

    ESA(detailNode, cwmp_xml_create_child_node(env ,  newNode, NULL, "detail", NULL));
    ESA(faultNode, cwmp_xml_create_child_node(env ,  detailNode, NULL, "cwmp:Fault", NULL));


    ESA(newNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "FaultCode", TRitoa(fault->fault_code)));
    ESA(newNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "FaultString", FAULT_STRING(fault->fault_code)));

    cwmp_log_debug("cwmp_create_faultcode_setparameterattributes_response_message count %d, %p", param_list->count, *param);
    for(i=0, count = param_list->count; (*param != NULL) && (i<count); i++, param++)
    {
        ESA(faultStructNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "SetParameterAttributesFault", NULL));
	ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "ParameterName", (*param)->name));
	ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultCode", TRitoa((*param)->fault_code)));
        ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultString", FAULT_STRING((*param)->fault_code)));
    }


    return doc;
}

xmldoc_t* cwmp_create_faultcode_getparameterattributes_response_message(env_t * env , header_t * header, parameter_list_t * param_list, fault_code_t * fault)
{

    int i, count;
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * responseNode;
    xmlnode_t * headerNode;
    xmlnode_t * faultStructNode;
    xmlnode_t * newNode, *detailNode, *faultNode;
    parameter_t ** param = param_list->parameters;

    FUNCTION_TRACE();

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );

    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env , envelopeNode, header);
    }
    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);

    cwmp_log_debug("create fault response , code is %d", fault->fault_code);
    ESA(faultStructNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, SOAP_ENV_FAULT, NULL));

    switch(fault->fault_code)
    {
        case FAULT_CODE_9000:
        case FAULT_CODE_9001:
        case FAULT_CODE_9002:
        case FAULT_CODE_9004:
        case FAULT_CODE_9009:
        case FAULT_CODE_9010:
        case FAULT_CODE_9011:
        case FAULT_CODE_9012:
        case FAULT_CODE_9013:
        case FAULT_CODE_9014:
        case FAULT_CODE_9015:
        case FAULT_CODE_9016:
        case FAULT_CODE_9017:
        case FAULT_CODE_9018:
        case FAULT_CODE_9019:
        {
            ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultcode", "Server"));
            break;
        }
        default:
        {
            ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultcode", "Client"));
            break;
        }
    }

    ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "faultstring", "Client fault"));

    ESA(detailNode, cwmp_xml_create_child_node(env ,  newNode, NULL, "detail", NULL));
    ESA(faultNode, cwmp_xml_create_child_node(env ,  detailNode, NULL, "cwmp:Fault", NULL));


    ESA(newNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "FaultCode", TRitoa(fault->fault_code)));
    ESA(newNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "FaultString", FAULT_STRING(fault->fault_code)));

    cwmp_log_debug("cwmp_create_faultcode_getparameterattributes_response_message count %d, %p", param_list->count, *param);
    for(i=0, count = param_list->count; (*param != NULL) && (i<count); i++, param++)
    {
        ESA(faultStructNode, cwmp_xml_create_child_node(env ,  faultNode, NULL, "GetParameterAttributesFault", NULL));
	ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "ParameterName", (*param)->name));
	ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultCode", TRitoa((*param)->fault_code)));
        ESA(newNode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultString", FAULT_STRING((*param)->fault_code)));
    }


    return doc;
}



xmldoc_t * cwmp_create_transfercomplete_message(env_t * env ,  header_t * header, event_code_t * evcode)
{
    xmlnode_t * envelopeNode;
    xmlnode_t * bodyNode;
    xmlnode_t * rpcNode;
    xmlnode_t * headerNode;
    xmlnode_t * node;

    xmlnode_t * faultStructNode;
    xmlnode_t * faultCode;
    xmlnode_t * faultString;

    xmldoc_t * doc = XmlDocCreateDocument(env->pool );
    envelopeNode    = cwmp_create_envelope_node(env ,  & doc->node);

    if (header)
    {
        headerNode  = cwmp_create_header_node(env ,  envelopeNode, header);
    }

    bodyNode        = cwmp_create_body_node(env ,  envelopeNode);
    ESA(rpcNode, cwmp_xml_create_child_node(env ,  bodyNode, NULL, CWMP_RPC_TRANSFERCOMPLETE, NULL));
    ESA(node, cwmp_xml_create_child_node(env ,  rpcNode, NULL, "CommandKey", evcode->command_key));
    //if(evcode->fault_code)
    {
		static char ok_str[]="OK";

        ESA(faultStructNode, cwmp_xml_create_child_node(env ,  rpcNode, NULL, "FaultStruct", NULL));
        ESA(faultCode, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultCode", TRitoa(evcode->fault_code)));
        if(evcode->fault_code == 0)
        	ESA(faultString, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultString", ok_str));
        else
        	ESA(faultString, cwmp_xml_create_child_node(env ,  faultStructNode, NULL, "FaultString", FAULT_STRING(evcode->fault_code)));

    }

    //ESA(node, cwmp_xml_create_child_node(env ,  rpcNode, NULL, "StartTime", begintime));
    //ESA(node, cwmp_xml_create_child_node(env ,  rpcNode, NULL, "CompleteTime", endtime));
        
	ESA(node, cwmp_xml_create_child_node(env ,	rpcNode, NULL, "StartTime", parse_time(&evcode->start)));
	ESA(node, cwmp_xml_create_child_node(env ,	rpcNode, NULL, "CompleteTime", parse_time(&evcode->end)));

    return doc;
}

int cwmp_write_doc_to_chunk(xmldoc_t *  doc, cwmp_chunk_t * chunk, pool_t * pool)
{
    //	return cwmp_xml_print_doc_to_chunk(doc, chunk, pool);
    char * xml;
    xml = XmlPrintDocument(pool, doc);
    cwmp_chunk_write_string(chunk, xml, TRstrlen(xml), pool);

    return CWMP_OK;
}

char *substring(char *p, int begin, int length){
    p = p + begin;
    *(p + length) = '\0';

    return p;
}


void replace_special_char(char *value) {
	do {
		if (*value < 32 || *value > 126) {
			*value = ' ';
		}
		value++;
	} while (*value != '\0');
}

int is_true_value(char *value) {
	if (strncmp(value, STR_TRUE_LC, strlen(STR_TRUE_LC)) == 0 || 
		strncmp(value, STR_TRUE, strlen(STR_TRUE)) == 0 || 
		strncmp(value, "1", 1) == 0) {
		return 1;
	}
	return 0;
}

int is_false_value(char *value) {
	if (strncmp(value, STR_FALSE_UC, strlen(STR_FALSE_UC)) == 0 || 
		strncmp(value, STR_FALSE, strlen(STR_FALSE)) == 0 || 
		strncmp(value, "0", 1) == 0) {
		return 1;
	}
	return 0;
}

//去掉双引号
char* strip_double_quote( char* one_string )
{
	char* tmp=strstr(one_string,"\"");
	//首先查找是否存在双引号
	if( tmp == one_string )
	{
		one_string+=1;
	}

	tmp=strstr(one_string,"\"");
	if( tmp != NULL )
	{
		*tmp=0;
	}

	return one_string;
}

int get_parameter_index(char *name, char *str, int max) {

	char *p = strstr(name, str);
	if (p == NULL) {
		return 1;
	}

    int index = atoi(p + strlen(str));
	if (index <= 0) {
		return 1;
	} else if (index > max) {
		return max;
	} else {
		return index;
	}
}

unsigned int hex2int(char c)
{
	if (c >= '0' && c <= '9')
		return (unsigned int)(c-'0');
	if (c >= 'a' && c <= 'f')
		return (unsigned int)(c-'a'+10);
	if (c >= 'A' && c <= 'F')
		return (unsigned int)(c-'A'+10);

	return 0;
}

char string2int(char *str, unsigned int *pOut)
{
	int i,n;
	unsigned int val;

	*pOut = 0;
	n = strlen(str);

	for(i = 0; i < n && i < 8; i++)
	{
		val = hex2int(*str);
		*pOut = *pOut<<4;
		*pOut |= val;

		str++;
	}

	return i;
}

char *strrstr(char const *s1, char const *s2){

	  register char *last;
	  register char *current;

	  last = NULL;
	  if (*s2 != '\0'){
		    current = strstr(s1, s2);
		    while (current != NULL){
			      last = current;
			      current = strstr(last + 1, s2);
		    }
	  }

	  return last;
}



static int connection_request = 0;

int get_connection_request(void) {
    return connection_request;
}

void set_connection_request_true(void) {
    connection_request = 1;
}

void set_connection_request_false(void) {
    connection_request = 0;
}

int cmd_touch(const char *file_name)
{
    //open file handle to write
    FILE* file_handle=fopen(file_name,"wb");

    if( file_handle == NULL )
    {
        return -1;
    }

    //close file handle
    fclose(file_handle);

    return 0;
}

int cmd_file_exist(const char* file_name)
{
#ifdef WIN32
    {
        WIN32_FIND_DATA wfd;
        HANDLE hFind=FindFirstFile( file_name,&wfd );
        //need create directory
        if( hFind == INVALID_HANDLE_VALUE )
        {
            return FALSE;
        }
    }
#else
    if( access( file_name,R_OK ) )
    {
        return FALSE;
    }
#endif
    return TRUE;
}

//write string to one specified file
int cmd_echo(char* str,const char *file_name)
{
    //open file handle to write
    FILE* file_handle=fopen(file_name,"wb");

    if( file_handle == NULL )
    {
        return -1;
    }

    fwrite(str,strlen( str ),1,file_handle);
    fwrite("\n",strlen( "\n" ),1,file_handle);
    //close file handle
    fclose(file_handle);

    return 0;
}

//print file content
int cmd_cat(const char* file_name,char* buffer,int buffer_size)
{
    //open file handle to write
    FILE* file_handle=fopen(file_name,"rb");

    if( file_handle == NULL )
    {
        return -1;
    }

    if( buffer != NULL )
    {
        memset(buffer,0,buffer_size);
        fread(buffer,buffer_size-1,1,file_handle);
    }
    else
    {
        char tmp_buffer[64];
        memset(tmp_buffer,0,sizeof(tmp_buffer));
        fread(tmp_buffer,sizeof(tmp_buffer)-1,1,file_handle);
    }


    //close file handle
    fclose(file_handle);

    return 0;
}

char* GetBasename( char* url )
{
    char* tmp_ptr;
    char* tmp_ptr2;

    tmp_ptr=url;
    tmp_ptr2=strstr( tmp_ptr,"/" );
    while( tmp_ptr2 )
    {
        tmp_ptr=tmp_ptr2+1;
        tmp_ptr2=strstr( tmp_ptr,"/" );
    }

    return tmp_ptr;
}
