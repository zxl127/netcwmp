TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    cwmpd/src/modules/InternetGatewayDevice/DeviceInfo/DeviceInfo.c \
    cwmpd/src/modules/InternetGatewayDevice/InternetGatewayDevice.c \
    cwmpd/src/modules/data_model.c \
    cwmpd/src/agent.c \
    cwmpd/src/conf.c \
    cwmpd/src/cwmpd.c \
    cwmpd/src/httpd.c \
    cwmpd/src/process.c \
    cwmpd/src/thread.c \
    libcwmp/src/buffer.c \
    libcwmp/src/cfg.c \
    libcwmp/src/cwmp.c \
    libcwmp/src/event.c \
    libcwmp/src/http.c \
    libcwmp/src/ini.c \
    libcwmp/src/log.c \
    libcwmp/src/md5.c \
    libcwmp/src/memory.c \
    libcwmp/src/model.c \
    libcwmp/src/session.c \
    libcwmp/src/ssl.c \
    libcwmp/src/util.c \
    libpool/src/pool.c \
    libxmlet/src/attr.c \
    libxmlet/src/document.c \
    libxmlet/src/element.c \
    libxmlet/src/list.c \
    libxmlet/src/namemap.c \
    libxmlet/src/node.c \
    libxmlet/src/parser.c \
    libxmlet/src/xmlet.c \
    libxmlet/src/xmlbuffer.c \
    libcwmp/src/task.c \
    libcwmp/src/task_list.c

HEADERS += \
    cwmpd/include/cwmp_agent.h \
    cwmpd/include/cwmp_conf.h \
    cwmpd/include/cwmp_httpd.h \
    cwmpd/include/cwmp_module.h \
    cwmpd/include/cwmp_process.h \
    cwmpd/include/cwmp_signal.h \
    cwmpd/include/cwmp_thread.h \
    cwmpd/include/cwmp_type.h \
    cwmpd/include/cwmpd.h \
    cwmpd/src/modules/data_model.h \
    libcwmp/include/cwmp/buffer.h \
    libcwmp/include/cwmp/cfg.h \
    libcwmp/include/cwmp/cwmp.h \
    libcwmp/include/cwmp/envment.h \
    libcwmp/include/cwmp/error.h \
    libcwmp/include/cwmp/event.h \
    libcwmp/include/cwmp/http.h \
    libcwmp/include/cwmp/log.h \
    libcwmp/include/cwmp/md5.h \
    libcwmp/include/cwmp/memory.h \
    libcwmp/include/cwmp/model.h \
    libcwmp/include/cwmp/session.h \
    libcwmp/include/cwmp/types.h \
    libcwmp/include/cwmp/util.h \
    libcwmp/src/inc/cwmp_private.h \
    libcwmp/src/inc/ini.h \
    libcwmp/src/common.h \
    libpool/include/cwmp/pool.h \
    libxmlet/include/cwmp/xmlet.h \
    libxmlet/src/inc/xmlbuffer.h \
    libxmlet/src/inc/xmlparser.h \
    config.h \
    libcwmp/include/cwmp/task.h \
    libcwmp/include/cwmp/task_list.h

INCLUDEPATH += \
    libcwmp/include \
    libpool/include \
    libxmlet/include \
    cwmpd/include \
    libxmlet/src/inc \
    libcwmp/src/inc/

DEFINES += \
    USE_CWMP_MEMORY_POOL

LIBS += \
    -lpthread
