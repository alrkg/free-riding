TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap

SOURCES += \
        gateway_info.cpp \
        main.cpp \
        net_utils.cpp \
        system_executor.cpp

HEADERS += \
    gateway_info.h \
    net_headers.h \
    net_utils.h \
    system_executor.h
