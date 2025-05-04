TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lnetfilter_queue

SOURCES += \
        main.cpp \
        packet_modifier.cpp

HEADERS += \
    net_headers.h \
    packet_modifier.h
