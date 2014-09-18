LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := aprocdump
LOCAL_SRC_FILES := file_writer.c tcp_writer.c aprocdump.c stdout_writer.c
LOCAL_CPPFLAGS := -stdgnu++0x -Wall -static
LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog
include $(BUILD_EXECUTABLE)