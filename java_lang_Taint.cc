/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common_throws.h"
#include "jni_internal.h"
#include "mirror/object-inl.h"
#include "mirror/string.h"
// #include "scoped_fast_native_object_access.h"
// #include "scoped_thread_state_change.h"
// #include "ScopedLocalRef.h"
#include "base/logging.h"
#include "attr/xattr.h"
#include <cerrno>

#define TAINT_XATTR_NAME "user.taint"

static int32_t getTaintXattr(int32_t fd) {
        int32_t ret;
        int32_t buf = 0;
        int32_t tag = TAINT_CLEAR;

        ret = fgetxattr(fd, TAINT_XATTR_NAME, &buf, sizeof(buf));
        if (ret > 0) {
                tag = buf;
        } else {
                if (errno == ENOATTR)
                        // do nothing
                else if (errno == ERANGE)
                        LOG(WARNING) << "TaintLog: fgetxattr(" << fd << ") contents to large";
                else if (errno == ENOTSUP)
                        // XATTRs are not supported. No need to spam the logs
                else if (errno == EPERM)
                        // Strange interaction with /dev/log/main. Suppress the log
                else
                        LOG(WARNING) << "TA64Log: fgetxattr(" << fd << "): unknown error code " << errno;
        }

        return tag;
}

static void setTaintXattr(int32_t fd, int32_t tag) {
        int32_t ret;
        ret = fsetxattr(fd, TAINT_XATTR_NAME, &tag, sizeof(tag), 0);

        if (ret < 0) {
                if (errno == ENOSPC || errno == EDQUOT)
                        LOG(WARNING) << "TaintLog: fsetxattr(" << fd << "): not enough room to set xattr";
                else if (errno == ENOTSUP)
                        // XATTRs are not supported. No need to spam the logs
                else if (errno == EPERM)
                        // Strange interaction with /dev/log/main. Suppress the log
                else
                        LOG(WARNING) << "TA64Log: fsetxattr(" << fd << "): unknown error code " << errno;
        }
}

// public static native void addTaintFile(int fd, int tag);
static void Taint_addTaintFile(JNIEnv* env, jobject, jint fd, jint tag) {
        int32_t t_fd = (int32_t)fd;
        int32_t t_tag = (int32_t)tag;
        int32_t tt_tag = getTaintXattr(t_fd);
        int32_t p_tag;
        if (t_tag > tt_tag)
                p_tag = t_tag;
        else
                p_tag = tt_tag;

        if (tag) {
                LOG(INFO) << "TA64Log: addTaintFile(" << fd << "): adding 0x" << tt_tag <<  "to 0x" << t_tag << ", the final tag is 0x" << p_tag;
        }

        setTaintXattr(fd, p_tag);
}

// public static native int getTaintFile(int fd);
static jint Taint_getTaintFile(JNIEnv* env, jobject, jint fd) {
        int32_t t_fd = (int32_t)fd;
        int32_t tag = getTaintXattr(t_fd);
        if (tag)
                LOG(INFO) << "TA64Log: getTaintFile(" << fd << ") = 0x" << tag;
        return tag;
}


/*
 * public static void log(String msg)
 */
static void Taint_log(JNIEnv* env, jclass, jstring java_string_msg) {
        if (UNLIKELY(java_string_msg == nullptr)) {
                ThrowNullPointerException("msg == null");
                return;
        }

        char *msg = env->GetStringUTFChars(java_string_msg, nullptr);
        while (strlen(msg) > 1013) {
                msg = msg + 1013;
                LOG(INFO) << "TaintLog: " << msg;
        }
        env->ReleaseStringUTFChars(java_string_msg, msg);
}

// public static void logPathFromFd(int fd)
static void Taint_logPathFromFd(jint fd) {
        int32_t t_fd = (int32_t) fd;
        pid_t pid;
        char ppath[20];  // these path lengths should be enough
        char rpath[80];
        // int32_t err;

        pid = getpid();
        snprintf(ppath, 20, "/proc/%d/fd/%d", pid, fd);
        // err = readlink(ppath, rpath, 80);  // there is no fun named readlink as TaintDroid fun.
        if (err >= 0)
                LOG(WARNING) << "TaintLog: " << fd << " -> " << rpath;
        else
                LOG(WARNING) << "TaintLog: error finding path for fd " << fd;
}

static JNINativeMethod gMethods[] = {
        NATIVE_METHOD(Taint, log, "(Ljava/lang/String;)V"),
        NATIVE_METHOD(Taint, addTaintFile, "(II)V"),
        NATIVE_METHOD(Taint, getTaintFile, "(I)I"),
        NATIVE_METHOD(Taint, logPathFromFd, "(I)V"),
};

void register_java_lang_Taint(JNIEnv* env) {
        REGISTER_NATIVE_METHODS("java/lang/Taint");
}
