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

#include "jni_internal.h"
#include "mirror/object-inl.h"
#include "mirror/string.h"
#include "scoped_fast_native_object_access.h"
#include "scoped_thread_state_change.h"
#include "ScopedLocalRef.h"
#include "base/logging.h"

/*
 * public static void log(String msg)
 */
static void Taint_log(JNIEnv* env, jobject java_this, jobject java_string_msg) {
        ScopedFastNativeObjectAccess soa(env);
        if (UNLIKELY(java_string_msg == nullptr)) {
                ThrowNullPointerException("msg == null");
                return;
        }

        const char* msg = env->GetStringUTFChars(java_string_msg, nullptr);
        LOG(INFO) << "TaintLog: " << msg;
        env->ReleaseStringUTFChars(java_string_msg, msg);
}

static JNINativeMethod gMethods[] = {
        NATIVE_METHOD(Taint, log, "!(Ljava/lang/String;)V"),
};

void register_java_lang_Taint(JNIEnv* env) {
          REGISTER_NATIVE_METHODS("java/lang/Taint");
}
