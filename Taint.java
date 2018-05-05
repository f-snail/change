/*
*  Licensed to the Apache Software Foundation (ASF) under one or more
*  contributor license agreements.  See the NOTICE file distributed with
*  this work for additional information regarding copyright ownership.
*  The ASF licenses this file to You under the Apache License, Version 2.0
*  (the "License"); you may not use this file except in compliance with
*  the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*/

package java.lang;

public final class Taint{

        public static final int TAINT_CLEAR      =0x00000000;
        public static final int TAINT_LV1        =0x00000001;
        public static final int TAINT_LV2        =0x00000002;
        public static final int TAINT_LV3        =0x00000003;

        // how many bytes of tainted network output data to print to log?
        public static final int dataBytesToLog = 100;

        /**
         * update/get the target "Int" data's taint tag
         * returns nothing
	 * the implementation is in optimizing compiler's intrinsic functions
         */
        public static native void addTaint(int val,int tag);
        public static native int getTaint(int val);
        public static native void addTaint(short val, int tag);
        public static native int getTaint(short val);
        public static native void addTaint(boolean val, int tag);
        public static native int getTaint(boolean val);       
        public static native void addTaint(byte val, int tag);
        public static native int getTaint(byte val);
        public static native void addTaint(float val, int tag);
        public static native int getTaint(float val);
        public static native void addTaint(double val, int tag);
        public static native int getTaint(double val);
        public static native int getTaint();
        public static native void addTaint(long val, int tag);
        public static native int getTaint(long val);
        public static native int[] addTaint(int[] val, int tag);
        public static native int getTaint(int[] val);
        public static native short[] addTaint(short[] val, int tag);
        public static native int getTaint(short[] val);
        public static native byte[] addTaint(byte[] val, int tag);
        public static native int getTaint(byte[] val);
        public static native char[] addTaint(char[] val, int tag);
        public static native int getTaint(char[] val);
        public static native boolean[] addTaint(boolean[] val, int tag);
        public static native int getTaint(boolean[] val);
        public static native long[] addTaint(long[] val, int tag);
        public static native int getTaint(long[] val);
        public static native float[] addTaint(float[] val, int tag);
        public static native int getTaint(float[] val);
        public static native double[] addTaint(double[] val, int tag);
        public static native int getTaint(double[] val);

        // not be able to use android.util.Slog,compile error, turn to native complement.
        public static native void log(String msg);                
}
