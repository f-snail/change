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

        /**
		 * update/get the target "Int" data's taint tag
          returns nothing
		  the implementation is in optimizing compiler's intrinsic functions. 
		  */
        public static native void addTaint(int val,int tag);
		public static native int getTaint(int val);
		public static native void addTaint(short val, int tag);
		public static native int getTaint(short val);
		public static native void addTaint(boolean val, int tag);
        public static native int getTaint(boolean val);
		public static native void addTaint(byte val, int tag);
		public static native int getTaint(byte val);
		public static native int getTaint();
		public static native void addTaint(long val, int tag);
		public static native int getTaint(long val);
		public static native IntArray addTaint(IntArray val, int tag);
		public static native int getTaint(IntArray val);
		public static native ShortArray addTaint(ShortArray val, int tag);
		public static native int getTaint(ShortArray val);
		public static native ByteArray addTaint(ByteArray val, int tag);
		public static native int getTaint(ByteArray val);
		public static native CharArray addTaint(CharArray val, int tag);
		public static native int getTaint(CharArray val);
		public static native BooleanArray addTaint(BooleanArray val, int tag);
		public static native int getTaint(BooleanArray val);
		public static native LongArray addTaint(LongArray val, int tag);
		public static native int getTaint(LongArray val);
        }
}
