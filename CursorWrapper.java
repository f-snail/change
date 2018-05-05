/*
 * Copyright (C) 2006 The Android Open Source Project
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

package android.database;

import android.content.ContentResolver;
import android.net.Uri;
import android.os.Bundle;

// Taint begin
import java.lang.Taint;
// Taint end

/**
 * Wrapper class for Cursor that delegates all calls to the actual cursor object.  The primary
 * use for this class is to extend a cursor while overriding only a subset of its methods.
 */
public class CursorWrapper implements Cursor {
    /** @hide */
    protected final Cursor mCursor;

    /**
     * Creates a cursor wrapper.
     * @param cursor The underlying cursor to wrap.
     */
    public CursorWrapper(Cursor cursor) {
        mCursor = cursor;
    }

    /**
     * Gets the underlying cursor that is wrapped by this instance.
     *
     * @return The wrapped cursor.
     */
    public Cursor getWrappedCursor() {
        return mCursor;
    }

    @Override
    public void close() {
        mCursor.close(); 
    }
 
    @Override
    public boolean isClosed() {
        return mCursor.isClosed();
    }

    // Taint begin
    private int taint_ = Taint.TAINT_CLEAR;

    public void setTaint(int taint) {
            this.taint_ = taint;
    }
    // Taint end

    @Override
    public int getCount() {
        return mCursor.getCount();
    }

    @Override
    @Deprecated
    public void deactivate() {
        mCursor.deactivate();
    }

    @Override
    public boolean moveToFirst() {
        return mCursor.moveToFirst();
    }

    @Override
    public int getColumnCount() {
        return mCursor.getColumnCount();
    }

    @Override
    public int getColumnIndex(String columnName) {
        return mCursor.getColumnIndex(columnName);
    }

    @Override
    public int getColumnIndexOrThrow(String columnName)
            throws IllegalArgumentException {
        return mCursor.getColumnIndexOrThrow(columnName);
    }

    @Override
    public String getColumnName(int columnIndex) {
         return mCursor.getColumnName(columnIndex);
    }

    @Override
    public String[] getColumnNames() {
        return mCursor.getColumnNames();
    }

    @Override
    public double getDouble(int columnIndex) {
            // Taint: TODO
        return mCursor.getDouble(columnIndex);
    }

    @Override
    public void setExtras(Bundle extras) {
        mCursor.setExtras(extras);
    }

    @Override
    public Bundle getExtras() {
        return mCursor.getExtras();
    }

    @Override
    public float getFloat(int columnIndex) {
            // Taint: TODO
        return mCursor.getFloat(columnIndex);
    }

    @Override
    public int getInt(int columnIndex) {
        // Taint begin
        // return mCursor.getInt(columnIndex);
        int val = mCursor.getInt(columnIndex);
        Taint.addTaint(val, taint_);
        return val;
        // Taint end
    }

    @Override
    public long getLong(int columnIndex) {
        // Taint begin            
        // return mCursor.getLong(columnIndex);
        long val = mCursor.getLong(columnIndex);
        Taint.addTaint(val, taint_);
        return val;
        // Taint end
    }

    @Override
    public short getShort(int columnIndex) {
        // Taint begin            
        // return mCursor.getShort(columnIndex);
        short val = mCursor.getShort(columnIndex);
        Taint.addTaint(val, taint_);
        return val;
        // Taint end
    }

    @Override
    public String getString(int columnIndex) {
        // Taint: TODO
        return mCursor.getString(columnIndex);
    }
    
    @Override
    public void copyStringToBuffer(int columnIndex, CharArrayBuffer buffer) {
        mCursor.copyStringToBuffer(columnIndex, buffer);
    }

    @Override
    public byte[] getBlob(int columnIndex) {
        return mCursor.getBlob(columnIndex);
    }
    
    @Override
    public boolean getWantsAllOnMoveCalls() {
        return mCursor.getWantsAllOnMoveCalls();
    }

    @Override
    public boolean isAfterLast() {
        return mCursor.isAfterLast();
    }

    @Override
    public boolean isBeforeFirst() {
        return mCursor.isBeforeFirst();
    }

    @Override
    public boolean isFirst() {
        return mCursor.isFirst();
    }

    @Override
    public boolean isLast() {
        return mCursor.isLast();
    }

    @Override
    public int getType(int columnIndex) {
        return mCursor.getType(columnIndex);
    }

    @Override
    public boolean isNull(int columnIndex) {
        return mCursor.isNull(columnIndex);
    }

    @Override
    public boolean moveToLast() {
        return mCursor.moveToLast();
    }

    @Override
    public boolean move(int offset) {
        return mCursor.move(offset);
    }

    @Override
    public boolean moveToPosition(int position) {
        return mCursor.moveToPosition(position);
    }

    @Override
    public boolean moveToNext() {
        return mCursor.moveToNext();
    }

    @Override
    public int getPosition() {
        return mCursor.getPosition();
    }

    @Override
    public boolean moveToPrevious() {
        return mCursor.moveToPrevious();
    }

    @Override
    public void registerContentObserver(ContentObserver observer) {
        mCursor.registerContentObserver(observer);
    }

    @Override
    public void registerDataSetObserver(DataSetObserver observer) {
        mCursor.registerDataSetObserver(observer);
    }

    @Override
    @Deprecated
    public boolean requery() {
        return mCursor.requery();
    }

    @Override
    public Bundle respond(Bundle extras) {
        return mCursor.respond(extras);
    }

    @Override
    public void setNotificationUri(ContentResolver cr, Uri uri) {
        mCursor.setNotificationUri(cr, uri);
    }

    @Override
    public Uri getNotificationUri() {
        return mCursor.getNotificationUri();
    }

    @Override
    public void unregisterContentObserver(ContentObserver observer) {
        mCursor.unregisterContentObserver(observer);
    }

    @Override
    public void unregisterDataSetObserver(DataSetObserver observer) {
        mCursor.unregisterDataSetObserver(observer);
    }
}

