/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.support;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import com.google.common.base.Preconditions;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import org.ldaptive.AbstractLdapBean;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchEntry;

import com.amazon.dlic.auth.ldap.LdapUser;

import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.io.stream.BytesStreamInput;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.io.stream.BaseWriteable;
import org.opensearch.core.common.io.stream.BaseWriteable.WriteableRegistry;
import org.opensearch.security.user.User;

public class Base64Helper {

    private static final Set<Class<?>> SAFE_CLASSES = ImmutableSet.of(
        String.class,
        SocketAddress.class,
        InetSocketAddress.class,
        Pattern.class,
        User.class,
        SourceFieldsContext.class,
        LdapUser.class,
        SearchEntry.class,
        LdapEntry.class,
        AbstractLdapBean.class,
        LdapAttribute.class
    );

    private static final List<Class<?>> SAFE_ASSIGNABLE_FROM_CLASSES = ImmutableList.of(
        InetAddress.class,
        Number.class,
        Collection.class,
        Map.class,
        Enum.class
    );


    private enum CustomSerializationFormat {

        WRITEABLE(1),
        GENERIC(2);

        private final int id;

        CustomSerializationFormat(int id) {
            this.id = id;
        }

        static CustomSerializationFormat fromId(int id) {
            switch (id) {
                case 1: return WRITEABLE;
                case 2: return GENERIC;
                default: throw new IllegalArgumentException(String.format("%d is not a valid id", id));
            }
        }

    }

    private static final ThreadLocal<BiMap<Class<?>, Integer>> writeableClassToIdMap = ThreadLocal.withInitial(HashBiMap::create);
    private static final Set<String> SAFE_CLASS_NAMES = Collections.singleton(
        "org.ldaptive.LdapAttribute$LdapAttributeValues"
    );

    static {
        registerStreamables();
        registerAllWriteables();
    }

    private static boolean isSafeClass(Class<?> cls) {
        return cls.isArray() ||
            SAFE_CLASSES.contains(cls) ||
            SAFE_CLASS_NAMES.contains(cls.getName()) ||
            SAFE_ASSIGNABLE_FROM_CLASSES.stream().anyMatch(c -> c.isAssignableFrom(cls));
    }

    private final static class SafeObjectOutputStream extends ObjectOutputStream {

        private static final boolean useSafeObjectOutputStream = checkSubstitutionPermission();

        @SuppressWarnings("removal")
        private static boolean checkSubstitutionPermission() {
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                try {
                    sm.checkPermission(new SpecialPermission());

                    AccessController.doPrivileged((PrivilegedAction<Void>)() -> {
                        AccessController.checkPermission(SUBSTITUTION_PERMISSION);
                        return null;
                    });
                } catch (SecurityException e) {
                    return false;
                }
            }
            return true;
        }

        static ObjectOutputStream create(ByteArrayOutputStream out) throws IOException {
            try {
                return useSafeObjectOutputStream ? new SafeObjectOutputStream(out) : new ObjectOutputStream(out);
            } catch (SecurityException e) {
                // As we try to create SafeObjectOutputStream only when necessary permissions are granted, we should
                // not reach here, but if we do, we can still return ObjectOutputStream after resetting ByteArrayOutputStream
                out.reset();
                return new ObjectOutputStream(out);
            }
        }

        @SuppressWarnings("removal")
        private SafeObjectOutputStream(OutputStream out) throws IOException {
            super(out);

            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> enableReplaceObject(true)
            );
        }

        @Override
        protected Object replaceObject(Object obj) throws IOException {
            Class<?> clazz = obj.getClass();
            if (isSafeClass(clazz)) {
                return obj;
            }
            throw new IOException("Unauthorized serialization attempt " + clazz.getName());
        }
    }

    private static String serializeObjectJDK(final Serializable object) {

        Preconditions.checkArgument(object != null, "object must not be null");

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final ObjectOutputStream out = SafeObjectOutputStream.create(bos)) {
            out.writeObject(object);
        } catch (final Exception e) {
            throw new OpenSearchException("Instance {} of class {} is not serializable", e, object, object.getClass());
        }
        final byte[] bytes = bos.toByteArray();
        return BaseEncoding.base64().encode(bytes);
    }

    private static String serializeObjectCustom(final Serializable object) {

        Preconditions.checkArgument(object != null, "object must not be null");
        final BytesStreamOutput streamOutput = new BytesStreamOutput(128);
        Class<?> clazz = object.getClass();
        try {
            if(isWriteable(clazz)) {
                streamOutput.writeByte((byte) CustomSerializationFormat.WRITEABLE.id);
                streamOutput.writeByte((byte) getWriteableClassID(clazz).intValue());
                ((Writeable) object).writeTo(streamOutput);
            } else {
                streamOutput.writeByte((byte) CustomSerializationFormat.GENERIC.id);
                streamOutput.writeGenericValue(object);
            }
        } catch (final Exception e) {
            throw new OpenSearchException("Instance {} of class {} is not serializable", e, object, object.getClass());
        }
        final byte[] bytes = streamOutput.bytes().toBytesRef().bytes;
        streamOutput.close();
        return BaseEncoding.base64().encode(bytes);
    }

    public static String serializeObject(final Serializable object, final boolean useJDKSerialization) {
        return useJDKSerialization ? serializeObjectJDK(object) : serializeObjectCustom(object);
    }

    public static String serializeObject(final Serializable object) {
        return serializeObjectCustom(object);
    }

    private static Serializable deserializeObjectJDK(final String string) {

        Preconditions.checkArgument(!Strings.isNullOrEmpty(string), "string must not be null or empty");

        final byte[] bytes = BaseEncoding.base64().decode(string);
        final ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        try (SafeObjectInputStream in = new SafeObjectInputStream(bis)) {
            return (Serializable) in.readObject();
        } catch (final Exception e) {
            throw new OpenSearchException(e);
        }
    }

    private static Serializable deserializeObjectCustom(final String string) {

        Preconditions.checkArgument(!Strings.isNullOrEmpty(string), "string must not be null or empty");
        final byte[] bytes = BaseEncoding.base64().decode(string);
        try (final BytesStreamInput streamInput = new BytesStreamInput(bytes)) {
            CustomSerializationFormat serializationFormat = CustomSerializationFormat.fromId(streamInput.readByte());
            if(serializationFormat.equals(CustomSerializationFormat.WRITEABLE)) {
                final int classId = streamInput.readByte();
                Class<?> clazz = getWriteableClassFromId(classId);
                return (Serializable) clazz.getConstructor(StreamInput.class).newInstance(streamInput);
            } else {
                return (Serializable) streamInput.readGenericValue();
            }
        } catch (final Exception e) {
            throw new OpenSearchException(e);
        }
    }

    public static Serializable deserializeObject(final String string) {
        return deserializeObjectCustom(string);
    }

    public static Serializable deserializeObject(final String string, final boolean useJDKDeserialization) {
        return useJDKDeserialization ? deserializeObjectJDK(string) : deserializeObjectCustom(string);
    }

    private final static class SafeObjectInputStream extends ObjectInputStream {

        public SafeObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {

            Class<?> clazz = super.resolveClass(desc);
            if (isSafeClass(clazz)) {
                return clazz;
            }

            throw new InvalidClassException("Unauthorized deserialization attempt ", clazz.getName());
        }
    }

    private static boolean isWriteable(Class<?> clazz) {
        return Writeable.class.isAssignableFrom(clazz);
    }

    /**
     * Returns integer ID for the registered Writeable class
     * <br/>
     * Protected for testing
     */
    protected static Integer getWriteableClassID(Class<?> clazz) {
        if ( !isWriteable(clazz) ) {
            throw new OpenSearchException("clazz should implement Writeable ", clazz);
        }
        if( !writeableClassToIdMap.get().containsKey(clazz) ) {
            throw new OpenSearchException("Writeable clazz not registered ", clazz);
        }
        return writeableClassToIdMap.get().get(clazz);
    }

    private static Class<?> getWriteableClassFromId(int id) {
        return writeableClassToIdMap.get().inverse().get(id);
    }

    /**
     * Registers the given <code>Writeable</code> class for custom serialization by assigning an incrementing integer ID
     * IDs are stored in two thread local maps
     * @param clazz class to be registered
     */
    private static void registerWriteable(Class<? extends Writeable> clazz) {
        if ( writeableClassToIdMap.get().containsKey(clazz) ) {
            throw new OpenSearchException("writeable clazz is already registered ", clazz.getName());
        }
        int id = writeableClassToIdMap.get().size() + 1;
        writeableClassToIdMap.get().put(clazz, id);
    }

    /**
     * Registers all <code>Writeable</code> classes for custom serialization support.
     * Removing existing classes / changing order of registration will cause a breaking change in the serialization protocol
     * as <code>registerWriteable</code> assigns an incrementing integer ID to each of the classes in the order it is called
     * starting from <code>1</code>.
     *<br/>
     * New classes can safely be added towards the end.
     */
    private static void registerAllWriteables() {
        registerWriteable(User.class);
        registerWriteable(LdapUser.class);
        registerWriteable(SourceFieldsContext.class);
    }

    private static void registerStreamables() {
        registerGenericWriters();
        registerGenericReaders();
    }

    private static void registerGenericWriters() {
        WriteableRegistry.<BaseWriteable.Writer<StreamOutput, ?>>registerWriter(InetSocketAddress.class, (o, v) -> {
            final InetSocketAddress inetSocketAddress = (InetSocketAddress) v;
            o.writeByte((byte) 101);
            o.writeString(inetSocketAddress.getHostString());
            o.writeByteArray(inetSocketAddress.getAddress().getAddress());
            o.writeInt(inetSocketAddress.getPort());
        });
    }

    public static void registerGenericReaders() {
        WriteableRegistry.<BaseWriteable.Reader<StreamInput, ?>>registerReader((byte) 101, (i) -> {
            String host = i.readString();
            byte[] addressBytes = i.readByteArray();
            int port = i.readInt();
            return new InetSocketAddress(InetAddress.getByAddress(host, addressBytes), port);
        });
    }
}
