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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import io.protostuff.LinkedBuffer;
import io.protostuff.ProtostuffIOUtil;
import io.protostuff.Schema;
import io.protostuff.runtime.RuntimeSchema;
import org.ldaptive.AbstractLdapBean;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchEntry;

import com.amazon.dlic.auth.ldap.LdapUser;

import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.Strings;
import org.opensearch.security.user.User;

public class Base64Helper {

    private static final ThreadLocal<LinkedBuffer> threadLocalLinkedBuffer = ThreadLocal.withInitial(() -> LinkedBuffer.allocate(1024));

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

    private static final Set<String> SAFE_CLASS_NAMES = Collections.singleton(
        "org.ldaptive.LdapAttribute$LdapAttributeValues"
    );

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

    public static String serializeObjectJDK(final Serializable object) {

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

    public static Serializable deserializeObjectJDK(final String string) {

        Preconditions.checkArgument(!Strings.isNullOrEmpty(string), "string must not be null or empty");

        final byte[] bytes = BaseEncoding.base64().decode(string);
        final ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        try (SafeObjectInputStream in = new SafeObjectInputStream(bis)) {
            return (Serializable) in.readObject();
        } catch (final Exception e) {
            throw new OpenSearchException(e);
        }
    }


    public static Serializable deserializeObjectProto(final String string) {
        //ToDo: introduce safe class checks during deserialization using proto
        Preconditions.checkArgument(!Strings.isNullOrEmpty(string), "string must not be null or empty");
        final byte[] bytes = BaseEncoding.base64().decode(string);
        try {
            Schema<SerializableWrapper> schema = RuntimeSchema.getSchema(SerializableWrapper.class);
            SerializableWrapper serializableWrapper = schema.newMessage();
            ProtostuffIOUtil.mergeFrom(bytes, serializableWrapper, schema);
            return serializableWrapper.serializable;
        } catch (final Exception e) {
            throw new OpenSearchException(e);
        }
    }

    public static Serializable deserializeObject(final String string, final boolean useJDKDeserialization) {
        return useJDKDeserialization ? deserializeObjectJDK(string) : deserializeObjectProto(string);
    }

    public static Serializable deserializeObject(final String string) {
        return deserializeObjectProto(string);
    }

    public static String serializeObjectProto(final Serializable object) {
        //ToDo: introduce safe class checks during serialization using proto
        SerializableWrapper serializableWrapper = new SerializableWrapper(object);
        Preconditions.checkArgument(object != null, "object must not be null");
        byte[] byteArray;
        Schema<SerializableWrapper> schema = RuntimeSchema.getSchema(SerializableWrapper.class);
        try {
            byteArray = ProtostuffIOUtil.toByteArray(serializableWrapper, schema, threadLocalLinkedBuffer.get());
            threadLocalLinkedBuffer.get().clear();
        } catch (Exception e) {
            throw new OpenSearchException("Instance {} of class {} is not serializable", e, object, object.getClass());
        }
        return BaseEncoding.base64().encode(byteArray);
    }

    public static String serializeObject(final Serializable object, final boolean useJDKSerialization) {
        return useJDKSerialization ? serializeObjectJDK(object) : serializeObjectProto(object);
    }

    public static String serializeObject(final Serializable object) {
        return serializeObjectProto(object);
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


    private static class SerializableWrapper {
        /*
         * Introduction of SerializableWrapper eases the protostuff deserialization part.
         *
         * When deserializing, we need to fetch the root proto Schema by specifying the class of the object that we
         * intend to deserialize. The serialized bytes in case of proto do not have a class label, hence it's not
         * possible to generically identify what object type are we deserializing.
         *
         * SerializableWrapper here will hold our actual serializable object, and we'll always (de)serialize
         * SerializableWrapper object. Protostuff will internally construct and maintain schemas for underlying
         * classes.
         */
        Serializable serializable;

        public SerializableWrapper(Serializable serializable) {
            this.serializable = serializable;
        }
    }
}
