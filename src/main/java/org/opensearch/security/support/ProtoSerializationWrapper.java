package org.opensearch.security.support;

import jdk.internal.reflect.ReflectionFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.AccessController;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ProtoSerializationWrapper {
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

    private static class ProtoSerializationInfo {

        private Class<?> clazz;

        private static final ReflectionFactory reflFactory =
                AccessController.doPrivileged(
                        new ReflectionFactory.GetReflectionFactoryAction());
        private final Method writeObjectMethod;
        private final Method readObjectMethod;

        private ProtoSerializationInfo(Class<?> clazz) {
            this.clazz = clazz;
            this.writeObjectMethod = getPrivateMethod(clazz, "writeObject", new Class<?>[] { ObjectOutputStream.class }, Void.TYPE);
            this.readObjectMethod = getPrivateMethod(clazz, "readObject", new Class<?>[] { ObjectInputStream.class }, Void.TYPE);
        }

        public boolean supportsCustom() {
            return writeObjectMethod != null && readObjectMethod != null;
        }

        byte[] invokeWriteObject(Object obj)
                throws IOException, UnsupportedOperationException
        {
            if (writeObjectMethod != null) {
                try {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    ObjectOutputStream out = new ObjectOutputStream(bos);
                    writeObjectMethod.invoke(obj, out);
                    out.close();
                    return bos.toByteArray();
                } catch (InvocationTargetException ex) {
                    Throwable th = ex.getTargetException();
                    if (th instanceof IOException) {
                        throw (IOException) th;
                    } else {
                        throw new UnsupportedOperationException(th);
                    }
                } catch (IllegalAccessException ex) {
                    // should not occur, as access checks have been suppressed
                    throw new InternalError(ex);
                }
            } else {
                throw new UnsupportedOperationException();
            }
        }

        Object invokeReadObject(byte[] bytez)
                throws ClassNotFoundException, IOException,
                UnsupportedOperationException
        {
            if (readObjectMethod != null) {
                try {
                    ByteArrayInputStream bis = new ByteArrayInputStream(bytez);
                    ObjectInputStream in = new ObjectInputStream(bis);
                    Object obj = reflFactory.newConstructorForSerialization(clazz).newInstance();
                    readObjectMethod.invoke(obj, in);
                    return obj;
                } catch (InvocationTargetException ex) {
                    Throwable th = ex.getTargetException();
                    if (th instanceof ClassNotFoundException) {
                        throw (ClassNotFoundException) th;
                    } else if (th instanceof IOException) {
                        throw (IOException) th;
                    } else {
                        throw new UnsupportedOperationException(th);
                    }
                } catch (IllegalAccessException ex) {
                    // should not occur, as access checks have been suppressed
                    throw new InternalError(ex);
                } catch (InstantiationException e) {
                    throw new RuntimeException(e);
                }
            } else {
                throw new UnsupportedOperationException();
            }
        }


        private static Method getPrivateMethod(Class<?> cl, String name,
                                               Class<?>[] argTypes,
                                               Class<?> returnType)
        {
            try {
                Method meth = cl.getDeclaredMethod(name, argTypes);
                meth.setAccessible(true);
                int mods = meth.getModifiers();
                return ((meth.getReturnType() == returnType) &&
                        ((mods & Modifier.STATIC) == 0) &&
                        ((mods & Modifier.PRIVATE) != 0)) ? meth : null;
            } catch (NoSuchMethodException ex) {
                return null;
            }
        }
    }

    private Serializable serializable;

    private static final Map<Class<?>, ProtoSerializationInfo> protoSerializationInfoMap = new ConcurrentHashMap<>();

    public ProtoSerializationWrapper(Serializable serializable) throws IOException {
        this.assignSerializable(serializable);
    }

    private static ProtoSerializationInfo getProtoSerializationInfo(Serializable serializable) {
        if (!protoSerializationInfoMap.containsKey(serializable.getClass())) {
            protoSerializationInfoMap.put(serializable.getClass(), new ProtoSerializationInfo(serializable.getClass()));
        }
        return protoSerializationInfoMap.get(serializable.getClass());
    }

    private void assignSerializable(Serializable serializable) throws IOException {
        ProtoSerializationInfo serializationInfo = getProtoSerializationInfo(serializable);
        if(serializationInfo.supportsCustom()) {
            this.serializable = serializationInfo.invokeWriteObject(serializable);
        } else {
            this.serializable = serializable;
        }
    }

    public Serializable getSerializable() {
        return this.serializable;
    }

}
