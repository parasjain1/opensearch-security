package org.opensearch.security.support;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import org.opensearch.OpenSearchException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.BaseWriteable;

/**
 * Registry for any class that does NOT implement the <code>Writeable</code> interface
 * and needs to be serialized over the wire. Supports registration of writer and reader via <code>registerStreamable</code>
 * for such classes and provides methods <code>writeTo</code> and <code>readFrom</code> for objects of such registered classes.
 * <br/>
 * StreamableRegistry is ThreadLocal singleton, so each thread will have its own instance.
 * <br/>
 * Methods are protected and intended to be accessed from only within the package. (mostly by <code>Base64Helper</code>)
 */
public class StreamableRegistry {

    private static final ThreadLocal<StreamableRegistry> THREAD_LOCAL = ThreadLocal.withInitial(StreamableRegistry::new);
    public final BiMap<Class<?>, Integer> classToIdMap = HashBiMap.create();
    private final Map<Integer, Entry> idToEntryMap = new HashMap<>();

    private StreamableRegistry() {}

    private static class Entry {
        BaseWriteable.Writer<StreamOutput, Object> writer;
        BaseWriteable.Reader<StreamInput, Object> reader;

        Entry(BaseWriteable.Writer<StreamOutput, Object> writer, BaseWriteable.Reader<StreamInput, Object> reader) {
            this.writer = writer;
            this.reader = reader;
        }
    }

    private BaseWriteable.Writer<StreamOutput, Object> getWriter(Class<?> clazz) {
        if ( !classToIdMap.containsKey(clazz) ) {
            throw new OpenSearchException(String.format("No writer registered for class %s", clazz.getName()));
        }
        return idToEntryMap.get(classToIdMap.get(clazz)).writer;
    }

    private BaseWriteable.Reader<StreamInput, Object> getReader(int id) {
        if ( !idToEntryMap.containsKey(id) ) {
            throw new OpenSearchException(String.format("No reader registered for id %s", id));
        }
        return idToEntryMap.get(id).reader;
    }

    private int getId(Class<?> clazz) {
        if ( !classToIdMap.containsKey(clazz) ) {
            throw new OpenSearchException(String.format("No writer registered for class %s", clazz.getName()));
        }
        return classToIdMap.get(clazz);
    }

    protected void writeTo(StreamOutput out, Object object) throws IOException {
        out.writeByte((byte) getId(object.getClass()));
        getWriter(object.getClass()).write(out, object);
    }

    protected Object readFrom(StreamInput in) throws IOException {
        int id = in.readByte();
        return getReader(id).read(in);
    }

    protected static StreamableRegistry getInstance() {
        return THREAD_LOCAL.get();
    }

    protected void registerStreamable(Class<?> clazz, BaseWriteable.Writer<StreamOutput, Object> writer, BaseWriteable.Reader<StreamInput, Object> reader) {
        Integer id = classToIdMap.size() + 1;
        classToIdMap.put(clazz, id);
        idToEntryMap.put(id, new Entry(writer, reader));
    }

}
