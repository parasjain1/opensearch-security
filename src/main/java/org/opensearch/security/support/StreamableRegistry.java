package org.opensearch.security.support;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import org.opensearch.OpenSearchException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
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

    private StreamableRegistry() {
        registerAllStreamables();
    }

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

    protected boolean isStreamable(Class<?> clazz) {
        return classToIdMap.containsKey(clazz);
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

    protected int getStreamableID(Class<?> clazz) {
        if (!isStreamable(clazz)) {
            throw new OpenSearchException(String.format("class %s is in streamable registry", clazz.getName()));
        }  else {
            return classToIdMap.get(clazz);
        }
    }

    /**
     * Register all streamables here. Register new streamables towards the end.
     * Removing / reordering a registered streamable will change the typeIDs associated with the streamables
     * causing a breaking change in the serialization format.
     */
    private void registerAllStreamables() {

        // InetSocketAddress
        this.registerStreamable(
            InetSocketAddress.class,
            (Writeable.Writer<Object>) (o, v) -> {
                final InetSocketAddress inetSocketAddress = (InetSocketAddress) v;
                o.writeString(inetSocketAddress.getHostString());
                o.writeByteArray(inetSocketAddress.getAddress().getAddress());
                o.writeInt(inetSocketAddress.getPort());
            },
            (Writeable.Reader<Object>) (i) -> {
                String host = i.readString();
                byte[] addressBytes = i.readByteArray();
                int port = i.readInt();
                return new InetSocketAddress(InetAddress.getByAddress(host, addressBytes), port);
            })
        ;
    }

}
