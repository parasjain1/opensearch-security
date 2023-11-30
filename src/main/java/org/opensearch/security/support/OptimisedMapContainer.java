package org.opensearch.security.support;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class OptimisedMapContainer implements Writeable, Serializable {

    private int entriesDeduped = 0;
    private int referenceCounter = 0;
    private boolean isOptimized = false;
    private Map<Object, Integer> references;
    private Map<Integer, Object> inverseReferences;
    private Map<Object, Integer> data;

    private OptimisedMapContainer() {
        inverseReferences = new HashMap<>();
        references = new HashMap<>();
        data = new HashMap<>();
    }

    public OptimisedMapContainer(StreamInput in) throws IOException {
        inverseReferences = (Map<Integer, Object>) in.readGenericValue();
        data = (Map<Object, Integer>) in.readGenericValue();
    }

    public boolean isOptimized() {
        return entriesDeduped > 0;
    }

    public Map<Object, Object> getOriginalMap() {
        // ToDo: de-optimise
        Map<Object, Object> map = new HashMap<>();
        for(Map.Entry<Object, Integer> entry : data.entrySet()) {
            map.put(entry.getKey(), inverseReferences.get(entry.getValue()));
        }
        return map;
    }

    public static OptimisedMapContainer optimise(Object obj) {
        if(!obj.getClass().isAssignableFrom(HashMap.class)) {
            throw new IllegalArgumentException("obj should be of type Map");
        }

        OptimisedMapContainer container = new OptimisedMapContainer();
        Map<Object, Object> map = (Map<Object, Object>) obj;

        if(map.isEmpty()) {
            return container;
        }

        for (Map.Entry<Object, Object> entry : map.entrySet()) {
            Integer reference = container.references.getOrDefault(entry.getValue(), null);
            if(reference != null) {
                container.entriesDeduped++;
            } else {
                reference = ++ container.referenceCounter;
                container.references.put(entry.getValue(), reference);
                container.inverseReferences.put(reference, entry.getValue());
            }
            container.data.put(entry.getKey(), reference);
        }
        return container;
    }

    public static void main(String argv[]) {
        HashMap<String, Set<String>> map = new HashMap<>();
        String string1 = "hello world, this is going to be awesome";
        String string2 = "I'm game, the red fox will never jump";
        String string3 = "Lets nail it, cause you never know";
        String string4 = "Lets nail it, cause you never know";
        String string5 = "Lets nail it, cause you never know";
        String string6 = "Lets nail it, cause you never know";
        for(int i=0; i<100; i++) {
            Set<String> set = new HashSet<>();
            set.add(string1);
            set.add(string2);
            set.add(string3);
            set.add(string4);
            set.add(string5);
            set.add(string6);
            map.put(UUID.randomUUID().toString(), set);
        }
        OptimisedMapContainer s = OptimisedMapContainer.optimise(map);
        System.out.println(s.data);
        System.out.println(s.references);
        System.out.println(Base64CustomHelper.serializeObject(map).length());
        System.out.println(Base64JDKHelper.serializeObject(map).length());
        System.out.println(Base64CustomHelper.serializeObject(s).length());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMap(inverseReferences, StreamOutput::writeInt, StreamOutput::writeGenericValue);
        out.writeGenericValue(data);
    }
}
