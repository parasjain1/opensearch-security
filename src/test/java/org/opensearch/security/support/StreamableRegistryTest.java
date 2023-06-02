package org.opensearch.security.support;

import org.junit.Assert;
import org.junit.Test;

import java.net.InetSocketAddress;

public class StreamableRegistryTest {

    StreamableRegistry streamableRegistry = StreamableRegistry.getInstance();
    @Test
    public void testStreamableTypeIDs() {
        Assert.assertEquals(1, streamableRegistry.getStreamableID(InetSocketAddress.class));
    }
}
