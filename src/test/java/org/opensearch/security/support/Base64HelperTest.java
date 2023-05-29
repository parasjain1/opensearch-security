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

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.amazon.dlic.auth.ldap.LdapUser;
import com.google.common.io.BaseEncoding;
import org.junit.Assert;
import org.junit.Test;

import org.ldaptive.LdapEntry;
import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import static org.opensearch.security.support.Base64Helper.deserializeObject;
import static org.opensearch.security.support.Base64Helper.serializeObject;

public class Base64HelperTest {

    private static final class NotSafeSerializable implements Serializable {
        private static final long serialVersionUID = 5135559266828470092L;
    }

    private static Serializable ds(Serializable s) {
        return deserializeObject(serializeObject(s));
    }

    @Test
    public void testString() {
        String string = "string";
        Assert.assertEquals(string, ds(string));
    }

    @Test
    public void testInteger() {
        Integer integer = Integer.valueOf(0);
        Assert.assertEquals(integer, ds(integer));
    }

    @Test
    public void testDouble() {
        Double number = Double.valueOf(0.);
        Assert.assertEquals(number, ds(number));
    }

    @Test
    public void testInetSocketAddress() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        Assert.assertEquals(inetSocketAddress, ds(inetSocketAddress));
    }

//    @Test
//    public void testPattern() {
//        Pattern pattern = Pattern.compile(".*");
//        Assert.assertEquals(pattern.pattern(), ((Pattern) ds(pattern)).pattern());
//    }

    @Test
    public void testUser() {
        User user = new User("user");
        Assert.assertEquals(user, ds(user));
    }

    @Test
    public void testLdapUser() {
        LdapUser ldapUser = new LdapUser(
                "username",
                "originalusername",
                new LdapEntry(),
                new AuthCredentials("originalusername", "12345"),
                34,
                WildcardMatcher.ANY
        );
        Assert.assertEquals(ldapUser, ds(ldapUser));
    }

    @Test
    public void testSourceFieldsContext() {
        SourceFieldsContext sourceFieldsContext = new SourceFieldsContext(new SearchRequest(""));
        Assert.assertEquals(sourceFieldsContext.toString(), ds(sourceFieldsContext).toString());
    }

    @Test
    public void testHashMap() {
        HashMap map = new HashMap();
        Assert.assertEquals(map, ds(map));
    }

    @Test
    public void testArrayList() {
        ArrayList list = new ArrayList();
        Assert.assertEquals(list, ds(list));
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeSerializable() {
        serializeObject(new NotSafeSerializable());
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeDeserializable() throws Exception {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(new NotSafeSerializable());
        }
        deserializeObject(BaseEncoding.base64().encode(bos.toByteArray()));
    }

    @Test
    public void testUnmodifiableMap() {
        /**
         * org.opensearch.security.support.Base64HelperTest$1
         * false
         */
        Map map = Collections.unmodifiableMap(new HashMap<>());
        Assert.assertEquals(map, ds((Serializable) map));
    }
}
