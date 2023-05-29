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
import java.util.HashMap;

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

    private static Serializable dsJDK(Serializable s) {
        return deserializeObject(serializeObject(s, true), true);
    }

    private static Serializable ds(Serializable s) {
        return deserializeObject(serializeObject(s));
    }

    @Test
    public void testString() {
        String string = "string";
        Assert.assertEquals(string, ds(string));
        Assert.assertEquals(string, dsJDK(string));
    }

    @Test
    public void testInteger() {
        Integer integer = Integer.valueOf(0);
        Assert.assertEquals(integer, ds(integer));
        Assert.assertEquals(integer, dsJDK(integer));
    }

    @Test
    public void testDouble() {
        Double number = Double.valueOf(0.);
        Assert.assertEquals(number, ds(number));
        Assert.assertEquals(number, dsJDK(number));
    }

    @Test
    public void testInetSocketAddress() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        Assert.assertEquals(inetSocketAddress, ds(inetSocketAddress));
        Assert.assertEquals(inetSocketAddress, dsJDK(inetSocketAddress));
    }

    @Test
    public void testUser() {
        User user = new User("user");
        Assert.assertEquals(user, ds(user));
        Assert.assertEquals(user, dsJDK(user));
    }

    @Test
    public void testSourceFieldsContext() {
        SourceFieldsContext sourceFieldsContext = new SourceFieldsContext(new SearchRequest(""));
        Assert.assertEquals(sourceFieldsContext.toString(), ds(sourceFieldsContext).toString());
        Assert.assertEquals(sourceFieldsContext.toString(), dsJDK(sourceFieldsContext).toString());
    }

    @Test
    public void testHashMap() {
        HashMap map = new HashMap();
        Assert.assertEquals(map, ds(map));
        Assert.assertEquals(map, dsJDK(map));
    }

    @Test
    public void testArrayList() {
        ArrayList list = new ArrayList();
        Assert.assertEquals(list, ds(list));
        Assert.assertEquals(list, dsJDK(list));
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
    public void testLdapUser() {
        LdapUser ldapUser = new LdapUser(
                "username",
                "originalusername",
                new LdapEntry("dn"),
                new AuthCredentials("originalusername", "12345"),
                34,
                WildcardMatcher.ANY
        );
        Assert.assertEquals(ldapUser, ds(ldapUser));
        Assert.assertEquals(ldapUser, dsJDK(ldapUser));
    }

    @Test
    public void testGetWriteableClassID() {
        Assert.assertEquals(Integer.valueOf(1), Base64Helper.getWriteableClassID(User.class));
        Assert.assertEquals(Integer.valueOf(2), Base64Helper.getWriteableClassID(LdapUser.class));
        Assert.assertEquals(Integer.valueOf(3), Base64Helper.getWriteableClassID(SourceFieldsContext.class));
    }

}
