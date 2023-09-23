/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.bwc;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.core5.http.HttpHost;
import org.junit.Assert;

import org.opensearch.Version;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.bwc.helpers.TestHelper;

import static org.hamcrest.Matchers.hasItem;

public class SecurityBackwardsCompatibilityIT extends SecurityBackwardsCompatibilityTestCase {

    private RestClient basicAuthClient;

    private static final String TEST_USER = "user";
    private static final String TEST_PASSWORD = "password";

    private static final String TEST_ROLE = "test-dls-fls-role";

//    @Before
//    private void testSetup() throws IOException {
//        final String bwcsuiteString = System.getProperty("tests.rest.bwcsuite");
//        Assume.assumeTrue("Test cannot be run outside the BWC gradle task 'bwcTestSuite' or its dependent tasks", bwcsuiteString != null);
//        CLUSTER_TYPE = ClusterType.parse(bwcsuiteString);
//        CLUSTER_NAME = System.getProperty("tests.clustername");
//        List<HttpHost> clusterHosts = getClusterHosts();
//        basicAuthClient = getClientWithBasicAuth(restClientSettings(), clusterHosts.toArray(new HttpHost[0]), TEST_USER, TEST_PASSWORD);
//    }

    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }


//    public void testBasicBackwardsCompatibility() throws Exception {
//        String round = System.getProperty("tests.rest.bwcsuite_round");
//        if (round.equals("first") || round.equals("old")) {
//            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-0/plugins");
//        } else if (round.equals("second")) {
//            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-1/plugins");
//        } else if (round.equals("third")) {
//            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-2/plugins");
//        }
//    }

    public void testDataIngestionAndSearchBackwardsCompatibility() throws Exception {
        String round = System.getProperty("tests.rest.bwcsuite_round");
        String index = String.format("test_index-%s", round);
        if (round.equals("first") || round.equals("old")) {
            createDLSFLSTestRole();
            createUser();
            createIndex(index);
            ingestData(index);
            searchMatchAll(index);
        } else if(round.equals("second")) {
            ingestData(index);
            searchMatchAll(index);
        } else if(round.equals("third")) {
            ingestData(index);
            searchMatchAll(index);
        }
    }

    private enum ClusterType {
        OLD,
        MIXED,
        UPGRADED;

        public static ClusterType parse(String value) {
            switch (value) {
                case "old_cluster":
                    return OLD;
                case "mixed_cluster":
                    return MIXED;
                case "upgraded_cluster":
                    return UPGRADED;
                default:
                    throw new AssertionError("unknown cluster type: " + value);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void assertPluginUpgrade(String uri) throws Exception {
        Map<String, Map<String, Object>> responseMap = (Map<String, Map<String, Object>>) getAsMap(uri).get("nodes");
        for (Map<String, Object> response : responseMap.values()) {
            List<Map<String, Object>> plugins = (List<Map<String, Object>>) response.get("plugins");
            Set<String> pluginNames = plugins.stream().map(map -> (String) map.get("name")).collect(Collectors.toSet());

            final Version minNodeVersion = this.minimumNodeVersion();

            if (minNodeVersion.major <= 1) {
                assertThat(pluginNames, hasItem("opensearch_security"));
            } else {
                assertThat(pluginNames, hasItem("opensearch-security"));
            }

        }
    }

    private void createIndex(String index) throws IOException {
//        String settings = "{\n" +
//                "  \"settings\": {\n" +
//                "    \"index\": {\n" +
//                "      \"number_of_shards\": 3,\n" +
//                "      \"number_of_replicas\": 1\n" +
//                "    }\n" +
//                "  },\n" +
//                "  \"mappings\": {\n" +
//                "    \"properties\": {\n" +
//                "      \"age\": {\n" +
//                "        \"type\": \"integer\"\n" +
//                "      }\n" +
//                "    }\n" +
//                "  },\n" +
//                "  \"aliases\": {\n" +
//                "    \"sample-alias1\": {}\n" +
//                "  }\n" +
//                "}";
        Response response = TestHelper.makeRequest(
                client(),
                "PUT",
                index,
                null,
                TestHelper.toHttpEntity("{}"),
                null,
                false
        );
        logger.info(response.getStatusLine());
    }

    private void ingestData(String index) throws IOException {
        StringBuilder bulkRequestBody = new StringBuilder();
        ObjectMapper objectMapper = new ObjectMapper();
        for(Song song : Song.SONGS) {
            Map<String, Map<String, String>> indexRequest = new HashMap<>();
            indexRequest.put("index", new HashMap<>() {{
                put("_index", index);
            }});
            bulkRequestBody.append(String.format("%s\n", objectMapper.writeValueAsString(indexRequest)));
            bulkRequestBody.append(String.format("%s\n", objectMapper.writeValueAsString(song.asJson())));
        }

        Response response = TestHelper.makeRequest(
                basicAuthClient,
                "POST",
                "_bulk",
                null,
                TestHelper.toHttpEntity(bulkRequestBody.toString()),
                null,
                false
        );

        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
    }

    private void searchMatchAll(String index) throws IOException {
        String matchAllQuery = "{\n" +
                "    \"query\": {\n" +
                "        \"match_all\": {}\n" +
                "    }\n" +
                "}";

        String url = String.format("%s/_search", index);

        Response response = TestHelper.makeRequest(
                basicAuthClient,
                "POST",
                url,
                null,
                TestHelper.toHttpEntity(matchAllQuery),
                null,
                false
        );

        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
    }

    private void createDLSFLSTestRole() throws IOException {
        String url = String.format("_plugins/_security/api/roles/%s", TEST_ROLE);
        String roleSettings = "{\n" +
                "    \"reserved\" : false,\n" +
                "    \"hidden\" : false,\n" +
                "    \"cluster_permissions\" : [\n" +
                "      \"unlimited\"\n" +
                "    ],\n" +
                "    \"index_permissions\" : [\n" +
                "      {\n" +
                "        \"index_patterns\" : [\n" +
                "          \"test-index-*\"\n" +
                "        ],\n" +
                "        \"dls\" : \"{\\n \\t\\\"bool\\\": {\\n \\t\\t\\\"must\\\": {\\n \\t\\t\\t\\\"match\\\": {\\n \\t\\t\\t\\t\\\"genre\\\": \\\"rock\\\"\\n \\t\\t\\t}\\n \\t\\t}\\n \\t}\\n }\",\n" +
                "        \"fls\" : [\n" +
                "          \"~lyrics\"\n" +
                "        ],\n" +
                "        \"masked_fields\" : [\n" +
                "          \"artist\"\n" +
                "        ],\n" +
                "        \"allowed_actions\" : [ ]\n" +
                "      }\n" +
                "    ],\n" +
                "    \"tenant_permissions\" : [ ],\n" +
                "    \"static\" : false\n" +
                "  },\n" +
                "  \"asynchronous_search_read_access\" : {\n" +
                "    \"reserved\" : true,\n" +
                "    \"hidden\" : false,\n" +
                "    \"cluster_permissions\" : [\n" +
                "      \"cluster:admin/opendistro/asynchronous_search/get\"\n" +
                "    ],\n" +
                "    \"index_permissions\" : [ ],\n" +
                "    \"tenant_permissions\" : [ ],\n" +
                "    \"static\" : false\n" +
                "  },\n" +
                "  \"index_management_full_access\" : {\n" +
                "    \"reserved\" : true,\n" +
                "    \"hidden\" : false,\n" +
                "    \"cluster_permissions\" : [\n" +
                "      \"cluster:admin/opendistro/ism/*\",\n" +
                "      \"cluster:admin/opendistro/rollup/*\",\n" +
                "      \"cluster:admin/opendistro/transform/*\",\n" +
                "      \"cluster:admin/opensearch/notifications/feature/publish\"\n" +
                "    ],\n" +
                "    \"index_permissions\" : [\n" +
                "      {\n" +
                "        \"index_patterns\" : [\n" +
                "          \"*\"\n" +
                "        ],\n" +
                "        \"fls\" : [ ],\n" +
                "        \"masked_fields\" : [ ],\n" +
                "        \"allowed_actions\" : [\n" +
                "          \"indices:admin/opensearch/ism/*\"\n" +
                "        ]\n" +
                "      }\n" +
                "    ],\n" +
                "    \"tenant_permissions\" : [ ],\n" +
                "    \"static\" : false\n" +
                "  }";

        Response response = TestHelper.makeRequest(
                adminClient(),
                "PUT",
                url,
                null,
                TestHelper.toHttpEntity(roleSettings),
                null,
                false
        );

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
    }

    private void createUser() throws IOException {
        String url = String.format("_plugins/_security/api/internalusers/%s", TEST_USER);
        String userSettings = String.format("{\n" +
                "  \"password\": \"%s\",\n" +
                "  \"opendistro_security_roles\": [\"%s\"],\n" +
                "  \"backend_roles\": [],\n" +
                "}", TEST_PASSWORD, TEST_ROLE);
        Response response = TestHelper.makeRequest(
                adminClient(),
                "PUT",
                url,
                null,
                TestHelper.toHttpEntity(userSettings),
                null,
                false
        );
    }

    private RestClient getClientWithBasicAuth(Settings settings, HttpHost[] hosts, String username, String password) throws IOException {
        final BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(
                new AuthScope(null, null, -1, null, null),
                new UsernamePasswordCredentials(username, password.toCharArray())
        );
        RestClientBuilder builder = RestClient.builder(hosts);
        configureClient(builder, settings);
        builder.setStrictDeprecationMode(true);
        builder.setHttpClientConfigCallback(httpAsyncClientBuilder -> httpAsyncClientBuilder.setDefaultCredentialsProvider(credentialsProvider));
        return builder.build();
    }
}
