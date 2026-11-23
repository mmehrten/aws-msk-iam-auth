/*
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
package software.amazon.msk.auth.iam.internals.region;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Counts the DNS queries a DNS-backed region provider really sends for a given {@code dns.retries},
 * against a stub DNS server on 127.0.0.1. {@code dns.retries=N} means one initial attempt plus N
 * retries, so N + 1 queries to an unresponsive server, and exactly one query when the first is
 * answered.
 */
public class DnsRetriesAttemptCountTest {
    private static final String ALIAS = "producer.amer-0.msk.gwcp.example";
    private static final String TARGET = "b-1.demo.abc123.c2.kafka.us-east-2.amazonaws.com";
    private static final String PROVIDER_URL = "java.naming.provider.url";

    private static StubDnsServer dns;
    private static String previousProviderUrl;

    @BeforeAll
    static void startDns() throws Exception {
        dns = new StubDnsServer(ALIAS, TARGET);
        previousProviderUrl = System.getProperty(PROVIDER_URL);
        System.setProperty(PROVIDER_URL, "dns://127.0.0.1:" + dns.port());
    }

    @AfterAll
    static void stopDns() {
        if (previousProviderUrl == null) {
            System.clearProperty(PROVIDER_URL);
        } else {
            System.setProperty(PROVIDER_URL, previousProviderUrl);
        }
        dns.close();
    }

    @BeforeEach
    void reset() {
        dns.mode = StubDnsServer.Mode.UP;
        dns.queries.set(0);
    }

    @AfterEach
    void restoreMode() {
        dns.mode = StubDnsServer.Mode.UP;
    }

    private static CnameRegionProvider provider(String retries) {
        // Silent-resolver cases time out on every attempt, so keep that short.
        return provider(retries, "20");
    }

    private static CnameRegionProvider provider(String retries, String timeoutMs) {
        Map<String, String> config = new HashMap<>();
        config.put("dns.timeout.ms", timeoutMs);
        if (retries != null) {
            config.put("dns.retries", retries);
        }
        return new CnameRegionProvider(config);
    }

    @Test
    public void testZeroRetriesStillSendsOneQueryAndResolves() {
        // On a resolver that answers, dns.retries=0 must still send the one initial query.
        String cname = provider("0", "2000").resolveCname(ALIAS);
        assertEquals(TARGET + ".", cname, "JNDI returns the fully-qualified target");
        assertEquals(1, dns.queries.get(), "dns.retries=0 means one attempt, not zero");
    }

    @Test
    public void testZeroRetriesResolvesTheRegionEndToEnd() {
        // On main the provider sent no query at all, so the region could never be learned.
        assertEquals(Region.US_EAST_2, provider("0", "2000").getRegion(ALIAS));
    }

    @Test
    public void testZeroRetriesAgainstSilentResolverSendsExactlyOneQuery() {
        assertSilentQueries("0", 1);
    }

    @Test
    public void testOneRetrySendsTwoQueries() {
        assertSilentQueries("1", 2);
    }

    @Test
    public void testTwoRetriesSendThreeQueries() {
        assertSilentQueries("2", 3);
    }

    @Test
    public void testDefaultSendsTheJdkDefaultFourQueries() {
        // Unset dns.retries must keep the attempt count the JDK uses when the property is absent.
        assertSilentQueries(null, 4);
    }

    private static void assertSilentQueries(String retries, int expectedQueries) {
        dns.mode = StubDnsServer.Mode.SILENT;
        CnameRegionProvider provider = provider(retries);
        assertThrows(SdkClientException.class, () -> provider.resolveCname(ALIAS));
        assertEquals(expectedQueries, dns.queries.get(),
                "dns.retries=" + retries + " against a silent resolver");
    }
}
