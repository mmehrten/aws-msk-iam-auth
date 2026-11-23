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
package software.amazon.msk.auth.iam.internals;

import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClientBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the real {@code awsRoleArn} path of {@link MSKCredentialProvider} (the library's own
 * StsClient and StsAssumeRoleCredentialsProvider) against {@link StubStsHttpService}, which fails
 * like a DNS outage while {@code dnsDown} is set. The ambient identity, standing in for a node or
 * pod role that needs no DNS, is the {@code aws.accessKeyId} system property. Nothing leaves the
 * JVM: the stub HTTP client refuses any non-STS host.
 */
public class RoleCredentialFallbackTest {
    private static final String AMBIENT_KEY = "AKIAAMBIENTNODEROLE";
    private static final String[] PROPERTIES = {
            "aws.accessKeyId", "aws.secretAccessKey", "aws.disableEc2Metadata",
            "aws.sharedCredentialsFile", "aws.configFile"};
    private static final Map<String, String> saved = new LinkedHashMap<>();

    @BeforeAll
    static void installStubs() {
        for (String p : PROPERTIES) {
            saved.put(p, System.getProperty(p));
        }
        System.setProperty("aws.accessKeyId", AMBIENT_KEY);
        System.setProperty("aws.secretAccessKey", "ambientSecret");
        System.setProperty("aws.disableEc2Metadata", "true");
        System.setProperty("aws.sharedCredentialsFile", "/nonexistent/credentials");
        System.setProperty("aws.configFile", "/nonexistent/config");
    }

    @AfterAll
    static void restoreProperties() {
        saved.forEach((k, v) -> {
            if (v == null) {
                System.clearProperty(k);
            } else {
                System.setProperty(k, v);
            }
        });
    }

    @BeforeEach
    void reset() {
        StubStsHttpService.dnsDown = false;
        StubStsHttpService.accessDenied = false;
        StubStsHttpService.credentialLifetime = Duration.ofHours(1);
    }

    @AfterEach
    void restore() {
        reset();
    }

    private static MSKCredentialProvider roleProvider(Map<String, String> extra) {
        Map<String, String> options = new HashMap<>();
        options.put("awsRoleArn", "arn:aws:iam::111122223333:role/msk-client");
        options.put("awsStsRegion", "us-east-1");
        options.put("awsMaxRetries", "0");
        options.putAll(extra);
        // The stub HTTP client is injected into the library's own StsClient builder rather than
        // selected through software.amazon.awssdk.http.service.impl, because the SDK caches the
        // first HTTP implementation it loads for the whole JVM and another test may load it first.
        return new MSKCredentialProvider(new MSKCredentialProvider.ProviderBuilder(options) {
            @Override
            StsClientBuilder getStsClientBuilder(Region stsRegion, Boolean shouldUseFips) {
                return super.getStsClientBuilder(stsRegion, shouldUseFips)
                        .httpClient(new StubStsHttpService.StubClient());
            }
        });
    }

    private static int sts() {
        return StubStsHttpService.assumeRoleAttempts.get();
    }

    @Test
    public void testRoleFailureOnFirstResolveDoesNotPinTheAmbientProvider() {
        try (MSKCredentialProvider provider = roleProvider(new HashMap<>())) {
            StubStsHttpService.dnsDown = true;
            AwsCredentials duringOutage = provider.resolveCredentials();
            assertNotEquals(StubStsHttpService.ROLE_KEY, duringOutage.accessKeyId(),
                    "With STS unreachable the chain falls back to the ambient identity");

            StubStsHttpService.dnsDown = false;
            AwsCredentials afterRecovery = provider.resolveCredentials();
            assertEquals(StubStsHttpService.ROLE_KEY, afterRecovery.accessKeyId(),
                    "Once STS is reachable again the next resolve must return the role credentials, "
                            + "not stay pinned to the ambient provider for the life of the client");
        }
    }

    @Test
    public void testSteadyStateResolveDoesNotCallStsEveryTime() {
        try (MSKCredentialProvider provider = roleProvider(new HashMap<>())) {
            int before = sts();
            for (int i = 0; i < 20; i++) {
                assertEquals(StubStsHttpService.ROLE_KEY, provider.resolveCredentials().accessKeyId());
            }
            assertEquals(1, sts() - before,
                    "The assume-role provider caches its session, so 20 resolves cost one AssumeRole");
        }
    }

    @Test
    public void testPermanentRoleFailureStillFallsBackOnEveryResolve() {
        // Users whose AssumeRole never succeeds and who rely on the default-chain fallback keep
        // working: every resolve still returns the ambient identity. What it costs per resolve
        // (STS attempts and latency) is printed for the record.
        StubStsHttpService.dnsDown = true;
        assertFallbackOnEveryResolve("unreachable");
    }

    @Test
    public void testPermanentAccessDeniedStillFallsBackOnEveryResolve() {
        // The likelier permanent failure: the role's trust policy rejects the caller.
        StubStsHttpService.accessDenied = true;
        assertFallbackOnEveryResolve("accessDenied");
    }

    private static void assertFallbackOnEveryResolve(String label) {
        try (MSKCredentialProvider provider = roleProvider(new HashMap<>())) {
            for (int i = 1; i <= 3; i++) {
                int before = sts();
                long t0 = System.nanoTime();
                AwsCredentials c = provider.resolveCredentials();
                long ms = (System.nanoTime() - t0) / 1_000_000;
                int calls = sts() - before;
                System.out.println("[FALLBACK-COST] " + label + " resolve#" + i + " key=" + c.accessKeyId()
                        + " stsAttempts=" + calls + " took=" + ms + "ms");
                assertNotEquals(StubStsHttpService.ROLE_KEY, c.accessKeyId());
                assertTrue(calls >= 1, "the role is retried on resolve#" + i);
            }
        }
    }

    @Test
    public void testRoleExpiryDuringOutageFallsBackThenReturnsToRole() throws Exception {
        // Credentials that are stale on arrival make every resolve refresh, standing in for a
        // session that expires while STS is unreachable.
        StubStsHttpService.credentialLifetime = Duration.ofSeconds(30);
        try (MSKCredentialProvider provider = roleProvider(new HashMap<>())) {
            assertEquals(StubStsHttpService.ROLE_KEY, provider.resolveCredentials().accessKeyId());
            StubStsHttpService.dnsDown = true;
            Thread.sleep(1100);
            assertNotEquals(StubStsHttpService.ROLE_KEY, provider.resolveCredentials().accessKeyId(),
                    "An expired role session during an outage falls back like a first resolve does");
            StubStsHttpService.dnsDown = false;
            Thread.sleep(1100);
            assertEquals(StubStsHttpService.ROLE_KEY, provider.resolveCredentials().accessKeyId());
        }
    }

    @Test
    public void testAddDefaultProvidersFalseStillFailsFastAndRecovers() {
        Map<String, String> extra = new HashMap<>();
        extra.put("awsAddDefaultProviders", "false");
        try (MSKCredentialProvider provider = roleProvider(extra)) {
            StubStsHttpService.dnsDown = true;
            assertThrows(SdkClientException.class, provider::resolveCredentials);
            StubStsHttpService.dnsDown = false;
            assertEquals(StubStsHttpService.ROLE_KEY, provider.resolveCredentials().accessKeyId());
        }
    }
}
