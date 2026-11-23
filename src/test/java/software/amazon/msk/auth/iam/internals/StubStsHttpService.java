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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicInteger;

import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.http.SdkHttpService;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * In-process stand-in for every SDK sync HTTP call (selected with the system property
 * software.amazon.awssdk.http.service.impl). Nothing leaves the JVM. While dnsDown is true it
 * fails exactly like a CoreDNS outage does in the real Apache client: UnknownHostException for
 * the STS host. Otherwise it answers STS AssumeRole with fixed role credentials.
 */
public class StubStsHttpService implements SdkHttpService {
    public static volatile boolean dnsDown = false;
    public static final AtomicInteger assumeRoleAttempts = new AtomicInteger();
    public static final AtomicInteger assumeRoleSuccesses = new AtomicInteger();
    public static final String ROLE_KEY = "ASIAROLEFROMASSUMEROLE";
    /** Lifetime of the issued role credentials. Under a minute makes them stale on arrival. */
    public static volatile Duration credentialLifetime = Duration.ofHours(1);
    /** When set, AssumeRole answers 403 AccessDenied, like a role whose trust policy rejects the caller. */
    public static volatile boolean accessDenied = false;

    @Override
    public SdkHttpClient.Builder createHttpClientBuilder() {
        return new SdkHttpClient.Builder() {
            @Override
            public SdkHttpClient buildWithDefaults(AttributeMap serviceDefaults) {
                return new StubClient();
            }
        };
    }

    static final class StubClient implements SdkHttpClient {
        @Override
        public ExecutableHttpRequest prepareRequest(HttpExecuteRequest request) {
            return new ExecutableHttpRequest() {
                @Override
                public HttpExecuteResponse call() throws IOException {
                    String host = request.httpRequest().host();
                    if (!host.startsWith("sts")) {
                        throw new IOException("stub refuses non-STS host " + host);
                    }
                    assumeRoleAttempts.incrementAndGet();
                    if (dnsDown) {
                        throw new UnknownHostException(host + ": Temporary failure in name resolution (stubbed CoreDNS outage)");
                    }
                    if (accessDenied) {
                        byte[] denied = ("<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error>"
                                + "<Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized to perform"
                                + " sts:AssumeRole</Message></Error><RequestId>stub</RequestId></ErrorResponse>")
                                .getBytes(StandardCharsets.UTF_8);
                        return HttpExecuteResponse.builder()
                                .response(SdkHttpResponse.builder().statusCode(403)
                                        .putHeader("Content-Type", "text/xml")
                                        .putHeader("Content-Length", Integer.toString(denied.length)).build())
                                .responseBody(AbortableInputStream.create(new ByteArrayInputStream(denied)))
                                .build();
                    }
                    assumeRoleSuccesses.incrementAndGet();
                    String exp = Instant.now().plus(credentialLifetime).truncatedTo(ChronoUnit.SECONDS).toString();
                    String body = "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                            + "<AssumeRoleResult><Credentials><AccessKeyId>" + ROLE_KEY + "</AccessKeyId>"
                            + "<SecretAccessKey>roleSecret</SecretAccessKey><SessionToken>roleToken</SessionToken>"
                            + "<Expiration>" + exp + "</Expiration></Credentials>"
                            + "<AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/msk-client/aws-msk-iam-auth</Arn>"
                            + "<AssumedRoleId>AROAEXAMPLE:aws-msk-iam-auth</AssumedRoleId></AssumedRoleUser>"
                            + "</AssumeRoleResult><ResponseMetadata><RequestId>stub</RequestId></ResponseMetadata>"
                            + "</AssumeRoleResponse>";
                    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                    return HttpExecuteResponse.builder()
                            .response(SdkHttpResponse.builder().statusCode(200)
                                    .putHeader("Content-Type", "text/xml")
                                    .putHeader("Content-Length", Integer.toString(bytes.length)).build())
                            .responseBody(AbortableInputStream.create(new ByteArrayInputStream(bytes)))
                            .build();
                }

                @Override
                public void abort() {
                }
            };
        }

        @Override
        public void close() {
        }
    }
}
