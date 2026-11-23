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

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Minimal UDP DNS server on 127.0.0.1 for JNDI CNAME lookups (java.naming.provider.url points
 * here). Mode UP answers CNAME alias -> target; SERVFAIL answers rcode 2 (what a resolver
 * returns when its upstream is gone); SILENT drops the query (CoreDNS pods absent: the client
 * times out). Names other than the alias get NXDOMAIN.
 */
public final class StubDnsServer implements AutoCloseable {
    public enum Mode { UP, SERVFAIL, SILENT }

    public volatile Mode mode = Mode.UP;
    public final AtomicInteger queries = new AtomicInteger();
    private final DatagramSocket socket;
    private final String alias;
    private final String target;
    private final Thread thread;

    public StubDnsServer(String alias, String target) throws SocketException {
        this.socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        this.alias = alias.toLowerCase(Locale.ROOT);
        this.target = target;
        this.thread = new Thread(this::serve, "stub-dns");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    public int port() {
        return socket.getLocalPort();
    }

    private void serve() {
        byte[] buf = new byte[512];
        while (!socket.isClosed()) {
            try {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                socket.receive(p);
                queries.incrementAndGet();
                Mode m = mode;
                if (m == Mode.SILENT) {
                    continue;
                }
                byte[] q = java.util.Arrays.copyOf(p.getData(), p.getLength());
                // Parse the question name (starts at offset 12).
                int i = 12;
                StringBuilder name = new StringBuilder();
                while (q[i] != 0) {
                    int len = q[i] & 0xff;
                    if (name.length() > 0) {
                        name.append('.');
                    }
                    name.append(new String(q, i + 1, len, java.nio.charset.StandardCharsets.US_ASCII));
                    i += len + 1;
                }
                int qEnd = i + 1 + 4; // zero byte + qtype + qclass
                int qtype = ((q[i + 1] & 0xff) << 8) | (q[i + 2] & 0xff);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write(q[0]);
                out.write(q[1]);
                boolean match = name.toString().toLowerCase(Locale.ROOT).equals(alias);
                int rcode = m == Mode.SERVFAIL ? 2 : (match ? 0 : 3);
                boolean answer = rcode == 0 && (qtype == 5 || qtype == 255);
                out.write(0x81);                 // QR=1, RD=1
                out.write(0x80 | rcode);         // RA=1, rcode
                out.write(0); out.write(1);      // QDCOUNT
                out.write(0); out.write(answer ? 1 : 0); // ANCOUNT
                out.write(0); out.write(0);
                out.write(0); out.write(0);
                out.write(q, 12, qEnd - 12);     // question
                if (answer) {
                    byte[] rdata = encodeName(target);
                    out.write(0xc0); out.write(0x0c); // name pointer to question
                    out.write(0); out.write(5);       // TYPE CNAME
                    out.write(0); out.write(1);       // CLASS IN
                    out.write(0); out.write(0); out.write(0); out.write(0); // TTL 0
                    out.write(rdata.length >> 8); out.write(rdata.length & 0xff);
                    out.write(rdata, 0, rdata.length);
                }
                byte[] resp = out.toByteArray();
                socket.send(new DatagramPacket(resp, resp.length, p.getSocketAddress()));
            } catch (Exception e) {
                if (socket.isClosed()) {
                    return;
                }
            }
        }
    }

    private static byte[] encodeName(String n) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (String label : n.split("\\.")) {
            o.write(label.length());
            o.write(label.getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, label.length());
        }
        o.write(0);
        return o.toByteArray();
    }

    @Override
    public void close() {
        socket.close();
    }
}
