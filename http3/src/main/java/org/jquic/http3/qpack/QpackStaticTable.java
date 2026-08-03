/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jquic.http3.qpack;

import java.util.List;

public class QpackStaticTable {

    public record Entry(String name, String value) {}

    public static final List<Entry> TABLE = List.of(
        new Entry(":authority", ""),
        new Entry(":path", "/"),
        new Entry("age", "0"),
        new Entry("content-disposition", ""),
        new Entry("content-length", "0"),
        new Entry("cookie", ""),
        new Entry("date", ""),
        new Entry("etag", ""),
        new Entry("if-modified-since", ""),
        new Entry("if-none-match", ""),
        new Entry("last-modified", ""),
        new Entry("link", ""),
        new Entry("location", ""),
        new Entry("referer", ""),
        new Entry("set-cookie", ""),
        new Entry(":method", "CONNECT"),
        new Entry(":method", "DELETE"),
        new Entry(":method", "GET"),
        new Entry(":method", "HEAD"),
        new Entry(":method", "OPTIONS"),
        new Entry(":method", "POST"),
        new Entry(":method", "PUT"),
        new Entry(":scheme", "http"),
        new Entry(":scheme", "https"),
        new Entry(":status", "103"),
        new Entry(":status", "200"),
        new Entry(":status", "304"),
        new Entry(":status", "404"),
        new Entry(":status", "503"),
        new Entry("accept", "*/*"),
        new Entry("accept", "application/dns-message"),
        new Entry("accept-encoding", "gzip, deflate, br"),
        new Entry("accept-ranges", "bytes"),
        new Entry("access-control-allow-headers", "cache-control"),
        new Entry("access-control-allow-headers", "content-type"),
        new Entry("access-control-allow-origin", "*"),
        new Entry("cache-control", "max-age=0"),
        new Entry("cache-control", "max-age=2592000"),
        new Entry("cache-control", "max-age=604800"),
        new Entry("cache-control", "no-cache"),
        new Entry("cache-control", "no-store"),
        new Entry("cache-control", "public, max-age=31536000"),
        new Entry("content-encoding", "br"),
        new Entry("content-encoding", "gzip"),
        new Entry("content-type", "application/dns-message"),
        new Entry("content-type", "application/javascript"),
        new Entry("content-type", "application/json"),
        new Entry("content-type", "application/x-www-form-urlencoded"),
        new Entry("content-type", "image/gif"),
        new Entry("content-type", "image/jpeg"),
        new Entry("content-type", "image/png"),
        new Entry("content-type", "text/css"),
        new Entry("content-type", "text/html; charset=utf-8"),
        new Entry("content-type", "text/plain"),
        new Entry("content-type", "text/plain;charset=utf-8"),
        new Entry("range", "bytes=0-"),
        new Entry("strict-transport-security", "max-age=31536000"),
        new Entry("strict-transport-security", "max-age=31536000; includesubdomains"),
        new Entry("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        new Entry("vary", "accept-encoding"),
        new Entry("vary", "origin"),
        new Entry("x-content-type-options", "nosniff"),
        new Entry("x-xss-protection", "1; mode=block"),
        new Entry(":status", "100"),
        new Entry(":status", "204"),
        new Entry(":status", "206"),
        new Entry(":status", "302"),
        new Entry(":status", "400"),
        new Entry(":status", "403"),
        new Entry(":status", "421"),
        new Entry(":status", "425"),
        new Entry(":status", "500"),
        new Entry("accept-language", ""),
        new Entry("access-control-allow-credentials", "FALSE"),
        new Entry("access-control-allow-credentials", "TRUE"),
        new Entry("access-control-allow-headers", "*"),
        new Entry("access-control-allow-methods", "get"),
        new Entry("access-control-allow-methods", "get, post, options"),
        new Entry("access-control-allow-methods", "options"),
        new Entry("access-control-expose-headers", "content-length"),
        new Entry("access-control-request-headers", "content-type"),
        new Entry("access-control-request-method", "get"),
        new Entry("access-control-request-method", "post"),
        new Entry("alt-svc", "clear"),
        new Entry("authorization", ""),
        new Entry("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        new Entry("early-data", "1"),
        new Entry("expect-ct", ""),
        new Entry("forwarded", ""),
        new Entry("if-range", ""),
        new Entry("origin", ""),
        new Entry("purpose", "prefetch"),
        new Entry("server", ""),
        new Entry("timing-allow-origin", "*"),
        new Entry("upgrade-insecure-requests", "1"),
        new Entry("user-agent", ""),
        new Entry("x-forwarded-for", ""),
        new Entry("x-frame-options", "deny"),
        new Entry("x-frame-options", "sameorigin")
    );

    public static Entry get(int index) {
        if (index >= 0 && index < TABLE.size()) {
            return TABLE.get(index);
        }
        return null;
    }
}
