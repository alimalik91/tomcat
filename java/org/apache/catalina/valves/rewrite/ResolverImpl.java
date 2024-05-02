/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.valves.rewrite;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;

import org.apache.catalina.WebResource;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.connector.Request;
import org.apache.tomcat.util.http.FastHttpDateFormat;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.jsse.PEMFile;
import org.apache.tomcat.util.net.openssl.ciphers.Cipher;
import org.apache.tomcat.util.net.openssl.ciphers.EncryptionLevel;
import org.apache.tomcat.util.net.openssl.ciphers.OpenSSLCipherConfigurationParser;

public class ResolverImpl extends Resolver {

    protected Request request = null;

    public ResolverImpl(Request request) {
        this.request = request;
    }

    /**
     * The following are not implemented:
     * - SERVER_ADMIN
     * - API_VERSION
     * - IS_SUBREQ
     */
    @Override
    public String resolve(String key) {
        if ("HTTP_USER_AGENT".equals(key)) {
            return request.getHeader("user-agent");
        } else if ("HTTP_REFERER".equals(key)) {
            return request.getHeader("referer");
        } else if ("HTTP_COOKIE".equals(key)) {
            return request.getHeader("cookie");
        } else if ("HTTP_FORWARDED".equals(key)) {
            return request.getHeader("forwarded");
        } else if ("HTTP_HOST".equals(key)) {
            // Don't look directly at the host header to handle:
            // - Host name in HTTP/1.1 request line
            // - HTTP/0.9 & HTTP/1.0 requests
            // - HTTP/2 :authority pseudo header
            return request.getServerName();
        } else if ("HTTP_PROXY_CONNECTION".equals(key)) {
            return request.getHeader("proxy-connection");
        } else if ("HTTP_ACCEPT".equals(key)) {
            return request.getHeader("accept");
        } else if ("REMOTE_ADDR".equals(key)) {
            return request.getRemoteAddr();
        } else if ("REMOTE_HOST".equals(key)) {
            return request.getRemoteHost();
        } else if ("REMOTE_PORT".equals(key)) {
            return String.valueOf(request.getRemotePort());
        } else if ("REMOTE_USER".equals(key)) {
            return request.getRemoteUser();
        } else if ("REMOTE_IDENT".equals(key)) {
            return request.getRemoteUser();
        } else if ("REQUEST_METHOD".equals(key)) {
            return request.getMethod();
        } else if ("SCRIPT_FILENAME".equals(key)) {
            return request.getServletContext().getRealPath(request.getServletPath());
        } else if ("REQUEST_PATH".equals(key)) {
            return request.getRequestPathMB().toString();
        } else if ("CONTEXT_PATH".equals(key)) {
            return request.getContextPath();
        } else if ("SERVLET_PATH".equals(key)) {
            return emptyStringIfNull(request.getServletPath());
        } else if ("PATH_INFO".equals(key)) {
            return emptyStringIfNull(request.getPathInfo());
        } else if ("QUERY_STRING".equals(key)) {
            return emptyStringIfNull(request.getQueryString());
        } else if ("AUTH_TYPE".equals(key)) {
            return request.getAuthType();
        } else if ("DOCUMENT_ROOT".equals(key)) {
            return request.getServletContext().getRealPath("/");
        } else if ("SERVER_NAME".equals(key)) {
            return request.getLocalName();
        } else if ("SERVER_ADDR".equals(key)) {
            return request.getLocalAddr();
        } else if ("SERVER_PORT".equals(key)) {
            return String.valueOf(request.getLocalPort());
        } else if ("SERVER_PROTOCOL".equals(key)) {
            return request.getProtocol();
        } else if ("SERVER_SOFTWARE".equals(key)) {
            return "tomcat";
        } else if ("THE_REQUEST".equals(key)) {
            return request.getMethod() + " " + request.getRequestURI()
            + " " + request.getProtocol();
        } else if ("REQUEST_URI".equals(key)) {
            return request.getRequestURI();
        } else if ("REQUEST_FILENAME".equals(key)) {
            return request.getPathTranslated();
        } else if ("HTTPS".equals(key)) {
            return request.isSecure() ? "on" : "off";
        } else if ("TIME_YEAR".equals(key)) {
            return String.valueOf(Calendar.getInstance().get(Calendar.YEAR));
        } else if ("TIME_MON".equals(key)) {
            return String.valueOf(Calendar.getInstance().get(Calendar.MONTH));
        } else if ("TIME_DAY".equals(key)) {
            return String.valueOf(Calendar.getInstance().get(Calendar.DAY_OF_MONTH));
        } else if ("TIME_HOUR".equals(key)) {
            return String.valueOf(Calendar.getInstance().get(Calendar.HOUR_OF_DAY));
        } else if ("TIME_MIN".equals(key)) {
            return String.valueOf(Calendar.getInstance().get(Calendar.MINUTE));
        } else if ("TIME_SEC".equals(key)) {
            return String.valueOf(Calendar.getInstance().get(Calendar.SECOND));
        } else if ("TIME_WDAY".equals(key)) {
            return String.valueOf(Calendar.getInstance().get(Calendar.DAY_OF_WEEK));
        } else if ("TIME".equals(key)) {
            return FastHttpDateFormat.getCurrentDate();
        }
        return null;
    }

    @Override
    public String resolveEnv(String key) {
        Object result = request.getAttribute(key);
        return (result != null) ? result.toString() : System.getProperty(key);
    }

    @Override
    public String resolveSsl(String key) {
        SSLSupport sslSupport = (SSLSupport) request.getAttribute(SSLSupport.SESSION_MGR);
        try {
            // SSL_SRP_USER: no planned support for SRP
            // SSL_SRP_USERINFO: no planned support for SRP
            if ("HTTPS".equals(key)) {
                return String.valueOf(sslSupport != null);
            } else if ("SSL_PROTOCOL".equals(key)) {
                return sslSupport.getProtocol();
            } else if ("SSL_SESSION_ID".equals(key)) {
                return sslSupport.getSessionId();
            } else if ("SSL_SESSION_RESUMED".equals(key)) {
                // FIXME session resumption state, not available anywhere
            } else if ("SSL_SECURE_RENEG".equals(key)) {
                // FIXME available from SSLHostConfig
            } else if ("SSL_COMPRESS_METHOD".equals(key)) {
                // FIXME available from SSLHostConfig
            } else if ("SSL_TLS_SNI".equals(key)) {
                // FIXME from handshake SNI processing
            } else if ("SSL_CIPHER".equals(key)) {
                return sslSupport.getCipherSuite();
            } else if ("SSL_CIPHER_EXPORT".equals(key)) {
                String cipherSuite = sslSupport.getCipherSuite();
                if (cipherSuite != null) {
                    Set<Cipher> cipherList = OpenSSLCipherConfigurationParser.parse(cipherSuite);
                    if (cipherList.size() == 1) {
                        Cipher cipher = cipherList.iterator().next();
                        if (cipher.getLevel().equals(EncryptionLevel.EXP40)
                                || cipher.getLevel().equals(EncryptionLevel.EXP56)) {
                            return "true";
                        } else {
                            return "false";
                        }
                    }
                }
            } else if ("SSL_CIPHER_ALGKEYSIZE".equals(key)) {
                String cipherSuite = sslSupport.getCipherSuite();
                if (cipherSuite != null) {
                    Set<Cipher> cipherList = OpenSSLCipherConfigurationParser.parse(cipherSuite);
                    if (cipherList.size() == 1) {
                        Cipher cipher = cipherList.iterator().next();
                        return String.valueOf(cipher.getAlg_bits());
                    }
                }
            } else if ("SSL_CIPHER_USEKEYSIZE".equals(key)) {
                Integer keySize = sslSupport.getKeySize();
                return (keySize == null) ? null : sslSupport.getKeySize().toString();
            } else if (key.startsWith("SSL_CLIENT_")) {
                X509Certificate[] certificates = sslSupport.getPeerCertificateChain();
                if (certificates != null && certificates.length > 0) {
                    key = key.substring("SSL_CLIENT_".length());
                    String result = resolveSslCertificates(key, certificates);
                    if (result != null) {
                        return result;
                    } else if (key.startsWith("SAN_OTHER_msUPN_")) {
                        // Type otherName, which is 0
                        key = key.substring("SAN_OTHER_msUPN_".length());
                        // FIXME OID from resolveAlternateName
                    } else if ("CERT_RFC4523_CEA".equals(key)) {
                        // FIXME return certificate[0] format CertificateExactAssertion in RFC4523
                    } else if ("VERIFY".equals(key)) {
                        // FIXME return verification state, not available anywhere
                    }
                }
            } else if (key.startsWith("SSL_SERVER_")) {
                X509Certificate[] certificates = sslSupport.getLocalCertificateChain();
                if (certificates != null && certificates.length > 0) {
                    key = key.substring("SSL_SERVER_".length());
                    String result = resolveSslCertificates(key, certificates);
                    if (result != null) {
                        return result;
                    } else if (key.startsWith("SAN_OTHER_dnsSRV_")) {
                        // Type otherName, which is 0
                        key = key.substring("SAN_OTHER_dnsSRV_".length());
                        // FIXME OID from resolveAlternateName
                    }
                }
            }
        } catch (IOException e) {
            // TLS access error
        }
        return null;
    }

    private String resolveSslCertificates(String key, X509Certificate[] certificates) {
        if ("M_VERSION".equals(key)) {
            return String.valueOf(certificates[0].getVersion());
        } else if ("M_SERIAL".equals(key)) {
            return certificates[0].getSerialNumber().toString();
        } else if ("S_DN".equals(key)) {
            return certificates[0].getSubjectX500Principal().toString();
        } else if (key.startsWith("S_DN_")) {
            key = key.substring("S_DN_".length());
            return resolveComponent(certificates[0].getSubjectX500Principal().getName(), key);
        } else if (key.startsWith("SAN_Email_")) {
            // Type rfc822Name, which is 1
            key = key.substring("SAN_Email_".length());
            return resolveAlternateName(certificates[0], 1, Integer.parseInt(key));
        } else if (key.startsWith("SAN_DNS_")) {
            // Type dNSName, which is 2
            key = key.substring("SAN_DNS_".length());
            return resolveAlternateName(certificates[0], 2, Integer.parseInt(key));
        } else if ("I_DN".equals(key)) {
            return certificates[0].getIssuerX500Principal().getName();
        } else if (key.startsWith("I_DN_")) {
            key = key.substring("I_DN_".length());
            return resolveComponent(certificates[0].getIssuerX500Principal().toString(), key);
        } else if ("V_START".equals(key)) {
            return String.valueOf(certificates[0].getNotBefore().getTime());
        } else if ("V_END".equals(key)) {
            return String.valueOf(certificates[0].getNotAfter().getTime());
        } else if ("V_REMAIN".equals(key)) {
            long remain = certificates[0].getNotAfter().getTime() - System.currentTimeMillis();
            if (remain < 0) {
                remain = 0L;
            }
            // Return remaining days
            return String.valueOf(TimeUnit.MILLISECONDS.toDays(remain));
        } else if ("A_SIG".equals(key)) {
            return certificates[0].getSigAlgName();
        } else if ("A_KEY".equals(key)) {
            return certificates[0].getPublicKey().getAlgorithm();
        } else if ("CERT".equals(key)) {
            try {
                return PEMFile.toPEM(certificates[0]);
            } catch (CertificateEncodingException e) {
                // Ignore
            }
        } else if (key.startsWith("CERT_CHAIN_")) {
            key = key.substring("CERT_CHAIN_".length());
            try {
                return PEMFile.toPEM(certificates[Integer.parseInt(key)]);
            } catch (NumberFormatException | ArrayIndexOutOfBoundsException
                    | CertificateEncodingException e) {
                // Ignore
            }
        }
        return null;
    }

    private String resolveComponent(String fullDN, String component) {
        HashMap<String, String> components = new HashMap<>();
        StringTokenizer tokenizer = new StringTokenizer(fullDN, ",");
        while (tokenizer.hasMoreElements()) {
            String token = tokenizer.nextToken().trim();
            int pos = token.indexOf('=');
            if (pos > 0 && (pos + 1) < token.length()) {
                components.put(token.substring(0, pos), token.substring(pos + 1));
            }
        }
        return components.get(component);
    }

    private String resolveAlternateName(X509Certificate certificate, int type, int n) {
        try {
            Collection<List<?>> alternateNames = certificate.getSubjectAlternativeNames();
            if (alternateNames != null) {
                List<String> elements = new ArrayList<>();
                for (List<?> alternateName : alternateNames) {
                    Integer alternateNameType = (Integer) alternateName.get(0);
                    if (alternateNameType.intValue() == type) {
                        elements.add(String.valueOf(alternateName.get(1)));
                    }
                }
                if (elements.size() > n) {
                    return elements.get(n);
                }
            }
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException
                | CertificateParsingException e) {
            // Ignore
        }
        return null;
    }

    @Override
    public String resolveHttp(String key) {
        String header = request.getHeader(key);
        if (header == null) {
            return "";
        } else {
            return header;
        }
    }

    @Override
    public boolean resolveResource(int type, String name) {
        WebResourceRoot resources = request.getContext().getResources();
        WebResource resource = resources.getResource(name);
        if (!resource.exists()) {
            return false;
        } else {
            switch (type) {
            case 0:
                return resource.isDirectory();
            case 1:
                return resource.isFile();
            case 2:
                return resource.isFile() && resource.getContentLength() > 0;
            default:
                return false;
            }
        }
    }

    private static String emptyStringIfNull(String value) {
        if (value == null) {
            return "";
        } else {
            return value;
        }
    }

    @Override
    public Charset getUriCharset() {
        return request.getConnector().getURICharset();
    }
}
