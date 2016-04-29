package io.brock.certchain;

import jdk.nashorn.internal.ir.annotations.Immutable;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class SslCertificateDownloader {
    private static final Logger sLogger = LoggerFactory.getLogger(SslCertificateDownloader.class);
    private static final int HTTPS_PORT = 443;

    private final OkHttpClient mOkHttpClient;
    private final SSLSocketFactory mSSLSocketFactory;
    public SslCertificateDownloader(X509TrustManager noCheckTrustManger) throws NoSuchAlgorithmException, KeyManagementException {
        mOkHttpClient = new OkHttpClient();

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] { noCheckTrustManger }, null);
        mSSLSocketFactory = sslContext.getSocketFactory();
    }

    public ConnectionResult getVerifiedCertificateChain(String url) {
        Request request = new Request.Builder().url(url).get().build();

        Response response = null;
        try {
            response = mOkHttpClient.newCall(request).execute();
        } catch (IOException e) {
            return new ConnectionResult(false, "Unable to connect via verified connection");
        }

        if (response.handshake() == null) {
            return new ConnectionResult(false, "Handshake failed");
        }

        List<Certificate> certificates = response.handshake().peerCertificates();

        return new ConnectionResult(true, "Connected", transformCertificates(certificates));
    }

    public ConnectionResult getUnverifiedPeerCertificates(String host) {
        HttpsURLConnection httpsURLConnection;
        try {
            URL url = new URL(host);
            httpsURLConnection = (HttpsURLConnection) url.openConnection();
            httpsURLConnection.setHostnameVerifier(new TrustingHostnameVerifier());
            httpsURLConnection.setSSLSocketFactory(mSSLSocketFactory);
        } catch (IOException e) {
            return new ConnectionResult(true, "Unable to connect to remote host " + host);
        }

        try {
            httpsURLConnection.connect();
            Certificate[] certificates = httpsURLConnection.getServerCertificates();
            return new ConnectionResult(false, "Unverified cert chain", transformCertificates(Arrays.asList(certificates)));
        } catch (IOException e) {
            return new ConnectionResult(true, "Unable to start handshake on socket");
        }
    }

    private List<X509CertificateWrapper> transformCertificates(List<Certificate> peerCerts) {
        List<X509CertificateWrapper> certs = new ArrayList<>();
        for (Certificate certificate : peerCerts) {
            if (!(certificate instanceof X509Certificate)) {
                sLogger.error("Certificate in the chain was not an instance of X509Certificate");
                continue;
            }

            try {
                X509CertificateWrapper x509CertificateWrapper = new X509CertificateWrapper((X509Certificate) certificate);
                certs.add(x509CertificateWrapper);
            } catch (CertificateEncodingException | IOException e) {
                sLogger.error("Unable to create X509CertificateWrapper for cert", e);
            }
        }

        return certs;
    }

    public static class TrustingHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }
    }

    @Immutable
    public static class ConnectionResult {
        private final boolean mWasVerified;
        private String mMsg;
        private List<X509CertificateWrapper> mCertificateChain;

        public ConnectionResult(boolean wasVerified, String msg) {
            this(wasVerified, msg, Collections.emptyList());
        }
        public ConnectionResult(boolean wasVerified, String msg, List<X509CertificateWrapper> certificateChain) {
            mWasVerified = wasVerified;
            mMsg = msg;
            mCertificateChain = Collections.unmodifiableList(certificateChain);
        }

        public boolean wasVerified() {
            return mWasVerified;
        }

        public List<X509CertificateWrapper> getCertificateChain() {
            return mCertificateChain;
        }

        public String getMsg() {
            return mMsg;
        }
    }
}
