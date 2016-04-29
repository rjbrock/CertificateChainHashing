package io.brock.certchain;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Find an instance of the system trust manager, and get a list of all trusted roots
 */
public class SystemTrustManager {
    private static final Logger sLogger = LoggerFactory.getLogger(SystemTrustManager.class);
    private final X509TrustManager mX509TrustManager;

    public SystemTrustManager() throws TrustManagerException {
        try {
            mX509TrustManager = getTrustManager();
        } catch(NoSuchAlgorithmException | KeyStoreException | TrustManagerException e) {
            throw new TrustManagerException(e);
        }
    }

    public List<X509CertificateWrapper> getRootCertificates() {
        X509Certificate[] certificates = mX509TrustManager.getAcceptedIssuers();
        List<X509CertificateWrapper> roots = new ArrayList<>(certificates.length);

        for (X509Certificate certificate : certificates) {
            try {
                X509CertificateWrapper wrapper = new X509CertificateWrapper(certificate);
                roots.add(wrapper);
            } catch (CertificateEncodingException | IOException e) {
                sLogger.error("Unable to encode root cert, ", e);
            }
        }

        return Collections.unmodifiableList(roots);
    }

    public X509TrustManager getNoCheckTrustManager() {
        return new NoCheckTrustManger();
    }

    private X509TrustManager getTrustManager() throws NoSuchAlgorithmException, KeyStoreException, TrustManagerException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        trustManagerFactory.init((KeyStore) null);

        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
            throw new TrustManagerException("Unable to find trust manager");
        }

        return (X509TrustManager) trustManagers[0];
    }

    public X509TrustManager getX509TrustManager() {
        return mX509TrustManager;
    }

    public static class TrustManagerException extends Exception {
        public TrustManagerException(Throwable tr) {
            super(tr);
        }

        public TrustManagerException(String msg) {
            super(msg);
        }
    }

    static class NoCheckTrustManger implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
