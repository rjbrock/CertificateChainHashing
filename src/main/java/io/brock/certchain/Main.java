package io.brock.certchain;

import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class Main {
    private static final X500NameStyle mX500NameStyle = BCStyle.INSTANCE;
    private static final Logger sLogger = LoggerFactory.getLogger(Main.class);
    private static final List<X509CertificateWrapper> sTrustedRoots = new ArrayList<X509CertificateWrapper>();

    public static void main(String args[]) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, SystemTrustManager.TrustManagerException {
        if (args.length != 1) {
            sLogger.error("Please provide a url, usage: ./gradlew run -Purl=\"mysecuresite.com\"");
            return;
        }

        String host = "https://" + args[0];
        sLogger.info("Checking host " + host);

        SystemTrustManager systemTrustManager = new SystemTrustManager();
        SslCertificateDownloader sslCertificateDownloader = new SslCertificateDownloader(systemTrustManager.getNoCheckTrustManager());

        SslCertificateDownloader.ConnectionResult result = sslCertificateDownloader.getVerifiedCertificateChain(host);
        sLogger.info("Was verified: " + result.wasVerified());
        printCertChain(result.getCertificateChain());

        result = sslCertificateDownloader.getUnverifiedPeerCertificates(host);
        sLogger.info("Got raw cert chain");
        printCertChain(result.getCertificateChain());
    }

    private static void printCertChain(List<X509CertificateWrapper> certChain) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Cert chain size: " + certChain.size() + "\n");
        for (X509CertificateWrapper x509CertificateWrapper : certChain) {
            stringBuilder.append("\t" + x509CertificateWrapper);
        }

        sLogger.info(stringBuilder.toString());
    }
}