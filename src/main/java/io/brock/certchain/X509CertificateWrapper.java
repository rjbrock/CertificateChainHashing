package io.brock.certchain;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class X509CertificateWrapper {
    private static final X500NameStyle sNameStyle = BCStyle.INSTANCE;
    private final X500Name mIssuer;
    private final X500Name mSubject;
    private final byte[] mSubjectPublicKeyInfo;
    private final byte[] mPublicKey;

    public X509CertificateWrapper(X509Certificate certificate) throws CertificateEncodingException, IOException {
        JcaX509CertificateHolder jcaX509CertificateHolder = new JcaX509CertificateHolder(certificate);
        mIssuer = jcaX509CertificateHolder.getIssuer();
        mSubject = jcaX509CertificateHolder.getSubject();
        mSubjectPublicKeyInfo = jcaX509CertificateHolder.getSubjectPublicKeyInfo().getEncoded();
        mPublicKey = jcaX509CertificateHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    }

    public X500Name getIssuer() {
        return mIssuer;
    }

    public X500Name getSubject() {
        return mSubject;
    }

    public boolean isIssuerOf(X509CertificateWrapper certificateChainEntry) {
        return sNameStyle.areEqual(mSubject, certificateChainEntry.getIssuer());
    }

    public String getBase64Sha256OfPublicKey() {
        byte[] hash = generateHash(new SHA256Digest(), mPublicKey);
        return createBase64String(hash);
    }

    public String getBase64Sha256OfSpki() {
        byte[] hash = generateHash(new SHA256Digest(), mSubjectPublicKeyInfo);
        return createBase64String(hash);
    }

    public String getHexSha1OfPublicKey() {
        byte[] hash = generateHash(new SHA1Digest(), mPublicKey);
        return createHexString(hash);
    }

    public String getHexSha1OfSpkiHash() {
        byte[] hash = generateHash(new SHA1Digest(), mSubjectPublicKeyInfo);
        return createHexString(hash);
    }

    @Override
    public String toString() {
        return "\nX509CertificateWrapper{" +
                "issuer=" + mIssuer +
                ", subject=" + mSubject + "\n" +
                "\t Hashes:\n" +
                "\t B64 SHA256 SPKI: " + getBase64Sha256OfSpki() + "\n" +
                "\t Hex SHA1 SPKI: " + getHexSha1OfSpkiHash() + "\n" +
                "\t B64 SHA256 Public Key: " + getBase64Sha256OfPublicKey() + "\n" +
                "\t Hex SHA1 Public Key: " + getHexSha1OfPublicKey() + "\n" +
                '}';
    }

    private String createHexString(byte[] source) {
        return Hex.toHexString(source);
    }

    private String createBase64String(byte[] source) {
        return new String(Base64.getEncoder().encode(source), StandardCharsets.UTF_8);
    }

    private byte[] generateHash(GeneralDigest digest, byte[] content) {
        digest.update(content, 0, content.length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);

        return bytes;
    }

}
