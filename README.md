# CertificateChainHashing
Examples of fetching the cert chain from a remote URL and hashing the PK &amp; SPKI

## Fetch certificates (trusted & untrusted) from a remote url
You can use this script to check to make sure your certificates are correct. It will try to fetch a trusted certificate chain as well as just fetch any certificates that a server includes in the handshake.

## Usage
`./gradlew run -Purl="brock.io"`
(Leave out the https, it will be added in automatically)
