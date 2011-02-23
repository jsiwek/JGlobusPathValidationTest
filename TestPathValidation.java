import org.globus.common.CoGProperties;
import org.globus.gsi.*;
import org.globus.gsi.stores.*;
import org.globus.gsi.provider.*;
import org.globus.gsi.trustmanager.*;
import org.globus.gsi.util.*;
import java.security.*;
import java.security.cert.*;
import java.io.*;

public class TestPathValidation {
    public static void main(String[] args) {
        String sha1 = "sha1";
        String sha2 = "sha2";
        String caCertFile = sha2 + "/01ac4149.0";
        String hostCertFile = sha2 + "/hostcert.pem";

        try {
        InputStream inStream = new FileInputStream(caCertFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert =
            (X509Certificate)cf.generateCertificate(inStream);
        inStream.close();
        inStream = new FileInputStream(hostCertFile);
        X509Certificate hostCert =
            (X509Certificate)cf.generateCertificate(inStream);
        inStream.close();

/*
        System.out.println("validate cert: " + caCert.getSubjectDN());
        System.out.println("issued by: " + caCert.getSubjectDN());
        caCert.verify(caCert.getPublicKey());

        System.out.println("validate cert: " + hostCert.getSubjectDN());
        System.out.println("issued by: " + caCert.getSubjectDN());
        hostCert.verify(caCert.getPublicKey());
*/

        Security.addProvider(new GlobusProvider());

        String caCertsLocation =
                "file:" + CoGProperties.getDefault().getCaCertLocations();
        String crlPattern = caCertsLocation + "/*.r*";
        String sigPolPattern = caCertsLocation + "/*.signing_policy";

        KeyStore keyStore = KeyStore.getInstance(
                GlobusProvider.KEYSTORE_TYPE, GlobusProvider.PROVIDER_NAME);
        CertStore crlStore = CertStore.getInstance(
                GlobusProvider.CERTSTORE_TYPE,
                new ResourceCertStoreParameters(null, crlPattern));
        ResourceSigningPolicyStore sigPolStore =
                new ResourceSigningPolicyStore(
                        new ResourceSigningPolicyStoreParameters(
                                sigPolPattern));
        keyStore.load(
                KeyStoreParametersFactory.createTrustStoreParameters(
                        caCertsLocation));
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(keyStore, crlStore,
                        sigPolStore, false);
        X509ProxyCertPathValidator validator =
                new X509ProxyCertPathValidator();

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = hostCert;

        validator.engineValidate(CertificateUtil.getCertPath(chain),parameters);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
