package validation

import java.math.BigInteger
import java.security._
import java.security.cert.X509Certificate
import java.util.{Calendar, Date}
import javax.security.auth.x500.X500Principal

import org.bouncycastle.asn1.x509.{Extension, BasicConstraints, KeyUsage}
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509ExtensionUtils, JcaX509v3CertificateBuilder}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder


// see
// http://www.bouncycastle.org/docs/pkixdocs1.5on/index.html
// http://www.bouncycastle.org/docs/docs1.5on/index.html
// https://github.com/joschi/cryptoworkshop-bouncycastle/blob/master/src/main/java/cwguide/JcaUtils.java
// http://www.cryptoworkshop.com/guide/cwguide-070313.pdf

/**
 * Created by Stefano on 15/03/15.
 */
object TestDataGenerator {


  // register the Bouncy Castle provider
  Security.addProvider(new BouncyCastleProvider)

  def generateRSAKeys() : KeyPair = {

    // create a key generator
    val generator = KeyPairGenerator.getInstance("RSA", "BC")

    // initialize it
    generator.initialize(2048, new SecureRandom())

    // generate the key pair
    generator.generateKeyPair()

  }

  def getCertificateBuilder(issuer : String,
                            expiration: Date,
                            subject: String,
                            publicKey: PublicKey ) : JcaX509v3CertificateBuilder = {

    // wrap issuer and subject in the right objects
    val x509Issuer = new X500Principal(issuer)
    val x509Subject = new X500Principal(subject)

    // create a serial
    val serial = BigInteger.valueOf(123)

    // get the current time and date
    val now = new Date()

    // create the certificate builder with
    // all the mandatory objects
    new JcaX509v3CertificateBuilder(x509Issuer, serial, now, expiration, x509Subject, publicKey)

  }

  def buildCertificate(subjectPublicKey: PublicKey,
                       subjectName: String,
                       signingPrivateKey: PrivateKey,
                       signingCertificate: X509Certificate,
                       expiration: Date,
                       basicConstraints: BasicConstraints,
                       keyUsage: KeyUsage ) = {

    // create the content signer
    val contentSignerBuilder =  new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC")
    val contentSigner = contentSignerBuilder.build(signingPrivateKey)

    // the signer name in x500 format
    val signerX500Name =  signingCertificate.getSubjectX500Principal.getName

    // the certificate builder
    val certBuilder = getCertificateBuilder(signerX500Name, expiration, subjectName, subjectPublicKey)

    // set the extensions for the certificates that will be built
    val extensionUtil = new JcaX509ExtensionUtils()
    val authId = extensionUtil.createAuthorityKeyIdentifier(signingCertificate)
    val keyId = extensionUtil.createSubjectKeyIdentifier(subjectPublicKey)
    certBuilder.addExtension(Extension.authorityKeyIdentifier, false, authId)
    certBuilder.addExtension(Extension.subjectKeyIdentifier, false, keyId)
    certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints)
    certBuilder.addExtension(Extension.keyUsage, true, keyUsage)

    // build the certificate
    certBuilder.build(contentSigner)

  }


  def oneDayAfter(now: Date) = {

    val cal = Calendar.getInstance()
    cal.setTime(now)
    cal.add(Calendar.DATE, 1)
    cal.getTime

  }

  def convertX509(holder : X509CertificateHolder) = {
    val converter = new JcaX509CertificateConverter().setProvider("BC")
    converter.getCertificate(holder)
  }


  def buildRootCertificate(keyPair: KeyPair, expiration: Date, signerX500Name: String) = {

    // create the content signer
    val contentSignerBuilder =  new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC")
    val contentSigner = contentSignerBuilder.build(keyPair.getPrivate)

    // the certificate builder
    val certBuilder = getCertificateBuilder(signerX500Name, expiration, signerX500Name, keyPair.getPublic)

    val keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign)

    // set the extensions for the certificates that will be built
    certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1))
    certBuilder.addExtension(Extension.keyUsage, true, keyUsage)

    // create the certificate
    val cert = certBuilder.build(contentSigner)

    // return the certificate in x509 format
    convertX509(cert)

  }

  def buildIntermediateCertificate(subjecPublicKey: PublicKey,
                                   subjectName: String,
                                   signingPrivateKey: PrivateKey,
                                   caCertificate: X509Certificate,
                                   expiration: Date ) : X509Certificate = {

    val basicConstraints = new BasicConstraints(0)
    val keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign)

    val intermediate = buildCertificate(subjecPublicKey, subjectName, signingPrivateKey, caCertificate, expiration, basicConstraints, keyUsage)

    convertX509(intermediate)

  }

  def buildEndCertificate(subjecPublicKey: PublicKey,
                          subjectName: String,
                          signingPrivateKey: PrivateKey,
                          caCertificate: X509Certificate,
                          expiration: Date ) : X509Certificate = {

    val basicConstraints = new BasicConstraints(false)
    val keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)

    val intermediate = buildCertificate(subjecPublicKey, subjectName, signingPrivateKey, caCertificate, expiration, basicConstraints, keyUsage)

    convertX509(intermediate)

  }


  /**
   * 1) generate the key pair for the CA entit
   * 2) build the root CA certificate
   * 3) generate the key pair for intermediate entity
   * 4) build the intermediate certificate
   * 5) generate the key pair for end entity
   * 6) build the end certificate
   * 7) return the three certificate
   */
  def generateTestCertificate(rootSubjectName: String,
                              intermediateSubjectName: String,
                              endSubjectName: String ) = {

    val now = new Date
    val tomorrow = oneDayAfter(now)
    val caKeyPair = generateRSAKeys()
    val intermediateKeyPair = generateRSAKeys()
    val endKeyPair = generateRSAKeys()

    val rootCertificate = buildRootCertificate(caKeyPair,tomorrow,rootSubjectName)
    val intermediateCertificate = buildIntermediateCertificate(intermediateKeyPair.getPublic, intermediateSubjectName, caKeyPair.getPrivate, rootCertificate, tomorrow)
    val endCertificate = buildEndCertificate(endKeyPair.getPublic, endSubjectName, intermediateKeyPair.getPrivate, intermediateCertificate, tomorrow)

    (rootCertificate, intermediateCertificate, endCertificate, caKeyPair.getPrivate)

  }

}
