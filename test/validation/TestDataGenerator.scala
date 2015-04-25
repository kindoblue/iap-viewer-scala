package validation

import java.math.BigInteger
import java.security._
import java.security.cert.X509Certificate
import java.util.{Calendar, Date}
import javax.security.auth.x500.X500Principal

import core.Common.convertX509

import org.bouncycastle.asn1.x509.{Extension, BasicConstraints, KeyUsage}
import org.bouncycastle.cert.jcajce.{JcaCertStore, JcaX509ExtensionUtils, JcaX509v3CertificateBuilder}
import org.bouncycastle.cms.{SignerInfoGenerator, CMSSignedData, CMSProcessableByteArray, CMSSignedDataGenerator}
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.{JcaDigestCalculatorProviderBuilder, JcaContentSignerBuilder}

import scala.collection.JavaConverters._

// see
// http://www.bouncycastle.org/docs/pkixdocs1.5on/index.html
// http://www.bouncycastle.org/docs/docs1.5on/index.html
// https://github.com/joschi/cryptoworkshop-bouncycastle/blob/master/src/main/java/cwguide/JcaUtils.java
// http://www.cryptoworkshop.com/guide/cwguide-070313.pdf

/**
 * Here are gathered methods to generate test data (keys, certificates, signed data) to be used in tests
 * for the validator functionality
 *
 * Created by Stefano on 15/03/15.
 */
object TestDataGenerator {


  // register the Bouncy Castle provider
  Security.addProvider(new BouncyCastleProvider)

  /**
   * Generate a pair of RSA keys
   * @return the key pair
   */
  def generateRSAKeys() : KeyPair = {

    // create a key generator
    val generator = KeyPairGenerator.getInstance("RSA", "BC")

    // initialize it
    generator.initialize(2048, new SecureRandom())

    // generate the key pair
    generator.generateKeyPair()

  }

  /**
   * Create a certificate builder, able to generate certificates.
   *
   * @param issuer the issuer of the certificates that will built
   * @param expiration the expiration of the certificates
   * @param subject the subject of the certificate
   * @param publicKey the public key of the subject that will be certified
   * @return
   */
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

  /**
   * Build a certificate.
   *
   * @param subjectPublicKey the subject public key
   * @param subjectName the subject nam
   * @param signingPrivateKey the private key of the signer
   * @param signingCertificate the certificate of the signer
   * @param expiration the expiration of the certificate
   * @param basicConstraints the basic constraints for the certificate
   * @param keyUsage key usage allowed for the generated certificate
   * @return
   */
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


  /**
   * Generate a date object representing the day after of the input date
   *
   * @param the input date
   * @return the date of one day after the input
   */
  def oneDayAfter(now: Date) = {

    val cal = Calendar.getInstance()
    cal.setTime(now)
    cal.add(Calendar.DATE, 1)
    cal.getTime

  }

  /**
   * Build a CA certificate
   *
   * @param keyPair the key pair of the issuer/subject
   * @param expiration the expiration date
   * @param signerX500Name the issuer/subject name
   * @return the CA certificate
   */
  def buildRootCertificate(keyPair: KeyPair, expiration: Date, signerX500Name: String) : X509Certificate = {

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

  /**
   * Build an intermediate certificate (the one signed by a CA certificates)
   *
   * @param subjecPublicKey the subject public key to be certified
   * @param subjectName the subject name to be certified
   * @param signingPrivateKey the signing private key (the issuer private key)
   * @param caCertificate the CA certificate (the issuer certificate)
   * @param expiration the expiration date of the certificate
   * @return the intermediate certificate
   */
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

  /**
   * Build a generic (end certificate)
   *
   * @param subjecPublicKey the subject public key to be certified
   * @param subjectName the subject name to be certified
   * @param signingPrivateKey the signing private key (the issuer private key)
   * @param issuerCertificate the issuer certificate (the issuer certificate)
   * @param expiration the expiration date of the certificate
   * @return the end certificate
   */
  def buildEndCertificate(subjecPublicKey: PublicKey,
                          subjectName: String,
                          signingPrivateKey: PrivateKey,
                          issuerCertificate: X509Certificate,
                          expiration: Date ) : X509Certificate = {

    val basicConstraints = new BasicConstraints(false)
    val keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)

    val end = buildCertificate(subjecPublicKey, subjectName, signingPrivateKey, issuerCertificate, expiration, basicConstraints, keyUsage)

    convertX509(end)

  }


  /**
   * Generate a chain of certificates: CA -> Intermediate -> End
   *
   * @param rootSubjectName  the subject name for the CA certificate
   * @param intermediateSubjectName the subject name for the Intermediate certificate
   * @param endSubjectName the subject name for the End certificate
   * @return a tuple with the three certificates and the private key of the subject of the end certificate
   */
  def generateTestCertificates(rootSubjectName: String,
                              intermediateSubjectName: String,
                              endSubjectName: String ) = {

    val now = new Date
    val tomorrow = oneDayAfter(now)

    // generate key pairs for CA, intermediate and end certificates
    val caKeyPair = generateRSAKeys
    val intermediateKeyPair = generateRSAKeys
    val endKeyPair = generateRSAKeys

    // generate the CA, intermediate and end certificates
    val rootCertificate = buildRootCertificate(caKeyPair,tomorrow,rootSubjectName)
    val intermediateCertificate = buildIntermediateCertificate(intermediateKeyPair.getPublic, intermediateSubjectName, caKeyPair.getPrivate, rootCertificate, tomorrow)
    val endCertificate = buildEndCertificate(endKeyPair.getPublic, endSubjectName, intermediateKeyPair.getPrivate, intermediateCertificate, tomorrow)

    // return the tuple with certificates and the end private key (it is the end certificate that will be used to
    // sign stuff, so the private key will be needed to the caller)
    (rootCertificate, intermediateCertificate, endCertificate, endKeyPair.getPrivate)

  }

  /**
   * Generate a CA certificate (simplified version)
   * @param subjectName the subject/issuer name of the CA certificate
   * @return the CA certificate
   */
  def generateSingleCertificate(subjectName: String) = {

    val now = new Date
    val tomorrow = oneDayAfter(now)

    val caKeyPair = generateRSAKeys

    buildRootCertificate(caKeyPair, tomorrow, subjectName)

  }


  /**
   * Create the CMS signed data, that will be used to test validation. The message will be
   * encapsulated in the signature
   *
   * @param message the message to sign
   * @param root  the root certificate
   * @param intermediate the intermediate certificate
   * @param end the end certificate that will be used to sign the message
   * @param privateKey the private key used to create the end certificate (you need it to sign stuff)
   * @return the signed data
   */
  def createSignedData(message : String,
                       root: X509Certificate,
                       intermediate: X509Certificate,
                       end: X509Certificate,
                       privateKey: PrivateKey ) : CMSSignedData = {


    /**
     * Create a byte array that can be signed
     *
     * implicit param the message to sign
     * @return CMSProcessableByteArray
     */
    def createProcessableData : CMSProcessableByteArray = {

      // get the array of bytes from the message
      val bytes = message.getBytes

      // create and return the processable array
      new CMSProcessableByteArray(bytes)
    }

    /**
     * Create a certification store
     *
     * implicit params: root, intermediate, end certificates
     * @return JcaCertStore
     */
    def createCertStore : JcaCertStore = {

      // create the list of certificates
      val certList = List(root, intermediate, end)

      // create and return the certification store
      new JcaCertStore(certList.asJava)

    }

    /**
     * Create the signer info generator
     * @param contentSigner the signer, basically an object wrapping the private key
     * @param certificate the certificate
     * @return signer info generator
     */
    def createSignerInfoGenerator(contentSigner : ContentSigner, certificate: X509Certificate) : SignerInfoGenerator = {

      // we need a digest calculator
      val digestCalculator = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()

      // we create a builder based on the digest calculator
      val generatorBuilder = new JcaSignerInfoGeneratorBuilder(digestCalculator)

      // build and return the signer info generator
      generatorBuilder.build(contentSigner, certificate)
    }


    /**
     * Create the CMS generator
     *
     * @return CMS signed data generator
     */
    def createCMSGenerator : CMSSignedDataGenerator = {

      // create the certificate store (implicit input: root, intermediate, end certificates)
      val certStore = createCertStore

      // create the content signer
      val contentSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC")
      val contentSigner = contentSignerBuilder.build(privateKey)

      // create the signer info generator
      val signerInfoGenerator = createSignerInfoGenerator(contentSigner, end)

      // create the CMS signed data generator
      val generator = new CMSSignedDataGenerator

      // setup the generator with the signer info generator and certificate store
      generator.addSignerInfoGenerator(signerInfoGenerator)
      generator.addCertificates(certStore)

      // return the CMS signed data generator
      generator

    }


    // create the processable data from the input message
    val data = createProcessableData

    // create the CMS signed data generator
    val cmsGenerator = createCMSGenerator

    // generate the CMS signed data
    // the flag true means: content should be encapsulated in the signature
    cmsGenerator.generate(data, true)

  }

}
