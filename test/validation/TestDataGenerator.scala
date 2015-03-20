package validation

import java.math.BigInteger
import java.security._
import java.security.cert.X509Certificate
import java.util.{Calendar, Date}
import javax.security.auth.x500.X500Principal

import org.bouncycastle.asn1.x509.{Extension, BasicConstraints, KeyUsage}
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.{JcaCertStore, JcaX509CertificateConverter, JcaX509ExtensionUtils, JcaX509v3CertificateBuilder}
import org.bouncycastle.cms.{SignerInfoGenerator, CMSSignedData, CMSProcessableByteArray, CMSSignedDataGenerator}
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.{JcaDigestCalculatorProviderBuilder, JcaContentSignerBuilder}


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
   *
   *  Generate test certificates
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

    // return the tuple with certificates and the CA private key
    (rootCertificate, intermediateCertificate, endCertificate, caKeyPair.getPrivate)

  }

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
      import collection.JavaConversions._
      new JcaCertStore(certList)

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
