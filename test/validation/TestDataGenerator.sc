import java.math.BigInteger
import java.security._
import java.security.cert._
import java.util
import java.util.{Calendar, Date}
import javax.security.auth.x500.X500Principal
import core.Common._
import org.bouncycastle.asn1.x509.{Extension, KeyUsage, BasicConstraints}
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.{JcaCertStore, JcaX509CertificateConverter, JcaX509ExtensionUtils, JcaX509v3CertificateBuilder}
import org.bouncycastle.cms._
import org.bouncycastle.cms.jcajce.{JcaSimpleSignerInfoVerifierBuilder, JcaSimpleSignerInfoGeneratorBuilder, JcaSignerInfoGeneratorBuilder}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.{JcaDigestCalculatorProviderBuilder, JcaContentSignerBuilder}
object TestDataGeneratorPlay {
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
  def createCertStore(root: X509Certificate, intermediate: X509Certificate, end: X509Certificate) = {

    val certList = List(root, intermediate, end)

    import collection.JavaConversions._
    new JcaCertStore(certList)
  }
  def createContentSigner(privateKey: PrivateKey) = {

    val contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC")
    contentSigner.build(privateKey)
  }
  def createSignerInfoGenerator(contentSigner : ContentSigner, certificate: X509Certificate) = {

    val digestCalculator = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()

    val generatorBuilder = new JcaSignerInfoGeneratorBuilder(digestCalculator)

    generatorBuilder.build(contentSigner, certificate)
  }
  def createCMSGenerator(root: X509Certificate, intermediate: X509Certificate, end: X509Certificate, privateKey: PrivateKey) : CMSSignedDataGenerator = {
    val certStore = createCertStore(root, intermediate, end)
    val contentSigner = createContentSigner(privateKey)
    val signerInfoGenerator = createSignerInfoGenerator(contentSigner, end)

    val generator = new CMSSignedDataGenerator

    generator.addSignerInfoGenerator(signerInfoGenerator)
    generator.addCertificates(certStore)

    generator
  }
  def createProcessableData(message: String) = {
    val bytes = message.getBytes
    new CMSProcessableByteArray(bytes)
  }
  def createSignedData(message : String, root: X509Certificate, intermediate: X509Certificate, end: X509Certificate, privateKey: PrivateKey ) = {
    val data = createProcessableData(message)
    val cmsGenerator = createCMSGenerator(root,intermediate, end, privateKey)
    cmsGenerator.generate(data, true)
  }
  val a = generateRSAKeys()
  val b = getCertificateBuilder("CN=Stefano", new Date, "CN=Stefano", a.getPublic)
  def using[A <: { def close(): Unit }, B](resource: A)(f: A => B): B =
    try {
      f(resource) }
    finally {
      resource.close()
  }
  def appleCACertificate() : java.security.cert.Certificate = {
    val b = this.getClass.getResource("/AppleIncRootCertificate.crt")
    using(b.openStream()) {
      CertificateFactory.getInstance("X.509", "BC").generateCertificate(_)
      }
    }

  /**
   * Returns the pkix parameters based on the input certificate as trust anchor,
   * correctly configured.
   * @param certificate the certificate to use as trust anchor
   */
  def createPKIXParams(certificate: X509Certificate) = {

    // create the trust anchor
    val trustAnchor = new TrustAnchor(certificate, null)

    // create a set to contain the trust anchor
    val jSet : java.util.HashSet[TrustAnchor] = new java.util.HashSet[TrustAnchor]()
    jSet.add(trustAnchor)

    // create the pkix parameters
    val pkix = new PKIXParameters(jSet)

    // configure
    pkix.setDate(new java.util.Date)
    pkix.setRevocationEnabled(false)

    pkix

  }

  def convertX509(holder: Any) = {
    val converter = new JcaX509CertificateConverter().setProvider("BC")
    converter.getCertificate(holder.asInstanceOf)
  }

  def getCertificateFrom(signedData: CMSSignedData) : Iterable[java.security.cert.X509Certificate] = {
    import scala.collection.JavaConversions._
    signedData.getCertificates.getMatches(null).map(convertX509)

  }



  def getSignerCertificateFrom(signedData: CMSSignedData) : X509Certificate  = {

    // get signer (there is only one, so go fetch the first)
    val signerInfo : SignerInformation = signedData.getSignerInfos.getSigners.iterator.next.asInstanceOf

    // get the certificate of the signer
    val certHolder : X509CertificateHolder = signedData.getCertificates.getMatches(signerInfo.getSID).iterator.next.asInstanceOf

    // convert the certificate to x509 format
    convertX509(certHolder)
  }


  def validateCertPath(signedData: CMSSignedData, trustAnchorCert: X509Certificate) : CertPathValidatorResult = {

    // get the list of the certificates in x509 format
    val certList = getCertificateFrom(signedData)

    // creates the certificate path from the certificate list
    val certPath = ???

    // creates a pkix parameters to drive the validation
    val pkix = createPKIXParams(trustAnchorCert)

    // create the validator
    val validator = CertPathValidator.getInstance("PKIX", "BC")

    // validate
    validator.validate(certPath, pkix)

  }

  def getSignerInfoFrom(signedData: CMSSignedData) : SignerInformation = signedData.getSignerInfos.getSigners.iterator.next.asInstanceOf


  def isValidSignature(signedData: CMSSignedData, trustAnchorCert: X509Certificate) : Boolean = {

    val signerInfo = getSignerInfoFrom(signedData)

    val signerCert = getSignerCertificateFrom(signedData)

    val verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert)

    val certPathValid = validateCertPath(signedData, trustAnchorCert)

    certPathValid && signerInfo.verify(verifier)

  }


  val c = getClass.getResource("/AppleIncRootCertificate.crt")

}