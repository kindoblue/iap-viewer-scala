package core

import java.security.cert._

import Common.{using, convertX509}

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.cms.{SignerInformation, CMSSignedData}

import scala.util.Try

import scala.collection.JavaConverters._

/**
 * Created by Stefano on 14/02/15.
 *
 * The Validator object provides functionality to validate the Apple receipts, by
 * checking the signature of the CMS envelop while using the Apple CA certificate
 * as trust anchor.
 */
object Validator {



  /**
   * Returns the pkix parameters based on the input certificate as trust anchor,
   * correctly configured.
   * @param certificate the certificate to use as trust anchor
   */
  private def createPKIXParams(certificate: X509Certificate) : PKIXParameters = {

    // create the trust anchor
    val trustAnchor = new TrustAnchor(certificate, null)

    // create a set to contain the trust anchor
    val jSet : java.util.HashSet[TrustAnchor] = new java.util.HashSet[TrustAnchor]()
    jSet.add(trustAnchor)

    // create the pkix parameters
    val pkix = new PKIXParameters(jSet)

    // configure for simple usage
    pkix.setDate(new java.util.Date)
    pkix.setRevocationEnabled(false)

    // and return
    pkix

  }


  /**
   * This function extract the certificates from the signed
   * data, and return them as a list of X509CertificateHolder
   * objects
   *
   * @param signedData the envelope containing the also the certificates
   */
  private def getCertificateFrom(signedData: CMSSignedData) : Iterable[java.security.cert.X509Certificate] = {

    signedData.getCertificates.getMatches(null).asScala.map(convertX509)

  }

  /**
   * Get the signer info object from the envelope
   * @param signedData signed data (envelope)
   * @return SignerInformation
   */
  private def getSignerInfoFrom(signedData: CMSSignedData) : SignerInformation =
    signedData.getSignerInfos.getSigners.iterator.next.asInstanceOf[SignerInformation]

  /**
   * Return the certificate of the signer, embedded in the envelope
   * @param signedData the signed data
   * @return the certificate of the signer, in x509 format
   */
  private def getSignerCertificateFrom(signedData: CMSSignedData) : X509Certificate  = {

    // get signer (there is only one, so go fetch the first)
    val signerInfo  = getSignerInfoFrom(signedData)

    // get the certificate of the signer
    val certHolder : X509CertificateHolder = signedData.getCertificates.getMatches(signerInfo.getSID).iterator.next.asInstanceOf[X509CertificateHolder]

    // convert the certificate to x509 format
    convertX509(certHolder)
  }


  /**
   * Validate the certification path, using the input certificate as trust anchor
   * @param signedData  the signed data
   * @param trustAnchorCert the certificate to use as trust anchor
   * @return the result of the validation
   */
  private def validateCertPath(signedData: CMSSignedData, trustAnchorCert: X509Certificate) : CertPathValidatorResult = {

    // get the list of the certificates in x509 format
    val certList = getCertificateFrom(signedData).toList.asJava

    // creates the certificate path from the certificate list
    val certPath = CertificateFactory.getInstance("x.509", "BC").generateCertPath(certList)

    // creates a pkix parameters to drive the validation
    val pkix = createPKIXParams(trustAnchorCert)

    // create the validator
    val validator = CertPathValidator.getInstance("PKIX", "BC")

    // validate
    validator.validate(certPath, pkix)

  }




  /**
   * Read from resources the Apple CA certificate
   *
   */
  def appleCACertificate() : Try[X509Certificate] = {

    Try {
      // get the url of the certificate
      val url = this.getClass.getResource("/AppleIncRootCertificate.crt")

      // using loan pattern, generate the certificate object from the
      // file stream
      val a =  using(url.openStream()) {
        CertificateFactory.getInstance("X.509", "BC").generateCertificate(_)
      }

      a.asInstanceOf[X509Certificate]
    }
  }

  /**
   * Check the signature. It validates the certification path using the input trust anchor and
   * then the embedded signature embedded in the envelope.
   *
   * @param signedData signed data containing the message and signature (envelope)
   * @param trustAnchorCert the trust anchor to validate the certification path
   * @return Try(true) if the signature is valid or Failure
   */
  def isValidSignature(signedData: CMSSignedData, trustAnchorCert: X509Certificate) : Try[Boolean] = {

    Try {

      // validate the cert path (not so functional ;-)
      validateCertPath(signedData, trustAnchorCert)

      // get the signer info
      val signerInfo = getSignerInfoFrom(signedData)

      // get the signer certificate
      val signerCert = getSignerCertificateFrom(signedData)

      // build the verifier using the signer certificate
      val verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert)

      // return true if the signature is valid
      signerInfo.verify(verifier)

    }
  }


}


