package core

import java.security.cert.{TrustAnchor, PKIXParameters, X509Certificate, CertificateFactory}


import Common.{using, convertX509}
import org.bouncycastle.cms.CMSSignedData

/**
 * Created by Stefano on 14/02/15.
 *
 * The Validator object provides functionality to validate the Apple receipts, by
 * checking the signature of the CMS envelop while using the Apple CA certificate
 * as trust anchor.
 */
object Validator {


  /**
   * Read from resources the Apple CA certificate, to validate the receipts.
   *
   */
  def appleCACertificate() : java.security.cert.Certificate = {

    // get the url of the certificate
    val url = this.getClass.getResource("/AppleIncRootCertificate.crt")

    // using loan pattern, generate the certificate object from the
    // file stream
    using(url.openStream()) {
      CertificateFactory.getInstance("X.509", "BC").generateCertificate(_)
    }
  }

  /**
   * Returns the pkix parameters based on the input certificate as trust anchor,
   * correctly configured.
   * @param certificate the certificate to use as trust anchor
   */
  def createPKIXParams(certificate: X509Certificate) : PKIXParameters = {

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
  def getCertificateFrom(signedData: CMSSignedData) : Iterable[java.security.cert.X509Certificate] = {
    import scala.collection.JavaConversions._
    signedData.getCertificates.getMatches(null).map(convertX509)

  }

}


