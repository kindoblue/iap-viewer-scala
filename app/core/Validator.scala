package core

import java.security.cert.CertificateFactory

import Common.using

/**
 * Created by Stefano on 14/02/15.
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

}


