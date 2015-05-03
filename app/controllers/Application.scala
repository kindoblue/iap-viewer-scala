package controllers

import play.api.mvc._

import scala.util.Try
import core.Parser

object Application extends Controller {

  def index = Action {
    Ok(views.html.index(Try(Nil)))
  }

  def uploadFile = Action(parse.multipartFormData) {

    request =>
      request.body.file("upfile").map { receipt =>

        // get the uri to the temporary file
        val receiptURI = receipt.ref.file.toURI

        // parse the purchases from the temp file
        val purchases = Parser.parsePurchasesFromURL(receiptURI.toURL)

        // render the page
        Ok(views.html.index(purchases))

      }.getOrElse {
        Redirect(routes.Application.index)
      }

  }

}