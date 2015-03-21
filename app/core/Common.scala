package core

/**
 * Created by Stefano on 21/03/15.
 *
 * Here's the stuff needed by Parser and Validation objects
 *
 */
object Common {

  /**
   * Loan pattern for resources that has to be closed after manipulation
   * Curried function so we can use {} to wrap the function literal in input
   *
   * see Programming in Scala, pag 174
   *
   * @param resource the resource to handle, which has for sure a close method
   * @param f the function to perform on the resource
   * @tparam A the type of the resource
   * @tparam B the return type resulting from the handling of the resource
   * @return the result from the applied f function
   */
  def using[A <: { def close(): Unit }, B](resource: A)(f: A => B): B =
    try {
      f(resource) }
    finally {
      resource.close()
    }

}
