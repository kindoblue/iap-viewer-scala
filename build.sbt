name := "iap-viewer-scala"

version := "1.0"

lazy val `iapviewer` = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "2.11.6"

libraryDependencies ++= Seq(
  anorm ,
  cache ,
  ws ,
  "org.bouncycastle" % "bcprov-jdk15on" % "1.50",
  "org.bouncycastle" % "bcmail-jdk15on" % "1.50",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.50"
)

unmanagedResourceDirectories in Test <+=  baseDirectory ( _ /"target/web/public/test" )  
