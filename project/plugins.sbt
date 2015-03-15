logLevel := Level.Debug

resolvers += "Typesafe repository" at "http://repo.typesafe.com/typesafe/releases/"

addSbtPlugin("com.typesafe.play" % "sbt-plugin" % "2.3.8")

dependencyOverrides += "org.scala-sbt" % "sbt" % "0.13.7"
