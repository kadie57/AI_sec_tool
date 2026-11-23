@main def exec() = {
  importCode("/project/Clean_Code/VulnerablePath.java")
  println("=== PATH_CALLS_BEGIN ===")
  cpg.call
    .filter(c => c.lineNumber.exists(n => n >= 13 && n <= 18))
    .foreach { c =>
      println(s"LINE=${c.lineNumber} NAME=${c.name}")
      println(s"METHOD=${c.methodFullName}")
      println(s"CODE=${c.code}")
      println("ARGS=" + c.argument.code.l.mkString(" | "))
    }
  println("=== PATH_CALLS_END ===")
}
