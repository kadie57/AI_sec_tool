@main def exec() = {
  importCode("/work/input")
  def enc(s: String): String = java.util.Base64.getEncoder.encodeToString(s.getBytes(java.nio.charset.StandardCharsets.UTF_8))
  def sources = cpg.method.parameter.filter(_.index > 0)
  val first = 66
  val last = 66
  val calls = cpg.call.filter(c =>
    c.lineNumber.exists(n => n >= first && n <= last) ||
    Set("command", "start", "exec", "add").contains(c.name) ||
    c.code.contains("ProcessBuilder") || c.methodFullName.contains("ProcessBuilder")
  ).l
  println("COMMAND_DIAGNOSTIC_V1_BEGIN")
  sources.l.foreach(p => println("PARAM\t" + p.id + "\t" + p.lineNumber.getOrElse(-1) + "\t" + p.index + "\t" + enc(p.name) + "\t" + enc(p.code)))
  calls.foreach { c =>
    println("CALL\t" + c.id + "\t" + c.lineNumber.getOrElse(-1) + "\t" + enc(c.name) + "\t" + enc(c.methodFullName) + "\t" + enc(c.code))
    c.argument.l.foreach { a =>
      println("ARG\t" + c.id + "\t" + a.argumentIndex + "\t" + a.lineNumber.getOrElse(-1) + "\t" + enc(a.code))
    }
    if (c.lineNumber.exists(n => n >= first && n <= last) || c.name == "start") {
      c.argument.l.foreach { a =>
        try {
          val paths = cpg.call.filter(_.id == c.id).argument.filter(_.argumentIndex == a.argumentIndex).reachableByFlows(sources).l
          println("FLOW\t" + c.id + "\t" + a.argumentIndex + "\t" + paths.size + "\t" + enc(paths.iterator.p.mkString("\n")))
        } catch {
          case error: Exception => println("FLOW_ERROR\t" + c.id + "\t" + a.argumentIndex + "\t" + enc(error.toString))
        }
      }
    }
  }
  println("COMMAND_DIAGNOSTIC_V1_END")
}
