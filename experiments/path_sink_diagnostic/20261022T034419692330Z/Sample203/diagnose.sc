@main def exec() = {
  importCode("/work/input")
  def source = cpg.method.parameter.filter(_.index > 0)
  println("DIAGNOSTIC_BEGIN")
  println("SOURCE_COUNT=" + source.size)
  cpg.call.nameExact("<init>").l.foreach { c =>
    println("LINE=" + c.lineNumber + " METHOD=" + c.methodFullName)
    println("CODE=" + c.code)
    c.argument.l.foreach { a =>
      println("ARG=" + a.argumentIndex + " CODE=" + a.code)
    }
    if (c.code.contains("File") || c.methodFullName.contains("File")) {
      val paths = cpg.call.id(c.id).argument(1).reachableByFlows(source).l
      println("ARG1_FLOW_COUNT=" + paths.size)
      println(paths.iterator.p.mkString("\n"))
    }
  }
  println("DIAGNOSTIC_END")
}
