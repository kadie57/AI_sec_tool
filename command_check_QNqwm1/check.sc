@main def exec() = {
  importCode("/work/input")

  println("=== COMMAND_FLOW_BEGIN ===")

  cpg.call.nameExact("exec").foreach { c =>
    println("LINE=" + c.lineNumber)
    println("METHOD=" + c.methodFullName)
    println("CODE=" + c.code)
    c.argument.foreach { a =>
      println("ARG[" + a.argumentIndex + "]=" + a.code)
    }
  }

  def source = cpg.method.nameExact("pingHost")
    .parameter.nameExact("targetIp")

  def sink = cpg.call.nameExact("exec")
    .filter(_.lineNumber.contains(12))
    .argument(1)

  val paths = sink.reachableByFlows(source).l
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\n"))

  println("=== COMMAND_FLOW_END ===")
}
