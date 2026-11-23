@main def exec() = {
  importCode("/project/Clean_Code/pilot_sql89/Trial07.java")
  def source = cpg.method.parameter.filter(_.index > 0)
  def sink = cpg.call.name("executeQuery|executeUpdate|execute|prepareStatement|prepareCall")
    .filter(c => c.lineNumber.exists(n => n >= 25 && n <= 25)).argument(1)
  
  println("=== DIAGNOSTIC_BEGIN ===")
  println("SOURCE_COUNT=" + source.size)
  println("SINK_ARGUMENT_COUNT=" + sink.size)
  sink.l.foreach(n => println("SINK_ARGUMENT=" + n.code))
  cpg.call.name("executeQuery").l.foreach { c =>
    println("CALL_LINE=" + c.lineNumber + " CODE=" + c.code)
    c.argument.l.foreach(a =>
      println("ARG=" + a.argumentIndex + " CODE=" + a.code))
  }
  println("=== DIAGNOSTIC_END ===")
  val paths = sink.reachableByFlows(source).l

  println("CPG_RESULT_BEGIN")
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\n"))
  println("CPG_RESULT_END")
}
