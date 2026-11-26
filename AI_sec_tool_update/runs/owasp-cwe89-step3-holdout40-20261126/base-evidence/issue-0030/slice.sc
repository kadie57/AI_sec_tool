@main def exec() = {
  importCode("/project/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02276.java")
  def source = cpg.method.parameter.filter(_.index > 0)
  def sinkCalls = cpg.call.name("execute|update|query|queryForList|queryForMap|queryForObject|queryForRowSet|queryForStream|batchUpdate")
    .filter(c => c.lineNumber.exists(n => n >= 58 && n <= 58))
  def sink = sinkCalls.argument(1)
  val paths = sink.reachableByFlows(source).l
  println("CPG_GATE_BEGIN")
  println("SINK_CALL_COUNT=" + sinkCalls.size)
  println("SINK_ARGUMENT_COUNT=" + sink.size)
  println("CPG_GATE_END")
  println("CPG_RESULT_BEGIN")
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\n"))
  println("CPG_RESULT_END")
}
