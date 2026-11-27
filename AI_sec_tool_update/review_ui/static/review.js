function revealSourceLine() {
  const id = window.location.hash.slice(1);
  if (!/^F\d+-L\d+$/.test(id)) return;

  const row = document.getElementById(id);
  const source = row?.closest("details");
  if (source) {
    source.open = true;
    row.scrollIntoView({ block: "center", inline: "nearest" });
  }
}

window.addEventListener("hashchange", revealSourceLine);
revealSourceLine();
