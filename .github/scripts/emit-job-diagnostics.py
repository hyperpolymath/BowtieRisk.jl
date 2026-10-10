# TEMPORARY diagnostic (#61): publish the tail of a failing step's output as
# check annotations, because raw job logs are not retrievable outside the UI.
# Removed once the root cause of the Julia install/format/JET failures is fixed.
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(errors="replace") if path.exists() else "(no log captured)"
text = text[-12000:]
def esc(s):
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
for i in range(0, len(text), 3000):
    print(f"::error title=diag {i // 3000}::{esc(text[i:i + 3000])}")
