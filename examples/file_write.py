from pathlib import Path
Path("/workspace/result.txt").write_text("This should fail: workspace is read-only.")
