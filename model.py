from pathlib import Path
import hashlib
import json

import numpy as np
import pandas as pd
#cleanup function 
def main():
    # Directory containing this script.
    root = Path(__file__).resolve().parent
    output = root / "cleaned"
    max_delta = 1.0

    frames = []
    summaries = []

    for name, label in [("h0", 0), ("h1", 1)]:
        folder = root / name

        if not folder.is_dir():
            raise FileNotFoundError(f"Missing folder: {folder}")

        frame, summary = clean_condition(
            folder, label, output, max_delta
        )

        frames.append(frame)
        summaries.append(summary)

    combined = pd.concat(frames, ignore_index=True)
    combined.to_csv(output / "combined_clean.csv", index=False)

    (output / "cleaning_summary.json").write_text(
        json.dumps(summaries, indent=2),
        encoding="utf-8",
    )

    print(f"\nSaved cleaned files to: {output.resolve()}")


if __name__ == "__main__":
    main()
