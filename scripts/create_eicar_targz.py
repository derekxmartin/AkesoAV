#!/usr/bin/env python3
"""Create testdata/eicar.tar.gz with the EICAR test string."""
import tarfile, io, os

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
assert len(EICAR) == 68, f"EICAR length {len(EICAR)} != 68"

outdir = os.path.join(os.path.dirname(__file__), "..", "testdata")
outpath = os.path.join(outdir, "eicar.tar.gz")

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as t:
    info = tarfile.TarInfo("eicar.com")
    info.size = len(EICAR)
    t.addfile(info, io.BytesIO(EICAR))

with open(outpath, "wb") as f:
    f.write(buf.getvalue())

print(f"Created {outpath} ({len(buf.getvalue())} bytes)")
