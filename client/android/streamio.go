package atlant

import (
	"atlant.local/protocol/wire"
	"io"
)

func writeFull(w io.Writer, p []byte) error { return wire.WriteFull(w, p) }
