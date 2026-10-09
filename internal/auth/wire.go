package auth

// Wire format recovered from CUeApMsg and the vendor MarshalBinary methods.
// TCP frames have a four-byte big-endian protobuf body length.
import (
	"encoding/binary"
	"errors"
	"io"
)

const maxAuthFrame = 65536

type field struct {
	number int
	wire   byte
	data   []byte
	value  uint64
}
type message struct {
	id, direction, version, flags, sqn  uint32
	payload, state, session, mac, nonce []byte
}

func bytesField(b []byte, n int, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	b = binary.AppendUvarint(b, uint64(n<<3|2))
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}
func intField(b []byte, n int, v uint32) []byte {
	if v == 0 {
		return b
	}
	b = binary.AppendUvarint(b, uint64(n<<3))
	return binary.AppendUvarint(b, uint64(v))
}
func fixedField(b []byte, n int, v uint32) []byte {
	if v == 0 {
		return b
	}
	b = binary.AppendUvarint(b, uint64(n<<3|5))
	return binary.LittleEndian.AppendUint32(b, v)
}
func parseFields(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 || tag>>3 == 0 || tag>>3 > 536870911 {
			return nil, errors.New("invalid authentication protobuf")
		}
		b = b[n:]
		f := field{number: int(tag >> 3), wire: byte(tag & 7)}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, io.ErrUnexpectedEOF
			}
			f.value = v
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, io.ErrUnexpectedEOF
			}
			f.value = binary.LittleEndian.Uint64(b)
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, io.ErrUnexpectedEOF
			}
			b = b[n:]
			f.data = append([]byte(nil), b[:int(l)]...)
			b = b[int(l):]
		case 5:
			if len(b) < 4 {
				return nil, io.ErrUnexpectedEOF
			}
			f.value = uint64(binary.LittleEndian.Uint32(b))
			b = b[4:]
		default:
			return nil, errors.New("unsupported authentication protobuf wire type")
		}
		out = append(out, f)
	}
	return out, nil
}
func (m message) marshal() []byte {
	b := intField(nil, 1, m.id)
	b = intField(b, 2, m.direction)
	b = bytesField(b, 3, m.payload)
	b = bytesField(b, 4, m.state)
	b = bytesField(b, 5, m.session)
	b = bytesField(b, 6, m.mac)
	b = bytesField(b, 7, m.nonce)
	b = intField(b, 8, m.version)
	b = fixedField(b, 9, m.flags)
	return fixedField(b, 10, m.sqn)
}
func decodeMessage(b []byte) (message, error) {
	var m message
	fs, e := parseFields(b)
	if e != nil {
		return m, e
	}
	for _, f := range fs {
		expected := byte(0)
		if f.number >= 3 && f.number <= 7 {
			expected = 2
		}
		if f.number == 9 || f.number == 10 {
			expected = 5
		}
		if f.number <= 10 && f.wire != expected {
			return m, errors.New("invalid authentication field type")
		}
		switch f.number {
		case 1:
			m.id = uint32(f.value)
		case 2:
			m.direction = uint32(f.value)
		case 3:
			m.payload = f.data
		case 4:
			m.state = f.data
		case 5:
			m.session = f.data
		case 6:
			m.mac = f.data
		case 7:
			m.nonce = f.data
		case 8:
			m.version = uint32(f.value)
		case 9:
			m.flags = uint32(f.value)
		case 10:
			m.sqn = uint32(f.value)
		}
	}
	if m.id == 0 || m.direction != 2 || m.version > 2 {
		return m, errors.New("unsupported authentication envelope")
	}
	return m, nil
}
func readMessage(r io.Reader) (message, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return message{}, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > maxAuthFrame {
		return message{}, errors.New("invalid authentication frame size")
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return message{}, e
	}
	return decodeMessage(b)
}
func writeMessage(w io.Writer, m message) error {
	b := m.marshal()
	if len(b) > maxAuthFrame {
		return errors.New("authentication message too large")
	}
	b = append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (m message) canonical() []byte {
	b := []byte{byte(m.id), byte(m.direction)}
	b = append(b, m.payload...)
	b = append(b, m.state...)
	b = append(b, m.session...)
	b = append(b, m.nonce...)
	b = append(b, byte(m.version))
	b = binary.BigEndian.AppendUint32(b, m.flags)
	return binary.BigEndian.AppendUint32(b, m.sqn)
}
