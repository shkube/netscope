package payload

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// IPKey represents a source-destination IP pair
type IPKey struct {
	SrcIP uint32
	DstIP uint32
}

// IPValue represents the traffic statistics for an IP pair
type IPValue struct {
	Bytes uint64
}

// Payload represents traffic data sent from agent to server
type Payload struct {
	NodeName string
	Data     map[IPKey]IPValue
}

// Encode encodes the payload into binary format for transmission
// Format: [nodeNameLen(4)][nodeName][numEntries(4)][[srcIP(4)][dstIP(4)][bytes(8)]]...
func (p *Payload) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write node name length and node name
	nodeNameBytes := []byte(p.NodeName)
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(nodeNameBytes))); err != nil {
		return nil, fmt.Errorf("failed to write node name length: %w", err)
	}
	if _, err := buf.Write(nodeNameBytes); err != nil {
		return nil, fmt.Errorf("failed to write node name: %w", err)
	}

	// Write number of entries
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(p.Data))); err != nil {
		return nil, fmt.Errorf("failed to write number of entries: %w", err)
	}

	// Write each entry
	for key, value := range p.Data {
		if err := binary.Write(buf, binary.LittleEndian, key.SrcIP); err != nil {
			return nil, fmt.Errorf("failed to write source IP: %w", err)
		}
		if err := binary.Write(buf, binary.LittleEndian, key.DstIP); err != nil {
			return nil, fmt.Errorf("failed to write destination IP: %w", err)
		}
		if err := binary.Write(buf, binary.LittleEndian, value.Bytes); err != nil {
			return nil, fmt.Errorf("failed to write bytes: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// Decode decodes binary data into a Payload
func Decode(data []byte) (*Payload, error) {
	buf := bytes.NewReader(data)
	payload := &Payload{
		Data: make(map[IPKey]IPValue),
	}

	// Read node name length
	var nodeNameLen uint32
	if err := binary.Read(buf, binary.LittleEndian, &nodeNameLen); err != nil {
		return nil, fmt.Errorf("failed to read node name length: %w", err)
	}

	// Read node name
	nodeNameBytes := make([]byte, nodeNameLen)
	if _, err := io.ReadFull(buf, nodeNameBytes); err != nil {
		return nil, fmt.Errorf("failed to read node name: %w", err)
	}
	payload.NodeName = string(nodeNameBytes)

	// Read number of entries
	var numEntries uint32
	if err := binary.Read(buf, binary.LittleEndian, &numEntries); err != nil {
		return nil, fmt.Errorf("failed to read number of entries: %w", err)
	}

	// Read each entry
	for i := uint32(0); i < numEntries; i++ {
		var key IPKey
		var value IPValue

		if err := binary.Read(buf, binary.LittleEndian, &key.SrcIP); err != nil {
			return nil, fmt.Errorf("failed to read source IP: %w", err)
		}
		if err := binary.Read(buf, binary.LittleEndian, &key.DstIP); err != nil {
			return nil, fmt.Errorf("failed to read destination IP: %w", err)
		}
		if err := binary.Read(buf, binary.LittleEndian, &value.Bytes); err != nil {
			return nil, fmt.Errorf("failed to read bytes: %w", err)
		}

		payload.Data[key] = value
	}

	return payload, nil
}
