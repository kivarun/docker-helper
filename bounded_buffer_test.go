package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestBoundedBufferSequentialPolling(t *testing.T) {
	buf := newBoundedBuffer(100)

	buf.Write([]byte("hello"))
	buf.Write([]byte("world"))

	// First poll from offset 0.
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if truncated {
		t.Error("should not be truncated")
	}
	if string(data) != "helloworld" {
		t.Errorf("expected 'helloworld', got %q", string(data))
	}
	if next != 10 {
		t.Errorf("expected next_offset 10, got %d", next)
	}

	// Second poll from next_offset should return empty.
	data, next, truncated = buf.Range(10, rangeUnbounded)
	if string(data) != "" {
		t.Errorf("expected empty, got %q", string(data))
	}
	if next != 10 {
		t.Errorf("expected next_offset 10, got %d", next)
	}

	// More data arrives.
	buf.Write([]byte("!!!"))

	// Poll from previous next_offset.
	data, next, truncated = buf.Range(10, rangeUnbounded)
	if string(data) != "!!!" {
		t.Errorf("expected '!!!', got %q", string(data))
	}
	if next != 13 {
		t.Errorf("expected next_offset 13, got %d", next)
	}
}

func TestBoundedBufferRollover(t *testing.T) {
	buf := newBoundedBuffer(10)

	// Write 15 bytes total; only last 10 should be retained.
	buf.Write([]byte("12345"))
	buf.Write([]byte("67890"))
	buf.Write([]byte("ABCDE"))

	// totalLen = 15, retained = last 10 = "67890ABCDE"
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if !truncated {
		t.Error("expected truncated=true for offset older than retained")
	}
	if string(data) != "67890ABCDE" {
		t.Errorf("expected '67890ABCDE', got %q", string(data))
	}
	if next != 15 {
		t.Errorf("expected next_offset 15, got %d", next)
	}

	// Poll from retained start.
	data, next, truncated = buf.Range(5, rangeUnbounded)
	if truncated {
		t.Error("should not be truncated for offset inside retained range")
	}
	if string(data) != "67890ABCDE" {
		t.Errorf("expected '67890ABCDE', got %q", string(data))
	}

	// Poll from middle of retained range.
	data, next, truncated = buf.Range(10, rangeUnbounded)
	if string(data) != "ABCDE" {
		t.Errorf("expected 'ABCDE', got %q", string(data))
	}
}

func TestBoundedBufferOffsetOlderThanRetained(t *testing.T) {
	buf := newBoundedBuffer(5)

	buf.Write([]byte("1234567890"))

	// totalLen = 10, retained = last 5 = "67890"
	// offset 0 is older than retained start (5).
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if !truncated {
		t.Error("expected truncated=true")
	}
	if string(data) != "67890" {
		t.Errorf("expected '67890', got %q", string(data))
	}
	if next != 10 {
		t.Errorf("expected next_offset 10, got %d", next)
	}
}

func TestBoundedBufferOffsetEqualsNextOffset(t *testing.T) {
	buf := newBoundedBuffer(100)

	buf.Write([]byte("hello"))

	data, next, truncated := buf.Range(5, rangeUnbounded)
	if len(data) != 0 {
		t.Errorf("expected empty data, got %q", string(data))
	}
	if next != 5 {
		t.Errorf("expected next_offset 5, got %d", next)
	}
	if truncated {
		t.Error("should not be truncated")
	}
}

func TestBoundedBufferSingleWriteLargerThanMax(t *testing.T) {
	buf := newBoundedBuffer(10)

	// Write 50 bytes at once.
	buf.Write(make([]byte, 50))

	// Should retain only the last 10 bytes.
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if !truncated {
		t.Error("expected truncated=true")
	}
	if len(data) != 10 {
		t.Errorf("expected 10 bytes, got %d", len(data))
	}
	if next != 50 {
		t.Errorf("expected next_offset 50, got %d", next)
	}
}

func TestBoundedBufferMultipleWritesExceedingLimit(t *testing.T) {
	buf := newBoundedBuffer(20)

	// Write 10 chunks of 5 bytes = 50 total.
	for i := 0; i < 10; i++ {
		buf.Write([]byte("12345"))
	}

	// totalLen = 50, retained = last 20 = "12345" repeated 4 times.
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if !truncated {
		t.Error("expected truncated=true")
	}
	if len(data) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(data))
	}
	if next != 50 {
		t.Errorf("expected next_offset 50, got %d", next)
	}

	// Poll from retained start.
	data, next, truncated = buf.Range(30, rangeUnbounded)
	if truncated {
		t.Error("should not be truncated for offset inside retained range")
	}
	if len(data) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(data))
	}
}

func TestBoundedBufferNoDuplicatesOnPolling(t *testing.T) {
	buf := newBoundedBuffer(100)

	buf.Write([]byte("abcdefghij"))

	var all string
	offset := int64(0)
	for i := 0; i < 5; i++ {
		data, next, truncated := buf.Range(offset, rangeUnbounded)
		all += string(data)
		offset = next
		if !truncated && offset >= 10 {
			break
		}
	}

	if all != "abcdefghij" {
		t.Errorf("expected 'abcdefghij', got %q (duplicates: %v)", all, all != "abcdefghij")
	}
	if len(all) != 10 {
		t.Errorf("expected 10 chars, got %d (duplicates detected)", len(all))
	}
}

func TestBoundedBufferReturnsIndependentCopy(t *testing.T) {
	buf := newBoundedBuffer(100)

	buf.Write([]byte("hello"))

	data1, _, _ := buf.Range(0, rangeUnbounded)
	if string(data1) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data1))
	}

	// Modify the returned slice.
	data1[0] = 'X'

	// Buffer should be unchanged.
	data2, _, _ := buf.Range(0, rangeUnbounded)
	if string(data2) != "hello" {
		t.Errorf("expected 'hello' after modification, got %q", string(data2))
	}
}

func TestBoundedBufferConcurrentWrites(t *testing.T) {
	buf := newBoundedBuffer(200000)

	// Concurrent writes from multiple goroutines.
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func(n int) {
			defer wg.Done()
			prefix := strings.Repeat(string(rune('A'+n)), 100)
			for j := 0; j < 100; j++ {
				buf.Write([]byte(prefix))
			}
		}(i)
	}
	wg.Wait()

	// Should have 100,000 bytes total.
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if truncated {
		t.Error("should not be truncated (100000 bytes fits in 200000 buffer)")
	}
	// Due to concurrent writes, exact content may vary, but total should be correct.
	if next != 100000 {
		t.Errorf("expected next_offset 100000, got %d", next)
	}
	if int64(len(data)) != next {
		t.Errorf("expected %d bytes, got %d", next, len(data))
	}
}

func TestBoundedBufferEmptyRange(t *testing.T) {
	buf := newBoundedBuffer(100)

	data, next, truncated := buf.Range(0, rangeUnbounded)
	if len(data) != 0 {
		t.Errorf("expected empty, got %q", string(data))
	}
	if next != 0 {
		t.Errorf("expected next_offset 0, got %d", next)
	}
	if truncated {
		t.Error("should not be truncated")
	}
}

func TestBoundedBufferOffsetBeyondTotal(t *testing.T) {
	buf := newBoundedBuffer(100)

	buf.Write([]byte("hello"))

	data, next, truncated := buf.Range(100, rangeUnbounded)
	if len(data) != 0 {
		t.Errorf("expected empty, got %q", string(data))
	}
	if next != 5 {
		t.Errorf("expected next_offset 5, got %d", next)
	}
	if truncated {
		t.Error("should not be truncated")
	}
}

func TestBoundedBufferExactMaxSize(t *testing.T) {
	buf := newBoundedBuffer(10)

	buf.Write([]byte("1234567890"))

	// Exactly at limit, nothing should be trimmed.
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if truncated {
		t.Error("should not be truncated at exact limit")
	}
	if string(data) != "1234567890" {
		t.Errorf("expected '1234567890', got %q", string(data))
	}
	if next != 10 {
		t.Errorf("expected next_offset 10, got %d", next)
	}
}

func TestBoundedBufferIncrementalRollover(t *testing.T) {
	buf := newBoundedBuffer(10)

	// Write one byte at a time, 20 total.
	for i := 0; i < 20; i++ {
		buf.Write([]byte{byte('0' + i%10)})
	}

	// totalLen = 20, retained = last 10.
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if !truncated {
		t.Error("expected truncated=true")
	}
	if len(data) != 10 {
		t.Errorf("expected 10 bytes, got %d", len(data))
	}
	if next != 20 {
		t.Errorf("expected next_offset 20, got %d", next)
	}

	// Poll from retained start.
	data, next, truncated = buf.Range(10, rangeUnbounded)
	if truncated {
		t.Error("should not be truncated for offset at retained start")
	}
	if len(data) != 10 {
		t.Errorf("expected 10 bytes, got %d", len(data))
	}
}

func TestBoundedBufferMixedWriteSizes(t *testing.T) {
	buf := newBoundedBuffer(100)

	// Various write sizes.
	buf.Write([]byte("a"))
	buf.Write([]byte("bb"))
	buf.Write([]byte("ccc"))
	buf.Write(make([]byte, 200)) // exceeds limit

	// totalLen = 1 + 2 + 3 + 200 = 206.
	// retained = last 100 bytes.
	data, next, truncated := buf.Range(0, rangeUnbounded)
	if !truncated {
		t.Error("expected truncated=true")
	}
	if len(data) != 100 {
		t.Errorf("expected 100 bytes, got %d", len(data))
	}
	if next != 206 {
		t.Errorf("expected next_offset 206, got %d", next)
	}

	// The last 100 bytes should be all zero bytes from the large write.
	if !bytes.Equal(data, make([]byte, 100)) {
		t.Error("expected last 100 bytes to be zero bytes from large write")
	}
}

// TestBoundedBufferBoundedChunkExactBoundary proves the bounded read: a
// retained stream of exactly one chunk returns that chunk with
// next_offset at the boundary, and the follow-up read is empty with no
// progress and no truncation.
func TestBoundedBufferBoundedChunkExactBoundary(t *testing.T) {
	buf := newBoundedBuffer(int64(logResponseChunkBytes))
	chunk := make([]byte, logResponseChunkBytes)
	for i := range chunk {
		chunk[i] = byte('a' + i%26)
	}
	buf.Write(chunk)

	data, next, truncated := buf.Range(0, logResponseChunkBytes)
	if truncated {
		t.Error("exact boundary must not be truncated")
	}
	if len(data) != logResponseChunkBytes {
		t.Fatalf("exact boundary must return the full chunk: %d", len(data))
	}
	if next != int64(logResponseChunkBytes) {
		t.Fatalf("next_offset must follow returned bytes: %d", next)
	}

	// One byte over the boundary: the follow-up read is empty.
	data, next, truncated = buf.Range(next, logResponseChunkBytes)
	if len(data) != 0 || next != int64(logResponseChunkBytes) || truncated {
		t.Fatalf("read at the exact boundary must be empty and untruncated: %d %d %v", len(data), next, truncated)
	}
}

// TestBoundedBufferBoundedChunkOverBoundary proves a stream one byte over the
// chunk ceiling splits into exactly two chunks at the boundary.
func TestBoundedBufferBoundedChunkOverBoundary(t *testing.T) {
	buf := newBoundedBuffer(int64(logResponseChunkBytes) + 1)
	buf.Write(make([]byte, logResponseChunkBytes+1))

	data, next, _ := buf.Range(0, logResponseChunkBytes)
	if len(data) != logResponseChunkBytes || next != int64(logResponseChunkBytes) {
		t.Fatalf("first chunk must be capped at the ceiling: %d %d", len(data), next)
	}
	data, next, _ = buf.Range(next, logResponseChunkBytes)
	if len(data) != 1 || next != int64(logResponseChunkBytes)+1 {
		t.Fatalf("second chunk must hold the one over-boundary byte: %d %d", len(data), next)
	}
}

// TestBoundedBufferChunkedReconstruction proves successive bounded chunks
// reconstruct the retained stream exactly: no gaps, no duplicates, and
// next_offset always advances by the bytes actually returned.
func TestBoundedBufferChunkedReconstruction(t *testing.T) {
	buf := newBoundedBuffer(int64(3 * logResponseChunkBytes))
	stream := make([]byte, 3*logResponseChunkBytes)
	for i := range stream {
		stream[i] = byte('A' + i%26)
	}
	buf.Write(stream)

	var got []byte
	offset := int64(0)
	for {
		data, next, truncated := buf.Range(offset, logResponseChunkBytes)
		got = append(got, data...)
		if !truncated && len(data) < logResponseChunkBytes {
			break
		}
		if int64(len(data)) > 0 && next <= offset {
			t.Fatalf("next_offset must advance beyond %d, got %d", offset, next)
		}
		offset = next
		if offset >= int64(len(stream)) {
			break
		}
	}
	if !bytes.Equal(got, stream) {
		t.Fatalf("chunked reconstruction mismatch: got %d bytes, want %d", len(got), len(stream))
	}
}

// TestBoundedBufferRolloverTruncatedChunk proves the rollover contract: an
// offset that predates the retained data starts at the oldest retained byte,
// returns at most one bounded chunk with truncated=true, and its next_offset
// follows the returned bytes — no retained bytes are silently skipped.
func TestBoundedBufferRolloverTruncatedChunk(t *testing.T) {
	buf := newBoundedBuffer(int64(2 * logResponseChunkBytes))
	total := 3 * logResponseChunkBytes
	buf.Write(make([]byte, total))

	// offset 0 predates the retained range [total-2*chunk, total).
	data, next, truncated := buf.Range(0, logResponseChunkBytes)
	if !truncated {
		t.Fatal("rollover read must be truncated")
	}
	if len(data) != logResponseChunkBytes {
		t.Fatalf("rollover read must be bounded to one chunk: %d", len(data))
	}
	if next != int64(total-2*logResponseChunkBytes+logResponseChunkBytes) {
		t.Fatalf("next_offset must follow the returned bytes: %d", next)
	}

	// The second read continues inside the retained range, untruncated.
	data, next, truncated = buf.Range(next, logResponseChunkBytes)
	if truncated {
		t.Fatal("continuation inside the retained range must not be truncated")
	}
	if len(data) != logResponseChunkBytes {
		t.Fatalf("continuation must return the rest of the retained range: %d", len(data))
	}
	if next != int64(total) {
		t.Fatalf("continuation next_offset must be totalLen: %d", next)
	}
}

// TestBoundedBufferZeroMaxBytesMakesNoProgress documents the zero-ceiling
// contract: no bytes and no progress, which is what terminates the shared
// drain helpers.
func TestBoundedBufferZeroMaxBytesMakesNoProgress(t *testing.T) {
	buf := newBoundedBuffer(100)
	buf.Write([]byte("hello"))
	data, next, _ := buf.Range(0, 0)
	if len(data) != 0 || next != 0 {
		t.Fatalf("zero ceiling must return no bytes and no progress: %d %d", len(data), next)
	}
}
