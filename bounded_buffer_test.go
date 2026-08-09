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
	data, next, truncated := buf.Range(0)
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
	data, next, truncated = buf.Range(10)
	if string(data) != "" {
		t.Errorf("expected empty, got %q", string(data))
	}
	if next != 10 {
		t.Errorf("expected next_offset 10, got %d", next)
	}

	// More data arrives.
	buf.Write([]byte("!!!"))

	// Poll from previous next_offset.
	data, next, truncated = buf.Range(10)
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
	data, next, truncated := buf.Range(0)
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
	data, next, truncated = buf.Range(5)
	if truncated {
		t.Error("should not be truncated for offset inside retained range")
	}
	if string(data) != "67890ABCDE" {
		t.Errorf("expected '67890ABCDE', got %q", string(data))
	}

	// Poll from middle of retained range.
	data, next, truncated = buf.Range(10)
	if string(data) != "ABCDE" {
		t.Errorf("expected 'ABCDE', got %q", string(data))
	}
}

func TestBoundedBufferOffsetOlderThanRetained(t *testing.T) {
	buf := newBoundedBuffer(5)

	buf.Write([]byte("1234567890"))

	// totalLen = 10, retained = last 5 = "67890"
	// offset 0 is older than retained start (5).
	data, next, truncated := buf.Range(0)
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

	data, next, truncated := buf.Range(5)
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
	data, next, truncated := buf.Range(0)
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
	data, next, truncated := buf.Range(0)
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
	data, next, truncated = buf.Range(30)
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
		data, next, truncated := buf.Range(offset)
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

	data1, _, _ := buf.Range(0)
	if string(data1) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data1))
	}

	// Modify the returned slice.
	data1[0] = 'X'

	// Buffer should be unchanged.
	data2, _, _ := buf.Range(0)
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
	data, next, truncated := buf.Range(0)
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

	data, next, truncated := buf.Range(0)
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

	data, next, truncated := buf.Range(100)
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
	data, next, truncated := buf.Range(0)
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
	data, next, truncated := buf.Range(0)
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
	data, next, truncated = buf.Range(10)
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
	data, next, truncated := buf.Range(0)
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
