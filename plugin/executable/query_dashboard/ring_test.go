package query_dashboard

import (
	"testing"
	"time"
)

func recordWithQname(qname string) QueryRecord {
	return QueryRecord{Time: time.Now(), Qname: qname, Client: "10.0.0.10", Route: "main", Entry: "main", Upstream: "upstream"}
}

func TestRingRecentNewestFirstAndCapacity(t *testing.T) {
	ring := NewRing(2)
	ring.Add(recordWithQname("one.example."))
	ring.Add(recordWithQname("two.example."))
	ring.Add(recordWithQname("three.example."))

	got := ring.Recent(10, 0)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Qname != "three.example." || got[1].Qname != "two.example." {
		t.Fatalf("recent order = %#v", got)
	}
}

func TestRingRecentOffsetAndCopy(t *testing.T) {
	ring := NewRing(3)
	ring.Add(recordWithQname("one.example."))
	ring.Add(recordWithQname("two.example."))
	ring.Add(recordWithQname("three.example."))

	got := ring.Recent(1, 1)
	if len(got) != 1 || got[0].Qname != "two.example." {
		t.Fatalf("recent with offset = %#v", got)
	}
	got[0].Qname = "changed.example."
	if again := ring.Recent(1, 1); again[0].Qname != "two.example." {
		t.Fatalf("ring returned mutable records: %#v", again)
	}
}

func TestRingSearch(t *testing.T) {
	ring := NewRing(4)
	ring.Add(QueryRecord{Time: time.Now(), Qname: "one.example.", Client: "10.0.0.10"})
	ring.Add(QueryRecord{Time: time.Now(), Qname: "two.example.", Route: "Foreign"})
	ring.Add(QueryRecord{Time: time.Now(), Qname: "three.example.", Upstream: "Quad9"})

	got := ring.Search("foreign", 10)
	if len(got) != 1 || got[0].Qname != "two.example." {
		t.Fatalf("route search = %#v", got)
	}
	got = ring.Search("quad9", 10)
	if len(got) != 1 || got[0].Qname != "three.example." {
		t.Fatalf("upstream search = %#v", got)
	}
}

func TestRingMinimumCapacity(t *testing.T) {
	ring := NewRing(0)
	ring.Add(recordWithQname("one.example."))
	ring.Add(recordWithQname("two.example."))
	if got := ring.Recent(10, 0); len(got) != 1 || got[0].Qname != "two.example." {
		t.Fatalf("minimum capacity recent = %#v", got)
	}
}
