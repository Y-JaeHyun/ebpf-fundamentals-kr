// 04-1: BPF 프로그램 없이 사용자 공간에서 map을 직접 만들어 종류별 동작 차이를 확인한다.
// (map 생성도 bpf() 시스템 콜이라 root가 필요하다)
package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	hashMap()
	arrayMap()
	lruMap()
	lpmTrie()
	perCPUArray()
}

func newMap(spec *ebpf.MapSpec) *ebpf.Map {
	m, err := ebpf.NewMap(spec)
	if err != nil {
		log.Fatalf("%s 생성 실패: %v", spec.Name, err)
	}
	return m
}

func hashMap() {
	fmt.Println("=== HASH (max_entries=4)")
	m := newMap(&ebpf.MapSpec{Name: "demo_hash", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 4})
	defer m.Close()

	for k := uint32(1); k <= 5; k++ {
		err := m.Put(k, uint64(k*100))
		fmt.Printf("  Put(%d) → %v\n", k, errOrOK(err))
	}
	var v uint64
	fmt.Printf("  Lookup(9) → %v\n", errOrOK(m.Lookup(uint32(9), &v)))
	// Update 플래그: NoExist는 "없을 때만", Exist는 "있을 때만"
	fmt.Printf("  Update(1, NoExist) → %v\n", errOrOK(m.Update(uint32(1), uint64(1), ebpf.UpdateNoExist)))
	fmt.Printf("  Delete(1) → %v, 이후 Put(5) → %v\n", errOrOK(m.Delete(uint32(1))), errOrOK(m.Put(uint32(5), uint64(500))))
}

func arrayMap() {
	fmt.Println("=== ARRAY (max_entries=4)")
	m := newMap(&ebpf.MapSpec{Name: "demo_array", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 4})
	defer m.Close()

	var v uint64
	fmt.Printf("  Lookup(2) (아무것도 안 넣음) → %v, 값=%d\n", errOrOK(m.Lookup(uint32(2), &v)), v)
	fmt.Printf("  Lookup(4) (범위 밖) → %v\n", errOrOK(m.Lookup(uint32(4), &v)))
	fmt.Printf("  Delete(2) → %v\n", errOrOK(m.Delete(uint32(2))))
}

func lruMap() {
	fmt.Println("=== LRU_HASH (max_entries=4): 1~4를 넣고 1을 조회한 뒤 5, 6을 넣는다")
	m := newMap(&ebpf.MapSpec{Name: "demo_lru", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 8, MaxEntries: 4})
	defer m.Close()

	var v uint64
	for k := uint32(1); k <= 4; k++ {
		m.Put(k, uint64(k))
	}
	m.Lookup(uint32(1), &v) // 1을 "최근 사용"으로 만든다
	for k := uint32(5); k <= 6; k++ {
		fmt.Printf("  Put(%d) → %v\n", k, errOrOK(m.Put(k, uint64(k))))
	}
	fmt.Print("  남은 키:")
	var k uint32
	it := m.Iterate()
	for it.Next(&k, &v) {
		fmt.Printf(" %d", k)
	}
	fmt.Println()
}

// LPM trie 키: 앞 4바이트가 prefix 길이(비트), 뒤가 주소(네트워크 바이트 순서)
type lpmKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

func lpmTrie() {
	fmt.Println("=== LPM_TRIE: 가장 긴 prefix 일치")
	m := newMap(&ebpf.MapSpec{
		Name: "demo_lpm", Type: ebpf.LPMTrie, KeySize: 8, ValueSize: 4, MaxEntries: 16,
		Flags: 1, // BPF_F_NO_PREALLOC: LPM trie는 반드시 이 플래그가 필요하다
	})
	defer m.Close()

	routes := map[string]uint32{"0.0.0.0/0": 1, "10.0.0.0/8": 2, "10.1.0.0/16": 3, "10.1.2.0/24": 4}
	for cidr, id := range routes {
		p := netip.MustParsePrefix(cidr)
		if err := m.Put(lpmKey{uint32(p.Bits()), p.Addr().As4()}, id); err != nil {
			log.Fatal(err)
		}
	}
	names := map[uint32]string{1: "0.0.0.0/0", 2: "10.0.0.0/8", 3: "10.1.0.0/16", 4: "10.1.2.0/24"}
	for _, ip := range []string{"10.1.2.3", "10.1.9.9", "10.200.0.1", "192.168.0.1"} {
		var id uint32
		// 조회할 때는 prefix 길이를 최대(32)로 준다
		err := m.Lookup(lpmKey{32, netip.MustParseAddr(ip).As4()}, &id)
		fmt.Printf("  %-12s → %s %v\n", ip, names[id], errOrEmpty(err))
	}
}

func perCPUArray() {
	n, err := ebpf.PossibleCPU()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("=== PERCPU_ARRAY: 키 하나에 CPU 수(%d)만큼 값이 있다\n", n)
	m := newMap(&ebpf.MapSpec{Name: "demo_pcpu", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	defer m.Close()

	vals := make([]uint64, n)
	for i := range vals {
		vals[i] = uint64(i + 1)
	}
	if err := m.Put(uint32(0), vals); err != nil {
		log.Fatal(err)
	}
	var got []uint64
	if err := m.Lookup(uint32(0), &got); err != nil {
		log.Fatal(err)
	}
	var sum uint64
	for _, v := range got {
		sum += v
	}
	fmt.Printf("  Lookup(0) → 길이 %d 슬라이스 %v, 합 %d\n", len(got), got, sum)
}

func errOrOK(err error) string {
	switch {
	case err == nil:
		return "OK"
	case errors.Is(err, ebpf.ErrKeyNotExist):
		return "ErrKeyNotExist"
	case errors.Is(err, ebpf.ErrKeyExist):
		return "ErrKeyExist"
	}
	return "에러: " + err.Error()
}

func errOrEmpty(err error) string {
	if err == nil {
		return ""
	}
	return "(" + errOrOK(err) + ")"
}
