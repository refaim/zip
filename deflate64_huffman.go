package zip

import (
	"sort"
)

// huffNode is used to construct a Huffman tree
type huffNode struct {
	weight uint32
	symbol int16
	left   int16
	right  int16
}

// buildHuffmanTree builds an optimal Huffman tree limited to maxDepth.
// Uses a classic bottom-up tree builder followed by depth limit correction.
func buildHuffmanTree(freqs []uint32, maxDepth int, lengths []byte) {
	for i := range lengths {
		lengths[i] = 0
	}

	// Storage for all tree nodes (leaves and parents)
	var treeNodes []huffNode
	// Active list of subtree indices
	var active []int

	for sym, freq := range freqs {
		if freq > 0 {
			active = append(active, len(treeNodes))
			treeNodes = append(treeNodes, huffNode{
				weight: freq,
				symbol: int16(sym),
				left:   -1,
				right:  -1,
			})
		}
	}

	if len(active) == 0 {
		return
	}
	if len(active) == 1 {
		lengths[treeNodes[active[0]].symbol] = 1
		return
	}

	// Build the tree bottom-up by combining nodes with the lowest weights
	for len(active) > 1 {
		sort.Slice(active, func(i, j int) bool {
			return treeNodes[active[i]].weight < treeNodes[active[j]].weight
		})

		leftIdx := active[0]
		rightIdx := active[1]

		parentIdx := len(treeNodes)
		// #nosec G115 -- treeNodes holds one leaf per used symbol plus one
		// parent per merge. The largest table passed in has
		// kFixedMainTableSize (288) symbols, so at most 575 nodes exist and
		// every index fits in int16.
		parent := huffNode{
			weight: treeNodes[leftIdx].weight + treeNodes[rightIdx].weight,
			symbol: -1,
			left:   int16(leftIdx),
			right:  int16(rightIdx),
		}
		treeNodes = append(treeNodes, parent)

		// Remove the two merged indices and append the new parent index
		active = append(active[2:], parentIdx)
	}

	// Recursive tree traversal to calculate Huffman code lengths
	var walk func(idx int, depth byte)
	walk = func(idx int, depth byte) {
		node := &treeNodes[idx]
		if node.symbol >= 0 {
			lengths[node.symbol] = depth
			return
		}
		walk(int(node.left), depth+1)
		walk(int(node.right), depth+1)
	}

	walk(active[0], 0) // Start traversal from the root (the only remaining index in active)

	// Adjust code depths if they exceed maxDepth (limiting max code length)
	limitCodeLengths(lengths, maxDepth)
}

// limitCodeLengths rewrites a code whose longest word runs past maxDepth,
// which the block header has no field to spell. Every alphabet it is called
// with fits maxDepth levels - 2^maxDepth is well above the number of symbols -
// so a code within the limit always exists.
func limitCodeLengths(lengths []byte, maxDepth int) {
	var count [33]int
	for _, l := range lengths {
		if l == 0 {
			continue
		}
		d := int(l)
		if d > maxDepth {
			d = maxDepth
		}
		count[d]++
	}

	// The code space the words take, counted in leaves of a full maxDepth
	// level tree. A tree that stayed inside the limit uses exactly all of it,
	// so anything more is the cost of the words that were cut back to it.
	limit := 1 << maxDepth
	used := 0
	for d := 1; d <= maxDepth; d++ {
		used += count[d] << (maxDepth - d)
	}
	if used <= limit {
		return
	}

	// Give the space back by lengthening words, always the longest one that
	// can still grow: that is the smallest repayment on offer, so the code
	// stays as close to the tree it came from as the limit allows. While the
	// words take more space than a full maxDepth level tree has, they cannot
	// all be at maxDepth already, so one is always left to lengthen.
	for used > limit {
		d := maxDepth - 1
		for count[d] == 0 {
			d--
		}
		count[d]--
		count[d+1]++
		used -= 1 << (maxDepth - d - 1)
	}

	// Assign new lengths to the symbols
	var activeSymbols []int
	for sym, l := range lengths {
		if l > 0 {
			activeSymbols = append(activeSymbols, sym)
		}
	}

	sort.Slice(activeSymbols, func(i, j int) bool {
		return lengths[activeSymbols[i]] < lengths[activeSymbols[j]]
	})

	currDepth := 1
	currCount := count[currDepth]
	for _, sym := range activeSymbols {
		for currCount == 0 {
			currDepth++
			currCount = count[currDepth]
		}
		lengths[sym] = byte(currDepth)
		currCount--
	}
}

// generateCodes generates bit-level Huffman codes based on their lengths
func generateCodes(lengths []byte, codes []uint32) {
	var nextCode [17]uint32
	var code uint32 = 0

	var count [17]uint32
	for _, l := range lengths {
		if l > 0 {
			count[l]++
		}
	}

	for bits := 1; bits <= 16; bits++ {
		code = (code + count[bits-1]) << 1
		nextCode[bits] = code
	}

	for i, l := range lengths {
		if l > 0 {
			// Reverse bits for writing (Deflate requires LSB-first format)
			codes[i] = reverseBits(nextCode[l], l)
			nextCode[l]++
		} else {
			codes[i] = 0
		}
	}
}

func reverseBits(code uint32, length byte) uint32 {
	var rev uint32 = 0
	for i := byte(0); i < length; i++ {
		rev |= (code & 1) << (length - 1 - i)
		code >>= 1
	}
	return rev
}
