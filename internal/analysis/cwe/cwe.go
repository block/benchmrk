// Package cwe answers "are these two CWE IDs talking about the same thing?"
// for the benchmark matcher. A scanner reports CWE-862 where the annotation
// says CWE-639; both are authorization flaws under CWE-285, and a matcher
// that compares strings misses this.
//
// Three signals, any one of which counts as "related":
//
//   - Ancestor tree. ChildOf edges under MITRE's View 1000 (Research
//     Concepts — the primary abstraction hierarchy). Two CWEs that share
//     a non-pillar ancestor within a combined depth budget are related.
//     Catches 639↔862 (meet at 285), 331↔330 (direct parent), 328↔327
//     (meet under 693 but that's a pillar — category saves this one).
//
//   - Shared category. MITRE's orthogonal groupings — OWASP Top 10 slices,
//     SFP clusters, CISQ quality characteristics. Two CWEs in the same
//     category are MITRE-endorsed "same thing from a different angle."
//
//   - Curated pairs. Cause→effect and mechanism↔consequence relationships
//     the tree doesn't encode. Mass assignment (915) CAUSES privilege
//     escalation (269) when the assignable field is role — MITRE models
//     these as unrelated because one is a Base weakness and the other is
//     a Class under a different pillar. Small hand-maintained list; grow
//     it when a benchmark surfaces a new pair.
//
// Tree and category data are generated from the MITRE XML (see data_gen.go
// and the go:generate directive). The curated list lives here so it shows
// up in diffs.
package cwe

import (
	"strconv"
	"strings"
)

//go:generate go run ./gen -src $CWE_XML -out data_gen.go

// Unrelated is the Distance sentinel for "no link within budget."
const Unrelated = -1

// Normalize extracts the numeric ID from any of the common CWE string forms:
// "CWE-89", "cwe-89", "CWE-89: SQL Injection", "89". Returns (0, false) for
// anything that doesn't parse to a positive integer after stripping.
//
// The benchmark matcher previously compared CWE strings byte-for-byte, so
// "CWE-89" from an annotation never matched "CWE-89: Improper Neutralization
// of..." from a SARIF rule ID. Normalize both sides before comparing.
func Normalize(s string) (int, bool) {
	s = strings.TrimSpace(s)
	// Cut at ":" — MITRE's canonical form is "CWE-N: Name", and SARIF rule
	// IDs often carry the full thing.
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	// Strip the prefix regardless of case and regardless of whether the
	// hyphen is there ("CWE89" shows up in the wild).
	if len(s) >= 3 && (s[:3] == "CWE" || s[:3] == "cwe" || s[:3] == "Cwe") {
		s = strings.TrimLeft(s[3:], "-_ ")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// Distance reports how closely two CWE IDs are related:
//
//	0   identical
//	1   direct parent/child, or a curated pair
//	2   siblings (same direct parent), or two hops in the tree,
//	    or shared MITRE category
//	3+  common ancestor at combined depth N
//	-1  no link within maxDepth hops, or either ID unknown
//
// Pillars (the ~10 top-level abstractions like 284 "Improper Access
// Control" and 707 "Improper Neutralization") don't count as common
// ancestors — everything is under a pillar, so meeting there is noise.
//
// maxDepth caps the combined hop count. 3 is a sensible default: it reaches
// siblings-of-siblings but stops before the tree's upper reaches where
// everything starts looking related.
func Distance(a, b, maxDepth int) int {
	if a == b {
		return 0
	}
	if a <= 0 || b <= 0 {
		return Unrelated
	}

	// Curated pairs are distance 1 regardless of where the tree puts them.
	// Checked first because it's O(1) and the tree walk is O(depth).
	if hasCuratedLink(a, b) {
		return 1
	}

	// Walk both chains up to maxDepth hops. depth[id] = hops from a.
	// ~970 CWEs, max chain length ~7, so this is trivially fast.
	depthA := ancestorDepths(a, maxDepth)
	depthB := ancestorDepths(b, maxDepth)

	best := Unrelated
	for id, da := range depthA {
		if isPillar(id) {
			continue
		}
		db, ok := depthB[id]
		if !ok {
			continue
		}
		if d := da + db; d <= maxDepth && (best == Unrelated || d < best) {
			best = d
		}
	}
	if best != Unrelated {
		return best
	}

	// Shared category is coarser than the tree — distance 2 reflects
	// "MITRE groups these together, but they're not hierarchically close."
	// Checked last so a tighter tree relationship wins.
	if 2 <= maxDepth && sharesCategory(a, b) {
		return 2
	}

	return Unrelated
}

// Related is the convenience predicate the matcher actually calls.
func Related(a, b, maxDepth int) bool {
	return Distance(a, b, maxDepth) != Unrelated
}

// ancestorDepths walks the ChildOf chain from id upward, returning
// {id: 0, parent: 1, grandparent: 2, ...} up to limit hops. The self
// entry at depth 0 lets the caller find "a is an ancestor of b" as a
// zero-cost-on-one-side meeting point.
func ancestorDepths(id, limit int) map[int]int {
	out := make(map[int]int, limit+1)
	for d := 0; d <= limit; d++ {
		if _, seen := out[id]; seen {
			break // cycle guard (284 → 284 appears in the raw data)
		}
		out[id] = d
		p := parentOf(id)
		if p == 0 {
			break
		}
		id = p
	}
	return out
}

// sharesCategory checks whether two CWEs appear in any common MITRE
// category. categoriesOf values are sorted (the generator guarantees it),
// so this is a two-pointer intersection — no allocation, linear in the
// shorter list.
func sharesCategory(a, b int) bool {
	ca, cb := categoriesOf[a], categoriesOf[b]
	i, j := 0, 0
	for i < len(ca) && j < len(cb) {
		switch {
		case ca[i] < cb[j]:
			i++
		case ca[i] > cb[j]:
			j++
		default:
			return true
		}
	}
	return false
}

// pillars are the View 1000 top-level abstractions. Every weakness sits
// under one of these, so a common ancestor here tells you nothing — it's
// the equivalent of "both are bugs." The tree walk skips them.
//
// This list is stable across CWE releases; MITRE calls them "Pillar"
// abstraction level.
var pillars = map[int]bool{
	284:  true, // Improper Access Control
	435:  true, // Improper Interaction Between Multiple Entities
	664:  true, // Improper Control of a Resource Through its Lifetime
	682:  true, // Incorrect Calculation
	691:  true, // Insufficient Control Flow Management
	693:  true, // Protection Mechanism Failure
	697:  true, // Incorrect Comparison
	703:  true, // Improper Check or Handling of Exceptional Conditions
	707:  true, // Improper Neutralization
	710:  true, // Improper Adherence to Coding Standards
	1000: true, // Research Concepts root
}

func isPillar(id int) bool { return pillars[id] }

// curated holds mechanism↔consequence pairs the MITRE tree doesn't link.
// These come from real benchmark mismatches: a scanner reported the
// mechanism (how the bug works) where the annotator tagged the consequence
// (what it lets you do), or vice versa. Both are correct; they're looking
// at the same code from different angles.
//
// Add to this list when a benchmark surfaces a same-line/near-line CWE
// drift that neither the tree nor the category set catches. Keep it
// tight — each entry is an assertion that two CWEs are "the same finding"
// for scoring purposes.
//
// Stored one-directional, checked both ways.
var curated = map[int][]int{
	// Mass assignment (the mechanism) is how you GET privilege escalation
	// (the consequence) when the assignable field is role/is_admin. MITRE
	// puts 915 under 913→664 and 269 under 284 — different pillars.
	915: {269},

	// JWT alg:none: 347 is the precise mechanism (signature not verified),
	// 287 is the resulting authentication bypass. Both correct for the
	// same line of code. 347→345→693; 287→284.
	347: {287},

	// Password change without current-password verification: the annotation
	// tags it 352 (CSRF — the attack that exploits it), the scanner tags it
	// 620 (the weakness itself). 620→1390→287→284; 352→345→693.
	620: {352},

	// 862 (no authz check at all) vs 863 (wrong authz check) vs 639 (IDOR —
	// authz on the wrong key). Scanners rarely distinguish and annotators
	// pick by taste. The tree already links 639↔862 through 285, but
	// 862↔863 don't meet until 284 (pillar). Make them all adjacent.
	862: {863, 639},
	863: {639},

	// 328 (reversible hash) and 327 (broken algo) both apply to MD5
	// password hashing. Tree puts them under 693 (pillar); categories
	// link them, but keep this explicit since it's the most common
	// crypto-CWE bikeshed.
	328: {327},
}

func hasCuratedLink(a, b int) bool {
	for _, x := range curated[a] {
		if x == b {
			return true
		}
	}
	for _, x := range curated[b] {
		if x == a {
			return true
		}
	}
	return false
}
