package main

import (
	"sort"
	"strings"
)

const chainThreshold = 15

// detectChains uses subset sum to find combinations of 2-4 correlated findings
// whose combined severity scores reach chainThreshold. Once a combination
// qualifies, it is recorded and the search stops extending it — this surfaces
// minimal attack paths rather than all qualifying supersets.
func detectChains(findings []Finding) []AttackChain {
	var candidates []Finding
	for _, f := range findings {
		if f.Severity != Info {
			candidates = append(candidates, f)
		}
	}
	n := len(candidates)

	var chains []AttackChain

	var search func(start, scoreSum int, current []Finding)
	search = func(start, scoreSum int, current []Finding) {
		if len(current) > 4 {
			return
		}
		if scoreSum >= chainThreshold && len(current) >= 2 {
			shared := make([]string, len(current[0].Tags))
			copy(shared, current[0].Tags)
			for _, f := range current[1:] {
				shared = intersection(shared, f.Tags)
			}
			var meaningful []string
			for _, t := range shared {
				if t != "port-scan" && t != "http" && t != "https" {
					meaningful = append(meaningful, t)
				}
			}
			if len(meaningful) > 0 {
				chain := AttackChain{TotalScore: scoreSum, SharedTags: meaningful}
				for _, f := range current {
					chain.FindingIDs = append(chain.FindingIDs, f.ID)
					chain.Titles = append(chain.Titles, f.Title)
				}
				chains = append(chains, chain)
			}
			return // don't extend qualifying chains further
		}
		for i := start; i < n; i++ {
			score := candidates[i].Severity.Score()
			search(i+1, scoreSum+score, append(current, candidates[i]))
		}
	}

	for i := 0; i < n; i++ {
		search(i+1, candidates[i].Severity.Score(), []Finding{candidates[i]})
	}

	seen := map[string]bool{}
	var unique []AttackChain
	for _, c := range chains {
		sort.Strings(c.FindingIDs)
		key := strings.Join(c.FindingIDs, "|")
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}

	sort.Slice(unique, func(i, j int) bool {
		return unique[i].TotalScore > unique[j].TotalScore
	})
	if len(unique) > 10 {
		unique = unique[:10]
	}
	return unique
}
