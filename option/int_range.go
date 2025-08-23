package option

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

type IntRange struct {
	Min int
	Max int
}

func (r IntRange) String() string {
	return fmt.Sprintf("%d-%d", r.Min, r.Max)
}

func (r IntRange) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *IntRange) UnmarshalJSON(data []byte) error {
	var rangeStr string
	if err := json.Unmarshal(data, &rangeStr); err != nil {
		return fmt.Errorf("failed to unmarshal range as string: %v", err)
	}

	parsed, err := ParseIntRange(rangeStr)
	if err != nil {
		return fmt.Errorf("failed to parse range '%s': %v", rangeStr, err)
	}

	*r = *parsed
	return nil
}

// ParseIntRange parses a range string. It accepts:
//   - "start-end"  → Min = start, Max = end
//   - "value"      → Min = Max = value
func ParseIntRange(rangeStr string) (*IntRange, error) {
	// Trim surrounding whitespace once – it also covers cases like " 5 - 10 ".
	s := strings.TrimSpace(rangeStr)

	// Split on '-' only if the delimiter is present.
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)

		startStr := strings.TrimSpace(parts[0])
		endStr := strings.TrimSpace(parts[1])

		start, err := strconv.Atoi(startStr)
		if err != nil {
			return nil, fmt.Errorf("invalid start value '%s': %w", startStr, err)
		}
		end, err := strconv.Atoi(endStr)
		if err != nil {
			return nil, fmt.Errorf("invalid end value '%s': %w", endStr, err)
		}
		if start > end {
			return nil, fmt.Errorf("invalid range: start (%d) cannot be greater than end (%d)", start, end)
		}
		return &IntRange{Min: start, Max: end}, nil
	}

	// No dash → treat the whole string as a single number.
	val, err := strconv.Atoi(s)
	if err != nil {
		return nil, fmt.Errorf("invalid integer value '%s': %w", s, err)
	}
	return &IntRange{Min: val, Max: val}, nil
}

// Random returns a fast pseudo‑random int in [Min, Max].
func (r IntRange) Random() int {
	min, max := r.Min, r.Max
	if min > max {
		min, max = max, min
	}
	if min == max {
		return min
	}
	return rand.Intn(max-min+1) + min
}
