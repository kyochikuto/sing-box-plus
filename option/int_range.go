package option

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type IntRange struct {
	Start int
	End   int
}

func (r IntRange) String() string {
	return fmt.Sprintf("%d-%d", r.Start, r.End)
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

// ParseIntRange parses a string into an IntRange
func ParseIntRange(rangeStr string) (*IntRange, error) {
	parts := strings.Split(rangeStr, "-")

	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: expected 'start-end', got '%s'", rangeStr)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid start value '%s': %v", parts[0], err)
	}

	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end value '%s': %v", parts[1], err)
	}

	if start > end {
		return nil, fmt.Errorf("invalid range: start (%d) cannot be greater than end (%d)", start, end)
	}

	return &IntRange{
		Start: start,
		End:   end,
	}, nil
}
