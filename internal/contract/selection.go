package contract

import (
	"errors"
	"strings"
)

// SelectionError reports that backend selection could not complete.
// Rejected is ordered by selection attempt. Cause reports either the terminal
// failure or [ErrBackendUnavailable] when all candidates were exhausted.
type SelectionError struct {
	Rejected []Rejection
	Cause    error
}

// Error implements error without including service names or secret values.
func (e *SelectionError) Error() string {
	if e == nil {
		return "credential backend selection failed"
	}

	var result strings.Builder
	result.WriteString("credential backend selection failed")
	for _, rejection := range e.Rejected {
		result.WriteString(": ")
		result.WriteString(string(rejection.Backend))
	}
	return result.String()
}

// Unwrap exposes the terminal cause and every backend rejection to errors.Is
// and errors.As.
func (e *SelectionError) Unwrap() []error {
	if e == nil {
		return nil
	}

	errorsList := make([]error, 0, len(e.Rejected)+1)
	if e.Cause != nil {
		errorsList = append(errorsList, e.Cause)
	}
	for _, rejection := range e.Rejected {
		if rejection.Err != nil && !errors.Is(e.Cause, rejection.Err) {
			errorsList = append(errorsList, rejection.Err)
		}
	}
	return errorsList
}
