package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/Diniboy1123/usque/models"
)

func TestRegistrationRejectsIncompleteResponses(t *testing.T) {
	for _, account := range []*models.AccountData{nil, {}, {Config: models.Config{Peers: []models.Peer{{}}}}} {
		if _, err := registrationConfig(account, "test-token", nil); err == nil {
			t.Fatal("accepted incomplete enrollment")
		}
	}
}

func TestRegistrationErrorsDoNotEchoCredentials(t *testing.T) {
	for _, source := range []error{errors.New("private-token-marker"), &models.APIError{Errors: []models.ErrorInfo{{Code: 1001, Message: "private-token-marker"}}}} {
		err := registrationFailure("enroll", source)
		if strings.Contains(err.Error(), "private-token-marker") {
			t.Fatal("registration error leaked credential")
		}
		if !strings.Contains(err.Error(), "usquectl register") {
			t.Fatal("missing recovery guidance")
		}
	}
}
