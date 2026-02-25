package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	// splitAuth := strings.Fields(authHeader)
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", errors.New("malformed authorization header")
	}

	// Проверяем, что после префикса действительно есть значение
	// splitAuth[1] может быть пустым, но strings.Fields не вернет пустые строки
	if splitAuth[1] == "" {
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}
