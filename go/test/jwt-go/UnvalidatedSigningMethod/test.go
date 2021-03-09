package ghas_bootcamp

import "github.com/dgrijalva/jwt-go"

func unvalidated_case() {
	token, err := jwt.ParseWithClaims(tokenString, &OctoClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(configuration.Secret), nil
	})

	if err != nil {
		log.Printf("AuthN: Invalid token %s", err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
}

func validated_case() {
	token, err := jwt.ParseWithClaims(tokenString, &OctoClaims{}, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(configuration.Secret), nil
	})

	if err != nil {
		log.Printf("AuthN: Invalid token %s", err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
}

func inverted_validated_case() {
	token, err := jwt.ParseWithClaims(tokenString, &OctoClaims{}, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			return []byte(configuration.Secret), nil
		}
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	})

	if err != nil {
		log.Printf("AuthN: Invalid token %s", err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
}
