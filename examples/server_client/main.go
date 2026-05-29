package main

import (
	"context"
	"fmt"
	"log"

	globiguard "github.com/globiguard/globiguard-go"
)

func main() {
	client, err := globiguard.NewServerClient(globiguard.ClientConfig{
		Environment: globiguard.EnvironmentSandbox,
		Services: map[string]string{
			"controlPlane": "https://api.globiguard.com",
		},
		Credential: globiguard.SecretCredential(
			"proj_example",
			"ggsk_example_replace_me",
			globiguard.EnvironmentSandbox,
		),
	})
	if err != nil {
		log.Fatal(err)
	}

	decision, err := client.GovernedActions.AuthorizeActionOrThrow(context.Background(), map[string]any{
		"actionType": "refund",
		"actor":      map[string]any{"id": "user_123"},
		"target":     map[string]any{"id": "order_456"},
		"reason":     "Customer support refund approval",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", decision)
}
