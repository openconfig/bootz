package main

var (
	port = pflags.StringVar("")
)

func main() {
	c, err := service.New()
	if err != nil {
		log.Errorf("Failed to start server: %w", err)
	}
	if err := c.Start(); err != nil {
		log.Fatalf("Server exited: %w", err)
	}
}
