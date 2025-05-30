# NotifyGate Makefile

# Variables
APP_NAME := notifygate
VERSION := 1.0.0
BUILD_DIR := build
BINARY_NAME := $(APP_NAME)
DOCKER_IMAGE := $(APP_NAME):$(VERSION)

# Go related variables
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Build flags
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(shell date -u '+%Y-%m-%d_%H:%M:%S')"

.PHONY: all build clean test coverage deps docker help dev prod logs

# Default target
all: clean deps test build

# Build the application
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/apisrv/main.go
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/apisrv/main.go
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 cmd/apisrv/main.go
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/apisrv/main.go
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 cmd/apisrv/main.go
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe cmd/apisrv/main.go
	@echo "Multi-platform build complete"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Development commands
dev: deps
	@echo "Starting development server..."
	$(GOCMD) run cmd/apisrv/main.go

# Start with file watching (requires air)
dev-watch:
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	@echo "Starting development server with hot reload..."
	air

# Database commands
db-migrate:
	@echo "Running database migrations..."
	$(GOCMD) run cmd/apisrv/main.go --migrate-only

db-seed:
	@echo "Seeding database..."
	$(GOCMD) run cmd/apisrv/main.go --seed-only

db-reset:
	@echo "Resetting database..."
	$(GOCMD) run cmd/apisrv/main.go --reset-db

# Docker commands
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .
	docker tag $(DOCKER_IMAGE) $(APP_NAME):latest

docker-run:
	@echo "Running Docker container..."
	docker run -p 8080:8080 --env-file .env $(DOCKER_IMAGE)

# Docker Compose commands
up:
	@echo "Starting services with Docker Compose..."
	docker-compose up -d

down:
	@echo "Stopping services..."
	docker-compose down

restart: down up

logs:
	@echo "Showing logs..."
	docker-compose logs -f notifygate

logs-db:
	@echo "Showing database logs..."
	docker-compose logs -f postgres

# Production deployment
prod:
	@echo "Starting production deployment..."
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

prod-down:
	@echo "Stopping production deployment..."
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml down

# Database admin
admin:
	@echo "Starting with admin tools..."
	docker-compose --profile admin up -d

# Redis support
redis:
	@echo "Starting with Redis support..."
	docker-compose --profile redis up -d

# Health check
health:
	@echo "Checking application health..."
	@curl -f http://localhost:8080/health || echo "Health check failed"

# Generate environment file
env:
	@echo "Generating .env file from template..."
	@if [ ! -f .env ]; then cp .env.example .env; echo ".env file created from template"; else echo ".env file already exists"; fi

# Setup for development
setup: env deps build
	@echo "Development setup complete!"
	@echo "1. Configure your .env file with OAuth2 credentials"
	@echo "2. Run 'make up' to start with Docker"
	@echo "3. Or run 'make dev' for local development"

# Install development tools
tools:
	@echo "Installing development tools..."
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Tools installed: air, golangci-lint"

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	$(GOCMD) vet ./...

# Security check
security:
	@echo "Running security check..."
	@which gosec > /dev/null || go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	gosec ./...

# Full code quality check
quality: fmt vet lint test
	@echo "Code quality check complete"

# Backup database (Docker)
backup:
	@echo "Creating database backup..."
	@mkdir -p backups
	docker-compose exec postgres pg_dump -U notifygate_user notifygate > backups/backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "Backup created in backups/ directory"

# Restore database (Docker)
restore:
	@echo "Restoring database from backup..."
	@read -p "Enter backup file path: " backup_file; \
	docker-compose exec -T postgres psql -U notifygate_user notifygate < $$backup_file

# Help
help:
	@echo "NotifyGate Makefile Commands:"
	@echo ""
	@echo "Development:"
	@echo "  setup          - Initial development setup"
	@echo "  dev            - Start development server"
	@echo "  dev-watch      - Start development server with hot reload"
	@echo "  test           - Run tests"
	@echo "  coverage       - Run tests with coverage"
	@echo ""
	@echo "Building:"
	@echo "  build          - Build binary"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  clean          - Clean build artifacts"
	@echo ""
	@echo "Docker:"
	@echo "  up             - Start services with Docker Compose"
	@echo "  down           - Stop services"
	@echo "  restart        - Restart services"
	@echo "  logs           - Show application logs"
	@echo "  logs-db        - Show database logs"
	@echo ""
	@echo "Production:"
	@echo "  prod           - Start production deployment"
	@echo "  prod-down      - Stop production deployment"
	@echo ""
	@echo "Database:"
	@echo "  db-migrate     - Run database migrations"
	@echo "  db-seed        - Seed database with initial data"
	@echo "  db-reset       - Reset database"
	@echo "  backup         - Backup database"
	@echo "  restore        - Restore database from backup"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt            - Format code"
	@echo "  vet            - Vet code"
	@echo "  lint           - Run linter"
	@echo "  security       - Run security check"
	@echo "  quality        - Run all code quality checks"
	@echo ""
	@echo "Utilities:"
	@echo "  env            - Generate .env file"
	@echo "  tools          - Install development tools"
	@echo "  health         - Check application health"
	@echo "  admin          - Start with admin tools"
	@echo "  redis          - Start with Redis support"
	@echo "  help           - Show this help message"