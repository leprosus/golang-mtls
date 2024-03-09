lint:
	golangci-lint --color always run

gofumpt-all:
	gofumpt -l -w .