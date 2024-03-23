lint:
	gofumpt -l -w .
	golangci-lint --color always run

gofumpt:
	gofumpt -l -w .