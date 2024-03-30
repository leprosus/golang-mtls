lint: gofumpt
	golangci-lint --color always run

gofumpt:
	gofumpt -l -w .