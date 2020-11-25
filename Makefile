build-linux:
	GOOS=linux GOARCH=amd64 go build -o zserver

build-mac:
	GOOS=darwin GOARCH=amd64 go build -o zserver

clean:
	rm zserver
