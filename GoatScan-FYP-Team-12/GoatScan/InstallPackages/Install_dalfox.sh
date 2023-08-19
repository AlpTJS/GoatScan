# Set Go environment variables (Execute whenever gf is used)
echo "Setting Go environment variables..."
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install gf tool
echo "Installing gf tool..."
go install github.com/hahwul/dalfox/v2@latest
