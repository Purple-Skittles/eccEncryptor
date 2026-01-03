module github.com/Purple-Skittles/encryptor

go 1.25.5

require golang.org/x/crypto v0.29.0

require golang.org/x/sys v0.27.0 // indirect

require eccencryptor/testdata/keys v0.0.0

replace eccencryptor/testdata/keys => ../testData/keys
