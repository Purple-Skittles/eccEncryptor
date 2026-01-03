module github.com/Purple-Skittles/decryptor

go 1.25.5

require golang.org/x/crypto v0.29.0

require golang.org/x/sys v0.27.0 // indirect

require github.com/Purple-Skittles/encryptor v0.0.0

replace github.com/Purple-Skittles/encryptor => ../encryptor

require eccencryptor/testdata/keys v0.0.0

replace eccencryptor/testdata/keys => ../testData/keys
