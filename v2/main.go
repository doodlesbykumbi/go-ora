package go_ora

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
)

func Mainx() {
	username := "sys"
	password := "password123"

	VerifierType := 18453
	pbkdf2VgenCount := 4096
	pbkdf2SderCount := 3
	pbkdf2ChkSalt := "446D85778A1975ADB9D7FA8BA9E49404"
	ServerCompileTimeCaps := []byte{0, 0, 0, 0, 32}

	Salt := "BB918465B54C07B5D31CD27E850D40B8"
	EServerSessKey := "31C9ECB85CA8DAA36908A24E14849283A4287C1973F6FBB2936D057FE311330A"
	EClientSessKey := "070E37FD4762BB80F541FC29DF604DC152FB958C828688C0509597AA039C470C"
	EPassword := "A6DE770E3ABDBA329D82C36195CA4DA84CE81C043F0A71683FE29FE5BB1A79D1"

	VerifierType = 6949
	pbkdf2VgenCount = 0
	pbkdf2SderCount = 0
	pbkdf2ChkSalt = ""
	ServerCompileTimeCaps = []byte{0, 0, 0, 0, 0}
	Salt = "3438638EA939C83C05F1"
	EServerSessKey = "34E0C658A498587F5F9FA0522EE368948655F87737BE077970C3200D155F88A37BA1A6B5A9AE5189479D3D1A123DA95E"
	EClientSessKey = "84F94024BF161814048D153781EE3835F1E4E60ABDE37A9C66D6E27133B4A8F050EF13CD51C3C271D80B43143BED2058"
	EPassword = "9EEED15ABA50E2F321E4A782919FF1E9D90EC0E04DD8E06B8B71217DCE138814"

	var key []byte
	var speedyKey []byte
	padding := false
	var err error

	if VerifierType == 2361 {
		key, err = getKeyFromUserNameAndPassword(username, password)
		if err != nil {
			panic(err)
		}

	} else if VerifierType == 6949 {

		if ServerCompileTimeCaps[4]&2 == 0 {
			padding = true
		}
		result, err := hex.DecodeString(Salt)
		if err != nil {
			panic(err)
		}
		result = append([]byte(password), result...)
		hash := sha1.New()
		_, err = hash.Write(result)
		if err != nil {
			panic(err)
		}
		key = hash.Sum(nil)           // 20 byte key
		key = append(key, 0, 0, 0, 0) // 24 byte key
	} else if VerifierType == 18453 {
		salt, err := hex.DecodeString(Salt)
		if err != nil {
			panic(err)
		}
		message := append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
		speedyKey = generateSpeedyKey(message, []byte(password), pbkdf2VgenCount)

		buffer := append(speedyKey, salt...)
		hash := sha512.New()
		hash.Write(buffer)
		key = hash.Sum(nil)[:32]
	} else {
		panic(errors.New("unsupported verifier type"))
	}
	// get the server session key
	ServerSessKey, err := decryptSessionKey(padding, key, EServerSessKey)
	if err != nil {
		panic(err)
	}

	// // note if serverSessKey length is less than the expected length according to verifier generate random one
	// // generate new key for client
	// ClientSessKey := make([]byte, len(ServerSessKey))
	// for {
	// 	_, err = rand.Read(ret.ClientSessKey)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if !bytes.Equal(ret.ClientSessKey, ret.ServerSessKey) {
	// 		break
	// 	}
	// }

	ClientSessKey, err := decryptSessionKey(padding, key, EClientSessKey)

	// // encrypt the client key
	// ret.EClientSessKey, err = encryptSessionKey(padding, key, ret.ClientSessKey)
	// if err != nil {
	// 	return nil, err
	// }

	newKey, err := generatePasswordEncKey(
		ServerSessKey,
		ClientSessKey,
		pbkdf2SderCount,
		pbkdf2ChkSalt,
		ServerCompileTimeCaps,

		VerifierType)
	// // get the hash key form server and client session key
	// newKey, err := ret.generatePasswordEncKey()
	if err != nil {
		panic(err)
	}
	if VerifierType == 18453 {
		padding = false
	} else {
		padding = true
	}

	Password, err := decryptSessionKey(true, newKey, EPassword)
	fmt.Println(string(Password[0x10:]))

	// TODO: this can change length and so has an impact on the rest of the bytes
	// NewEPassword, err := encryptPassword([]byte("password"), newKey, true)
	// fmt.Println(len(NewEPassword))
	// // encrypt the password
	// ret.EPassword, err = encryptPassword([]byte(password), newKey, true)
	// if err != nil {
	// 	return nil, err
	// }
	// if ret.VerifierType == 18453 {
	// 	ret.ESpeedyKey, err = encryptPassword(speedyKey, newKey, padding)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	// return ret, nil
}

func Mainy() {
	EPassword, EClientSessKey := ReEncryptPassword(
		"sys",
		"password123",
		"34E0C658A498587F5F9FA0522EE368948655F87737BE077970C3200D155F88A37BA1A6B5A9AE5189479D3D1A123DA95E",
		"3438638EA939C83C05F1",
		"84F94024BF161814048D153781EE3835F1E4E60ABDE37A9C66D6E27133B4A8F050EF13CD51C3C271D80B43143BED2058",
		"9EEED15ABA50E2F321E4A782919FF1E9D90EC0E04DD8E06B8B71217DCE138814",
	)

	fmt.Println(EPassword, EClientSessKey)
}

func ReEncryptPassword(username, password, EServerSessKey, Salt, EClientSessKey, EPassword string) (string, string) {
	// Static
	VerifierType := 6949
	ServerCompileTimeCaps := []byte{0, 0, 0, 0, 0}

	// Dummy
	pbkdf2VgenCount := 0
	pbkdf2SderCount := 0
	pbkdf2ChkSalt := ""

	var key []byte
	var speedyKey []byte
	padding := false
	var err error

	if VerifierType == 2361 {
		key, err = getKeyFromUserNameAndPassword(username, password)
		if err != nil {
			panic(err)
		}

	} else if VerifierType == 6949 {

		if ServerCompileTimeCaps[4]&2 == 0 {
			padding = true
		}
		result, err := hex.DecodeString(Salt)
		if err != nil {
			panic(err)
		}
		result = append([]byte(password), result...)
		hash := sha1.New()
		_, err = hash.Write(result)
		if err != nil {
			panic(err)
		}
		key = hash.Sum(nil)           // 20 byte key
		key = append(key, 0, 0, 0, 0) // 24 byte key
	} else if VerifierType == 18453 {
		salt, err := hex.DecodeString(Salt)
		if err != nil {
			panic(err)
		}
		message := append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
		speedyKey = generateSpeedyKey(message, []byte(password), pbkdf2VgenCount)

		buffer := append(speedyKey, salt...)
		hash := sha512.New()
		hash.Write(buffer)
		key = hash.Sum(nil)[:32]
	} else {
		panic(errors.New("unsupported verifier type"))
	}
	// get the server session key
	ServerSessKey, err := decryptSessionKey(padding, key, EServerSessKey)
	if err != nil {
		panic(err)
	}

	// // note if serverSessKey length is less than the expected length according to verifier generate random one
	// // generate new key for client
	GenClientSessKey := make([]byte, len(ServerSessKey))
	for {
		_, err = rand.Read(GenClientSessKey)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(GenClientSessKey, ServerSessKey) {
			break
		}
	}

	// // encrypt the client key
	GenEClientSessKey, err := encryptSessionKey(false, key, GenClientSessKey)
	if err != nil {
		panic(err)
	}

	ClientSessKey, err := decryptSessionKey(padding, key, EClientSessKey)
	if err != nil {
		panic(err)
	}

	useGen := true
	if useGen {
		EClientSessKey = GenEClientSessKey
		ClientSessKey = GenClientSessKey
	}
	// // get the hash key form server and client session key
	// newKey, err := ret.generatePasswordEncKey()
	newKey, err := generatePasswordEncKey(
		ServerSessKey,
		ClientSessKey,
		pbkdf2SderCount,
		pbkdf2ChkSalt,
		ServerCompileTimeCaps,
		VerifierType)
	if err != nil {
		panic(err)
	}
	if VerifierType == 18453 {
		padding = false
	} else {
		padding = true
	}

	Password, err := decryptSessionKey(true, newKey, EPassword)
	fmt.Println(string(Password[0x10:]))

	// encrypt the password
	NewEPassword, err := encryptPassword([]byte(password), newKey, true)
	if err != nil {
		panic(err)
	}

	return EClientSessKey, NewEPassword
	// if ret.VerifierType == 18453 {
	// 	ret.ESpeedyKey, err = encryptPassword(speedyKey, newKey, padding)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	// return ret, nil
}

func generatePasswordEncKey(
	ServerSessKey,
	ClientSessKey []byte,
	pbkdf2SderCount int,
	pbkdf2ChkSalt string,
	ServerCompileTimeCaps []byte,
	VerifierType int) ([]byte, error) {
	hash := md5.New()
	key1 := ServerSessKey
	key2 := ClientSessKey
	start := 16

	logonCompatibility := ServerCompileTimeCaps[4]
	if logonCompatibility&32 != 0 {
		var keyBuffer string
		var retKeyLen int
		switch VerifierType {
		case 2361:
			buffer := append(key2[:len(key2)/2], key1[:len(key1)/2]...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 16
		case 6949:
			buffer := append(key2[:24], key1[:24]...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 24
		case 18453:
			buffer := append(key2, key1...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 32
		default:
			return nil, errors.New("unsupported verifier type")
		}
		df2key, err := hex.DecodeString(pbkdf2ChkSalt)
		if err != nil {
			return nil, err
		}
		return generateSpeedyKey(df2key, []byte(keyBuffer), pbkdf2SderCount)[:retKeyLen], nil
	} else {
		switch VerifierType {
		case 2361:
			buffer := make([]byte, 16)
			for x := 0; x < 16; x++ {
				buffer[x] = key1[x+start] ^ key2[x+start]
			}
			_, err := hash.Write(buffer)
			if err != nil {
				return nil, err
			}
			return hash.Sum(nil), nil
		case 6949:
			buffer := make([]byte, 24)
			for x := 0; x < 24; x++ {
				buffer[x] = key1[x+start] ^ key2[x+start]
			}
			_, err := hash.Write(buffer[:16])
			if err != nil {
				return nil, err
			}
			ret := hash.Sum(nil)
			hash.Reset()
			_, err = hash.Write(buffer[16:])
			if err != nil {
				return nil, err
			}
			ret = append(ret, hash.Sum(nil)...)
			return ret[:24], nil
		default:
			return nil, errors.New("unsupported verifier type")
		}

	}
}
