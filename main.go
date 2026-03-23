package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"crypto/ed25519"
	"crypto/rsa"
	"errors"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func init() {
	log.SetFlags(0)
}

func readEntity(keypath string) (*openpgp.Entity, error) {
	f, err := os.Open(keypath)
	if err != nil {
		log.Println("Error opening file")
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		log.Println("decoding")
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}

var (
	UnsupportedKeyType = errors.New("only ed25519 and rsa keys are supported")
)

func getEDDSAKey(castkey *eddsa.PrivateKey) ([]byte, []byte) {
	var pubkey ed25519.PublicKey = castkey.PublicKey.X

	sshPub, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		log.Fatal(err)
	}
	publicSSHKey := ssh.MarshalAuthorizedKey(sshPub)
	log.Println("public SSH key:\n" + string(publicSSHKey))

	var privkey = ed25519.NewKeyFromSeed(castkey.D)

	privPem, err := ssh.MarshalPrivateKey(&privkey, "")
	if err != nil {
		log.Fatal(err)
	}
	privateKeyPem := pem.EncodeToMemory(privPem)
	return privateKeyPem, publicSSHKey
}

func getRSAKey(castkey *rsa.PrivateKey) ([]byte, []byte) {
	var pubkey rsa.PublicKey = castkey.PublicKey

	sshPub, err := ssh.NewPublicKey(&pubkey)
	if err != nil {
		log.Fatal(err)
	}
	publicSSHKey := ssh.MarshalAuthorizedKey(sshPub)
	log.Println("public SSH key:\n" + string(publicSSHKey))

	privPem, err := ssh.MarshalPrivateKey(castkey, "")
	if err != nil {
		log.Fatal(err)
	}
	privateKeyPem := pem.EncodeToMemory(privPem)
	return privateKeyPem, publicSSHKey
}

func saveKeysToFile(baseFilename string, privateKeyPem []byte, publicSSHKey []byte) error {
	privateKeyFile := baseFilename
	if err := os.WriteFile(privateKeyFile, privateKeyPem, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	log.Printf("Private key saved to: %s", privateKeyFile)

	publicKeyFile := baseFilename + ".pub"
	if err := os.WriteFile(publicKeyFile, publicSSHKey, 0644); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}
	log.Printf("Public key saved to: %s", publicKeyFile)

	return nil
}

func main() {
	keyfile := flag.String("f", "./priv.asc", "Path to private PGP key file")
	password := flag.String("p", "", "Passphrase to decrypt PGP key")
	keyIndex := flag.Int("n", -1, "Index of the key to use (0 for primary key)")
	listKeys := flag.Bool("l", false, "List all available keys")
	saveFile := flag.String("s", "", "Save private and public keys to file (e.g., -s ./id_ed25519)")

	flag.Parse()

	if _, err := os.Stat(*keyfile); err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("Error: Private key file not found: %s\n", *keyfile)
		}
		log.Fatalf("Error accessing key file: %v\n", err)
	}

	e, err := readEntity(*keyfile)
	if err != nil {
		log.Fatal(err)
	}

	if *keyIndex == -1 {
		log.Println("Keys:")
		log.Println("[0]", e.PrimaryKey.KeyIdString()+" (primary)")
		for i := 0; i < len(e.Subkeys); i++ {
			log.Println(fmt.Sprintf("[%d]", i+1), e.Subkeys[i].PrivateKey.KeyIdString()+" (subkey)")
		}
	}

	if *listKeys {
		return
	}

	if *keyIndex < 0 || *keyIndex > len(e.Subkeys) {
		log.Fatalf("Invalid key index: %d\n", *keyIndex)
	}

	var targetKey *packet.PrivateKey
	if *keyIndex == 0 {
		log.Println(fmt.Sprintf("Continuing with key [%d]", *keyIndex), e.PrimaryKey.KeyIdString())
		targetKey = e.PrivateKey
	} else {
		var subkey = e.Subkeys[*keyIndex-1]
		log.Println(fmt.Sprintf("Continuing with key [%d]", *keyIndex), subkey.PrivateKey.KeyIdString())
		targetKey = subkey.PrivateKey
	}

	if targetKey.Encrypted {
		var bytePassphrase []byte
		if *password != "" {
			bytePassphrase = []byte(*password)
		} else {
			fmt.Fprint(os.Stderr, "Please enter passphrase to decrypt PGP key: ")
			var err error
			bytePassphrase, err = term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr)
		}
		targetKey.Decrypt(bytePassphrase)
	}

	castkey_eddsa, ok_eddsa := targetKey.PrivateKey.(*eddsa.PrivateKey)
	if ok_eddsa {
		privateKeyPem, publicSSHKey := getEDDSAKey(castkey_eddsa)

		if *saveFile != "" {
			if err := saveKeysToFile(*saveFile, privateKeyPem, publicSSHKey); err != nil {
				log.Fatalf("Error saving keys: %v\n", err)
			}
		} else {
			log.Println("Private SSH key:\n" + string(privateKeyPem))
		}
		return
	}
	castkey_rsa, ok_rsa := targetKey.PrivateKey.(*rsa.PrivateKey)
	if ok_rsa {
		privateKeyPem, publicSSHKey := getRSAKey(castkey_rsa)

		if *saveFile != "" {
			if err := saveKeysToFile(*saveFile, privateKeyPem, publicSSHKey); err != nil {
				log.Fatalf("Error saving keys: %v\n", err)
			}
		} else {
			log.Println("Private SSH key:\n" + string(privateKeyPem))
		}
		return
	}
}
