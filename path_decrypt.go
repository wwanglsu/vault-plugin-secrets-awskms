package awskms

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/aws"
	// "github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	// kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func (b *backend) pathDecrypt() *framework.Path {
	fmt.Println("This is test on 4/16/2020-awskms pathDecrypt()")
	return &framework.Path{
		Pattern: "decrypt/" + framework.GenericNameRegex("key"),

		HelpSynopsis: "Decrypt a ciphertext value using a named key",
		HelpDescription: `
Use the named encryption key to decrypt a ciphertext string previously
encrypted with this same key. The provided ciphertext come from a previous
invocation of the /encrypt endpoint. It is not guaranteed to work with values
encrypted with the same Google Cloud KMS key outside of Vault.
`,

		Fields: map[string]*framework.FieldSchema{
			"key": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Name of the key in Vault to use for decryption. This key must already exist in
Vault and must map back to a Google Cloud KMS key.
`,
			},

			"additional_authenticated_data": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Optional data that was specified during encryption of this payload.
`,
			},

			"ciphertext": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Ciphertext to decrypt as previously returned from an encrypt operation. This
must be base64-encoded ciphertext as previously returned from an encrypt
operation.
`,
			},

			"key_version": &framework.FieldSchema{
				Type: framework.TypeInt,
				Description: `
Integer version of the crypto key version to use for decryption. This is
required for asymmetric keys. For symmetric keys, Cloud KMS will choose the
correct version automatically.
`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathDecryptWrite),
			logical.UpdateOperation: withFieldValidator(b.pathDecryptWrite),
		},
	}
}

// pathDecryptWrite corresponds to PUT/POST awskms/decrypt/:key and is
// used to decrypt the ciphertext string using the named key.
func (b *backend) pathDecryptWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	fmt.Println("This is test on 4/16/2020-awskms pathDecryptWrite()")
	key := d.Get("key").(string)
	// aad := d.Get("additional_authenticated_data").(string)
	// keyVersion := d.Get("key_version").(int)

	data, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("awskms/decrypt/%s, Request body: %s\n", key, data)

	/*k, err := b.Key(ctx, req.Storage, key)
	if err != nil {
		if err == ErrKeyNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}*/

	// We gave the user back base64-encoded ciphertext in the /encrypt payload
	/*ciphertext, err := base64.StdEncoding.DecodeString(d.Get("ciphertext").(string))
	if err != nil {
		return nil, errwrap.Wrapf("failed to base64 decode ciphtertext: {{err}}", err)
	}*/

	/*cryptoKey := k.CryptoKeyID
	if keyVersion > 0 {
		if k.MinVersion > 0 && keyVersion < k.MinVersion {
			resp := fmt.Sprintf("requested version %d is less than minimum allowed version of %d",
				keyVersion, k.MinVersion)
			return logical.ErrorResponse(resp), logical.ErrPermissionDenied
		}

		if k.MaxVersion > 0 && keyVersion > k.MaxVersion {
			resp := fmt.Sprintf("requested version %d is greater than maximum allowed version of %d",
				keyVersion, k.MaxVersion)
			return logical.ErrorResponse(resp), logical.ErrPermissionDenied
		}

		cryptoKey = fmt.Sprintf("%s/cryptoKeyVersions/%d", cryptoKey, keyVersion)
	}*/

	/*kmsClient, closer, err := b.KMSClient(req.Storage)
	if err != nil {
		return nil, err
	}
	defer closer()*/

	// Lookup the key so we can determine the type of decryption (symmetric or
	// asymmetric).
	/*ck, err := kmsClient.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: k.CryptoKeyID,
	})
	if err != nil {
		return nil, errwrap.Wrapf("failed to get underlying crypto key: {{err}}", err)
	}*/

	var plaintext string
	os.Setenv("AWS_ACCESS_KEY_ID","AKIAJYRQDOGKVOVBWUFA")
	os.Setenv("AWS_SECRET_ACCESS_KEY","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")
	// Initialize a session in us-west-2 that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials.
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
		CredentialsChainVerboseErrors:aws.Bool(true)},
	)

	// Create KMS service client
	svc := kms.New(sess)
	_, err = sess.Config.Credentials.Get()
	fmt.Println("awskms decryption ciphertext: ",d.Get("ciphertext").(string))

	// Decrypt the data
	result2, err := svc.Decrypt(&kms.DecryptInput{CiphertextBlob: []byte(d.Get("ciphertext").(string))})

	if err != nil {
		fmt.Println("Got error from aws kms decrypting data: ", err)
	}

	plaintext = string(result2.Plaintext)
	fmt.Println("Decrypted test:", plaintext)

	/*switch ck.Purpose {
	case kmspb.CryptoKey_ASYMMETRIC_DECRYPT:
		if keyVersion == 0 {
			return nil, errMissingFields("key_version")
		}

		resp, err := kmsClient.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
			Name:       cryptoKey,
			Ciphertext: ciphertext,
		})
		if err != nil {
			return nil, errwrap.Wrapf("failed to decrypt ciphertext (asymmetric): {{err}}", err)
		}
		plaintext = string(resp.Plaintext)
	case kmspb.CryptoKey_ENCRYPT_DECRYPT, kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED:
		resp, err := kmsClient.Decrypt(ctx, &kmspb.DecryptRequest{
			Name:                        cryptoKey,
			Ciphertext:                  ciphertext,
			AdditionalAuthenticatedData: []byte(aad),
		})
		if err != nil {
			return nil, errwrap.Wrapf("failed to decrypt ciphertext (symmetric): {{err}}", err)
		}
		plaintext = string(resp.Plaintext)
	case kmspb.CryptoKey_ASYMMETRIC_SIGN:
		return nil, logical.ErrUnsupportedOperation
	}*/

	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": plaintext,
		},
	}, nil
}
