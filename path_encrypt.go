package awskms

import (
	"context"
	"encoding/base64"
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
)

func (b *backend) pathEncrypt() *framework.Path {
	fmt.Println("This is test on 4/16/2020-awskms pathEncrypt()")
	return &framework.Path{
		Pattern: "encrypt/" + framework.GenericNameRegex("key"),

		HelpSynopsis: "Encrypt a plaintext value using a named key",
		HelpDescription: `
Use the named encryption key to encrypt an arbitrary plaintext string. The
response will be the base64-encoded encrypted value (ciphertext).
`,

		Fields: map[string]*framework.FieldSchema{
			"key": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Name of the key in Vault to use for encryption. This key must already exist in
Vault and must map back to a Google Cloud KMS key.
`,
			},

			"additional_authenticated_data": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Optional base64-encoded data that, if specified, must also be provided to
decrypt this payload.
`,
			},

			"key_version": &framework.FieldSchema{
				Type: framework.TypeInt,
				Description: `
Integer version of the crypto key version to use for encryption. If unspecified,
this defaults to the latest active crypto key version.
`,
			},

			"plaintext": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
Plaintext value to be encrypted. This can be a string or binary, but the size
is limited. See the Google Cloud KMS documentation for information on size
limitations by key types.
`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathEncryptWrite),
			logical.UpdateOperation: withFieldValidator(b.pathEncryptWrite),
		},
	}
}

// pathEncryptWrite corresponds to PUT/POST awskms/encrypt/:key and is
// used to encrypt the plaintext string using the named key.
func (b *backend) pathEncryptWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	fmt.Println("This is test on 4/16/2020-awskms pathEncryptWrite()")
	key := d.Get("key").(string)
	fmt.Println("Encrypting using awskms key: "+key)
	// aad := d.Get("additional_authenticated_data").(string)
	plaintext := d.Get("plaintext").(string)
	keyVersion := d.Get("key_version").(int)

	data, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Request body: %s\n", data)

	k, err := b.Key(ctx, req.Storage, key)
	if err != nil {
		if err == ErrKeyNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}

	cryptoKey := k.CryptoKeyID
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
	}

	/*kmsClient, closer, err := b.KMSClient(req.Storage)
	if err != nil {
		return nil, err
	}
	defer closer()

	resp, err := kmsClient.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        cryptoKey,
		Plaintext:                   []byte(plaintext),
		AdditionalAuthenticatedData: []byte(aad),
	})
	if err != nil {
		return nil, errwrap.Wrapf("failed to encrypt plaintext: {{err}}", err)
	}*/

	os.Setenv("AWS_ACCESS_KEY_ID","AKIAICPWGJX5GPZUPH3A")
	os.Setenv("AWS_SECRET_ACCESS_KEY","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")

	// Initialize a session in us-west-2 that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials.
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
		CredentialsChainVerboseErrors:aws.Bool(true)},
	)

	// Create KMS service client
	svc := kms.New(sess)
	resp, err := sess.Config.Credentials.Get()
	fmt.Println("111111",resp,err)
	keyId := "arn:aws:kms:us-west-2:679498570023:key/0e97f126-e466-4c1f-bb70-0187b86329c4"


	// Encrypt the data
	result, err := svc.Encrypt(&kms.EncryptInput{
		KeyId: aws.String(keyId),
		Plaintext: []byte(plaintext),
	})

	if err != nil {
		fmt.Println("Got error aws kms encrypting data: ", err)
	}

	fmt.Println("Blob (base-64 byte array):")
	fmt.Println(result.GoString())
	fmt.Println(result.CiphertextBlob)
	base := base64.StdEncoding.EncodeToString(result.CiphertextBlob)
	fmt.Println("awskms encryption string: "+base)

	return &logical.Response{
		Data: map[string]interface{}{
			"key_id": result.KeyId,
			"ciphertext":  base,
		},
	}, nil
}
