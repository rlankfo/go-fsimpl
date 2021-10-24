package awssmfs

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type fakeClient struct {
	t       *testing.T
	secrets map[string]*testVal
}

var _ SecretsManagerClient = (*fakeClient)(nil)

func (c *fakeClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput,
	optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	c.t.Logf("GetSecretValue(SecretId=%s)", *params.SecretId)

	name := *params.SecretId
	if val, ok := c.secrets[name]; ok {
		out := secretsmanager.GetSecretValueOutput{Name: aws.String(name)}

		if val.b != nil {
			out.SecretBinary = make([]byte, len(val.b))
			copy(out.SecretBinary, val.b)
		} else {
			out.SecretString = aws.String(val.s)
		}

		return &out, nil
	}

	return nil, &types.ResourceNotFoundException{
		Message: aws.String("Secrets Manager can't find the specified secret."),
	}
}

func (c *fakeClient) ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput,
	optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	c.t.Logf("ListSecrets(Filters=%v)", params.Filters)

	nameFilter := ""

	for _, f := range params.Filters {
		if f.Key == "name" {
			nameFilter = f.Values[0]

			break
		}
	}

	secretList := []types.SecretListEntry{}

	for k := range c.secrets {
		cond := strings.HasPrefix(k, nameFilter)
		if strings.HasPrefix(nameFilter, "!") {
			cond = !strings.HasPrefix(k, nameFilter[1:])
		}

		if cond {
			secretList = append(secretList, types.SecretListEntry{
				Name: aws.String(k),
			})
		}
	}

	if params.MaxResults > 0 && len(secretList) > int(params.MaxResults) {
		secretList = secretList[:int(params.MaxResults)]
	}

	return &secretsmanager.ListSecretsOutput{
		SecretList: secretList,
	}, nil
}

func clientWithValues(t *testing.T, secrets map[string]*testVal) *fakeClient {
	t.Helper()

	return &fakeClient{t: t, secrets: secrets}
}

type testVal struct {
	s string
	b []byte
}

func vs(s string) *testVal {
	return &testVal{s: s}
}

func vb(b []byte) *testVal {
	return &testVal{b: b}
}
