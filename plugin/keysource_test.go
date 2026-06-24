package plugin

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
)

func TestNewMasterKey(t *testing.T) {
	var (
		dummyRole              = "a-role"
		dummyEncryptionContext = map[string]*string{
			"foo": aws.String("bar"),
		}
	)
	key := NewMasterKey(dummyARN, dummyRole, dummyEncryptionContext)
	assert.Equal(t, dummyARN, key.Arn)
	assert.Equal(t, dummyRole, key.Role)
	assert.Equal(t, dummyEncryptionContext, key.EncryptionContext)
	assert.NotNil(t, key.CreationDate)
}
