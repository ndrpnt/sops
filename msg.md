A SOPS KMS plugin is identified by its name and can be passed arbitrary configuration (usually what's needed to identify the key used for encryption).

## Configuration format

SOPS KMS plugins are not configurable with inline with flags

```yaml
# .sops.yaml
creation_rules:
  - plugin:
      - name: suffix # Dummy plugin that appends a string to the key, instead of encrypting it.
        format: json # json or binary. Defaults to binary.
        configuration:
          suffix: hello
      - name: scw
        configuration:
          id: a00dcfec-f93d-4905-af1e-887941bfe1c0
          region: nl-ams
          associated_data: aGVsbG8=
```

## Plugin API

A SOPS KMS plugin is a standalone executable file that:

* Verifies that the `__SOPS_KMS_PLUGIN=1` environment variable is set, and exits with an error message otherwise.
* Reads a protobuf message from stdin, containing the request.
* Writes a protobuf message to stdout, containing the response, an error, or both.
* Exits with code 0 unless there is a system error, in which case stdout is discarded
* Optionally logs to stderr

The plugin runs in SOPS' working directory so that relative paths, e.g. `SOPS_AGE_KEY_FILE` work. Also, setting `cmd.Dir = os.TempDir()` is somewhat broken because the inherited `PWD` is not updated. The environment is forwarded to the plugin so that it can access its configuration, like `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` variables.

The schema is as follow:

```protobuf
message EncryptRequest {
  optional bytes plaintext = 1;
  google.protobuf.Struct configuration = 2;
}

message EncryptResponse {
  optional bytes ciphertext = 1;
  Error error = 2;
}

message DecryptRequest {
  optional bytes ciphertext = 1;
  google.protobuf.Struct configuration = 2;
}

message DecryptResponse {
  optional bytes plaintext = 1;
  Error error = 2;
}

message Error {
  Code code = 1;
  string message = 2;
}

// Matches google.rpc.Code.
enum Code {
  CODE_UNSPECIFIED = 0;
  CODE_CANCELED = 1;
  CODE_UNKNOWN = 2;
  CODE_INVALID_ARGUMENT = 3;
  CODE_DEADLINE_EXCEEDED = 4;
  CODE_NOT_FOUND = 5;
  CODE_ALREADY_EXISTS = 6;
  CODE_PERMISSION_DENIED = 7;
  CODE_RESOURCE_EXHAUSTED = 8;
  CODE_FAILED_PRECONDITION = 9;
  CODE_ABORTED = 10;
  CODE_OUT_OF_RANGE = 11;
  CODE_UNIMPLEMENTED = 12;
  CODE_INTERNAL = 13;
  CODE_UNAVAILABLE = 14;
  CODE_DATA_LOSS = 15;
  CODE_UNAUTHENTICATED = 16;
  CODE_OK = 17;
}
```

## Plugin selection

To find the corresponding executable file, we first lookup the `SOPS_PLUGIN_KMS_{NAME}` environment variable. If it is non-empty we execute the file it references value without futher validation. Otherwise, we execute `sops-plugin-kms-{name}`, which must be present in the `PATH`. The `SOPS_PLUGIN_KMS_{NAME}` environment variable can contain a path to the executable (absolute or relative to the working directory), or the name of an executable available in the `PATH`.

We avoid storing user-specific info, like absolute paths, in versioned files (i.e. configuration and encrypted files). By forbiding relative paths in plugin names, we prevent arbitrary code execution when executing a SOPS command in an unvetted project.

## Open questions

* How do we handle plugins that require user input, e.g. SSH passphrases in age
* Should `EncryptResponse.ciphertext` and `DecryptRequest.ciphertext` be `bytes` or `string` ? I think the tradeoff is whether we force the plugin to return valid UTF-8 or if we do with any byte array and it's SOPS' job to base64-encode it.
