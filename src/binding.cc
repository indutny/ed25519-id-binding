#include <nan.h>

#include "sodium.h"
#include "ed25519.h"
#include "openssl/bn.h"

using namespace node;
using namespace v8;

// As per Libsodium install docs
#define SODIUM_STATIC

namespace ed25519id {

const unsigned int kAlphaLen = 26;

NAN_METHOD(Generate) {
  const char* name = Buffer::Data(info[0]);
  size_t len = Buffer::Length(info[0]);
  int iterations = info[1]->IntegerValue();
  uint8_t codes[len + 1];

  for (size_t i = 0; i < len; i++)
    codes[i] = name[i] - 'a' + 1;
  codes[len] = 0;

  ed25519_secret_key sk;
  ed25519_public_key pk;

  BIGNUM num;
  BN_init(&num);

  int i;
  for (i = 0; i < iterations; i++) {
    randombytes_buf(sk, sizeof(sk));
    ed25519_publickey(sk, pk);

    BN_bin2bn(pk, sizeof(pk), &num);

    size_t j;
    for (j = 0; j < len + 1; j++)
      if (codes[j] != BN_div_word(&num, kAlphaLen + 1))
        break;

    if (j == len + 1)
      break;
  }

  if (i == iterations) {
    info.GetReturnValue().Set(Nan::False());
    return;
  }

  char out[sizeof(sk) + sizeof(pk)];
  memcpy(out, sk, sizeof(sk));
  memcpy(out + sizeof(sk), pk, sizeof(pk));

  info.GetReturnValue().Set(Nan::CopyBuffer(out, sizeof(out)).ToLocalChecked());
}

NAN_MODULE_INIT(Init) {
  if (sodium_init() == -1) {
    Nan::ThrowError("sodium_init() failed");
    return;
  }

  Nan::SetMethod(target, "generate", Generate);
}

}  // namespace ed25519id

NODE_MODULE(ed25519id, ed25519id::Init)
