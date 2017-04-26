#include <nan.h>
#include <nan.h>
#include "ed25519.h"

#include "openssl/bn.h"
#include "openssl/conf.h"
#include "openssl/rand.h"

using namespace node;
using namespace v8;

namespace ed25519id {

NAN_METHOD(Generate) {
  const char* prefix_data = Buffer::Data(info[0]);
  size_t prefix_len = Buffer::Length(info[0]);
  int prefix_bits = info[1]->IntegerValue();
  int iterations = info[2]->IntegerValue();

  ed25519_secret_key sk;
  ed25519_public_key pk;

  BIGNUM num;
  BIGNUM prefix;

  BN_init(&num);
  BN_init(&prefix);
  BN_bin2bn(reinterpret_cast<const unsigned char*>(prefix_data), prefix_len,
            &prefix);

  int i;
  for (i = 0; i < iterations; i++) {
    RAND_bytes(sk, sizeof(sk));
    ed25519_publickey(sk, pk);

    BN_bin2bn(pk, sizeof(pk), &num);
    BN_mask_bits(&num, prefix_bits);

    if (BN_ucmp(&num, &prefix) == 0)
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
  OPENSSL_no_config();

  for (;;) {
    int status = RAND_status();
    if (status == 1)
      break;

    // Give up, RAND_poll() not supported.
    if (RAND_poll() == 0)
      break;
  }

  Nan::SetMethod(target, "generate", Generate);
}

}  // namespace ed25519id

NODE_MODULE(ed25519id, ed25519id::Init)
