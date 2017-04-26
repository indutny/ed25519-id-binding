{
  'targets': [
    {
      'target_name': 'ed25519id',
      'include_dirs' : [
        "<!(node -e \"require('nan')\")",
        "<(nodedir)/deps/openssl/openssl/include",
        'deps/ed25519-donna',
      ],
      'defines': [
        'ED25519_SSE2',
      ],
      'sources': [
        'deps/ed25519-donna/ed25519.c',
        'src/binding.cc',
      ],
      'xcode_settings': {
        'OTHER_CFLAGS': [
          '-g',
          '-O3',
        ]
      },
      'cflags': [
        '-g',
        '-O3',
      ],
    }
  ]
}
