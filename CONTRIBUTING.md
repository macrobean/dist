# Guidelines for Contributing

This project is in the public domain. Serious contributions are welcome.

By submitting a contribution, you agree to release your work into the public domain under the terms of The Unlicense.

## How to Contribute

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and commit them.
4.  Push your changes to your fork.
5.  Open a pull request.

## TODOs

Some feature add-ons to start with:

- [ ] Lua dynamic response header
  * Responses are currently handled via static lua route handling and middleware with hardcoded error outputs. Implement Lua-side control over HTTP status, cookies, content-types etc.
- [ ] TLS 4 support {psa_crypto_init()}
- [ ] Add process supervision to auto-restart on crash
- [ ] Multi-user auth
- [ ] Upgrade to `epoll`/`kqueue` on Linux/macOS
